#!/usr/bin/env python3
"""Smoke-check a running, demo-seeded workspace. Never submit a decision.

Run from the repository root after starting the local Phoenix app:
  python -m pip install playwright==1.57.0
  python -m playwright install chromium
  python scripts/check_workspace_ui.py --output ui-results

The CI workflow uses its own disposable database. This checks real rendered
LiveViews, not reconstructed HTML. It is not a full accessibility audit.
"""
from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright

SCREENS = {
    "overview": "/?page=overview",
    "inventory": "/?page=inventory",
    "review": "/?page=review",
    "timeline": "/timeline",
}
SIZES = [(1600, 1000), (1280, 800), (1024, 600), (768, 1024), (390, 844), (320, 740)]


def wait_for_server(base: str) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base, timeout=5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    raise RuntimeError("The local Phoenix server did not become ready in 120 seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:4000")
    parser.add_argument("--output", type=Path, default=Path("ui-results"))
    args = parser.parse_args()
    # This is a demo/dev test, not a probe to run against arbitrary deployments.
    if urlparse(args.base).hostname not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("--base must use a loopback host")
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    wait_for_server(args.base)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport={"width": 1600, "height": 1000})
        page = context.new_page()
        page.set_default_timeout(15000)

        def visit(screen: str) -> None:
            response = page.goto(args.base + SCREENS[screen], wait_until="domcontentloaded")
            assert response and response.status == 200, "Page request failed"
            expect(page.locator("#shell")).to_be_visible()
            page.wait_for_selector("[data-phx-main].phx-connected")
            page.wait_for_function("getComputedStyle(document.querySelector('.topbar')).backgroundColor === 'rgb(255, 255, 255)'")

        def check(name: str, function) -> None:
            try:
                details = function()
                results.append({"name": name, "passed": True, "details": details})
                print(f"PASS {name}", flush=True)
            except Exception as error:
                results.append({"name": name, "passed": False, "error": str(error)})
                print(f"FAIL {name}: {error}", flush=True)
                page.screenshot(path=str(out / (re.sub(r"[^a-zA-Z0-9_-]", "_", name) + "-failure.png")))

        for width, height in SIZES:
            page.set_viewport_size({"width": width, "height": height})
            for screen in SCREENS:
                def layout(screen=screen, width=width, height=height):
                    visit(screen)
                    measurements = page.evaluate("""() => {
                      const rect = selector => {
                        const el = document.querySelector(selector);
                        const r = el.getBoundingClientRect();
                        return {x:r.x, y:r.y, right:r.right, bottom:r.bottom,
                                width:r.width, height:r.height,
                                display:getComputedStyle(el).display};
                      };
                      return {
                        documentWidth: document.documentElement.scrollWidth,
                        documentHeight: document.documentElement.scrollHeight,
                        page: rect('#main-content'),
                        footer: rect('.bottom-status'),
                        coverage: rect('.scopebar .freshness'),
                        nav: [...document.querySelectorAll('.topnav a')].map(el => {
                          const r = el.getBoundingClientRect();
                          return {x:r.x, right:r.right, height:r.height};
                        })
                      };
                    }""")
                    assert measurements["documentWidth"] <= width + 1, measurements
                    assert measurements["documentHeight"] <= height + 1, measurements
                    assert measurements["page"]["height"] >= 100, measurements
                    assert measurements["footer"]["bottom"] <= height + 1, measurements
                    coverage = measurements["coverage"]
                    assert coverage["display"] != "none" and coverage["height"] > 0, measurements
                    assert coverage["right"] <= width + 1, measurements
                    assert len(measurements["nav"]) == 4, measurements
                    assert all(n["x"] >= 0 and n["right"] <= width + 1 for n in measurements["nav"]), measurements
                    if screen == "review":
                        expect(page.locator("#workspace-review")).to_be_visible()
                        if width > 640:
                            overflow = page.locator("#workspace-decision").evaluate("el => getComputedStyle(el).overflowY")
                            assert overflow == "auto", overflow
                            for column in [".evidence-column", ".decision-column"]:
                                assert page.locator(column).evaluate("el => getComputedStyle(el).overflowY") == "visible"
                        page.locator(".review-footer").scroll_into_view_if_needed()
                        assert page.locator(".review-footer").bounding_box()["y"] < height
                        page.locator("#main-content").evaluate("el => el.scrollTop = 0")
                    if (width, height) in [(1600, 1000), (390, 844)]:
                        page.screenshot(path=str(out / f"{screen}-{width}-after.png"), animations="disabled")
                    return measurements
                check(f"{screen}-{width}x{height}", layout)

        page.set_viewport_size({"width": 1600, "height": 1000})

        def before_after():
            visit("overview")
            text = page.locator("#main-content").inner_text()
            page.locator('link[href*="workspace-comfort.css"]').evaluate("el => el.disabled = true")
            page.wait_for_function("getComputedStyle(document.querySelector('.topbar')).backgroundColor !== 'rgb(255, 255, 255)'")
            page.screenshot(path=str(out / "overview-1600-before.png"), animations="disabled")
            assert page.locator("#main-content").inner_text() == text
            page.locator('link[href*="workspace-comfort.css"]').evaluate("el => el.disabled = false")
            page.screenshot(path=str(out / "overview-1600-after.png"), animations="disabled")
            return {"same_overview_text_with_and_without_theme": True}
        check("same-data-before-after", before_after)

        def density():
            visit("inventory")
            row = page.locator("#workspace-inventory tbody tr").first
            normal = row.bounding_box()["height"]
            page.locator('button[phx-click="density"]').click()
            expect(page.locator("#shell")).to_have_class(re.compile(r"compact"))
            compact = row.bounding_box()["height"]
            assert compact < normal, (normal, compact)
            return {"comfortable_height": normal, "compact_height": compact}
        check("live-density-toggle", density)

        def inspector():
            visit("inventory")
            page.locator("#workspace-inventory .cve-link").first.click()
            dialog = page.locator("dialog.inspector")
            expect(dialog).to_be_visible()
            box = dialog.bounding_box()
            assert box["x"] >= 0 and box["y"] >= 0, box
            assert box["x"] + box["width"] <= 1601, box
            assert box["y"] + box["height"] <= 1001, box
            page.screenshot(path=str(out / "inspector-1600-after.png"), animations="disabled")
            page.keyboard.press("Escape")
            expect(dialog).to_have_count(0)
            return {"escape_closed_live_inspector": True}
        check("live-inspector-escape", inspector)

        def task_target():
            visit("overview")
            item = page.locator(".attention-item").first
            hit = item.evaluate("""el => {
              const r = el.getBoundingClientRect();
              return !!document.elementFromPoint(r.left+8, r.top+8)?.closest('a');
            }""")
            assert hit, "The item corner did not hit its existing link"
            item.click(position={"x": 8, "y": 8})
            expect(page).to_have_url(re.compile(r"mode=urgent"))
            return {"whole_item_follows_existing_link": True}
        check("overview-expanded-task-target", task_target)

        def phone_queue():
            page.set_viewport_size({"width": 390, "height": 844})
            visit("review")
            page.locator('button[phx-click="queue-toggle"]').click()
            expect(page.locator(".queue-panel")).to_be_visible()
            expect(page.locator("#workspace-review")).to_be_hidden()
            page.locator('button[phx-click="queue-toggle"]').click()
            expect(page.locator("#workspace-review")).to_be_visible()
            return {"queue_and_assessment_both_reachable": True}
        check("live-phone-queue-toggle", phone_queue)

        def focus_and_motion():
            page.set_viewport_size({"width": 1280, "height": 800})
            page.emulate_media(reduced_motion="reduce")
            visit("overview")
            page.keyboard.press("Tab")
            focus = page.evaluate("""() => {
              const s = getComputedStyle(document.activeElement);
              return {outline:s.outlineWidth, style:s.outlineStyle};
            }""")
            assert focus["style"] != "none" and float(focus["outline"].replace("px", "")) >= 2, focus
            duration = page.locator("#workspace-settings").evaluate("el => getComputedStyle(el).transitionDuration")
            assert all(float(v.strip().rstrip("s")) == 0 for v in duration.split(",")), duration
            return {"focus": focus, "reduced_motion_duration": duration}
        check("keyboard-focus-and-reduced-motion", focus_and_motion)
        version = browser.version
        browser.close()

    report = {"browser": "Chromium " + version, "source": "running Phoenix app with demo seed data",
              "checks": results, "passed": sum(r["passed"] for r in results),
              "failed": sum(not r["passed"] for r in results)}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['passed']} passed; {report['failed']} failed", flush=True)
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
