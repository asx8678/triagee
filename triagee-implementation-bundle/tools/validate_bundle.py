#!/usr/bin/env python3
"""Validate this handoff package only. No application or service is contacted.

The default mode uses the Python standard library for integrity, JSON, task
references and fixture consistency. If jsonschema is installed, example schema
validation also runs; --require-jsonschema makes a missing dependency an error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {"manifest.json", "SHA256SUMS.txt"}


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def safe_path(relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("Invalid empty/non-string manifest path")
    path = ROOT / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError(f"Unsafe package path: {relative}")
    if path.is_symlink() or ROOT not in path.resolve().parents:
        raise ValueError(f"Path escapes bundle or is a symlink: {relative}")
    return path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest() -> int:
    manifest = load_json(ROOT / "manifest.json")
    paths: set[str] = set()
    for entry in manifest["files"]:
        relative = entry["path"]
        require(relative not in paths, f"Duplicate manifest entry: {relative}")
        paths.add(relative)
        path = safe_path(relative)
        require(path.is_file(), f"Missing file: {relative}")
        require(path.stat().st_size == entry["bytes"], f"Size mismatch: {relative}")
        require(sha256(path) == entry["sha256"], f"Checksum mismatch: {relative}")
    actual = {
        str(p.relative_to(ROOT))
        for p in ROOT.rglob("*")
        if p.is_file() and str(p.relative_to(ROOT)) not in EXCLUDED
    }
    require(actual == paths, f"Unlisted/missing files: {sorted(actual ^ paths)}")
    sums = {}
    for line in (ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relative = line.split("  ", 1)
        require(relative not in sums, f"Duplicate checksum line: {relative}")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "Invalid SHA-256")
        sums[relative] = digest
        require(sha256(safe_path(relative)) == digest, f"SHA256SUMS mismatch: {relative}")
    require(set(sums) == paths | {"manifest.json"}, "Checksum list does not cover exact package files")
    return len(paths) + len(EXCLUDED)


def validate_tasks_and_fixtures() -> tuple[int, int]:
    for path in ROOT.rglob("*.json"):
        load_json(path)
    task_list = load_json(ROOT / "tasks.json")["tasks"]
    cases = load_json(ROOT / "qa/acceptance-cases.json")["cases"]
    tasks = {t["id"]: t for t in task_list}
    case_map = {c["id"]: c for c in cases}
    require(len(tasks) == len(task_list), "Duplicate task IDs")
    require(len(case_map) == len(cases), "Duplicate acceptance IDs")
    visited, visiting = set(), set()

    def visit(task_id: str) -> None:
        require(task_id in tasks, f"Unknown dependency: {task_id}")
        require(task_id not in visiting, f"Task cycle: {task_id}")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dep in tasks[task_id]["depends_on"]:
            visit(dep)
        visiting.remove(task_id)
        visited.add(task_id)

    for task in task_list:
        visit(task["id"])
        for relative in task["read"]:
            require(safe_path(relative).is_file(), f"Missing task input: {relative}")
        for case_id in task["acceptance_ids"]:
            require(case_id in case_map, f"Unknown acceptance ID: {case_id}")
            require(task["id"] in case_map[case_id]["task_ids"], f"Asymmetric mapping: {case_id}")
    for case in cases:
        require(case["status"] == "NOT_RUN", "Handoff must not claim application test execution")
        for task_id in case["task_ids"]:
            require(task_id in tasks and case["id"] in tasks[task_id]["acceptance_ids"],
                    f"Acceptance/task mapping mismatch: {case['id']}")

    fixture = load_json(ROOT / "qa/semantic-fixtures.json")
    require(fixture["synthetic"] and fixture["not_a_seed_script"], "Fixture boundary is missing")
    ops = [t for t in fixture["targets"] if t["operational"]]
    expected = fixture["expected"]
    cv = lambda ts: sorted({t["cve"] for t in ts})
    checks = {
        "all_tracked_cves": cv(ops),
        "needs_attention_cves": cv(t for t in ops if t["expected_attention"]),
        "in_progress_cves": cv(t for t in ops if t["expected_in_progress"]),
        "recorded_present_cves": cv(t for t in ops if t["observation_state"] == "recorded_present"),
        "exposure_unknown_target_ids": sorted(t["placement_id"] for t in ops if t["exposure"] == "unknown"),
        "exception_target_ids": sorted(t["placement_id"] for t in ops if t["assessment_type"] in ("risk_accepted", "not_affected")),
    }
    for name, value in checks.items():
        require(expected[name] == value, f"Fixture expected projection mismatch: {name}")
    counts = expected["counts"]
    for name in ("all_tracked_cves", "needs_attention_cves", "in_progress_cves", "recorded_present_cves"):
        require(counts[name] == len(checks[name]), f"Fixture count mismatch: {name}")
    require(counts["operational_targets"] == len(ops), "Operational target count mismatch")
    require(counts["exception_targets"] == len(checks["exception_target_ids"]), "Exception target count mismatch")
    require(counts["exposure_unknown_targets"] == len(checks["exposure_unknown_target_ids"]), "Unknown target count mismatch")
    for variant in fixture["additional_isolated_variants"]:
        require(set(variant["case_ids"]) <= set(case_map), f"Unknown variant case IDs: {variant['id']}")

    # These checks only confirm the synthetic examples are internally connected.
    target_map = {t["placement_id"]: t for t in fixture["targets"]}
    evidence = {e["id"]: e for e in fixture["evidence"]}
    for name in ("ai-investigate.json", "ai-not-affected-candidate.json"):
        example = load_json(ROOT / "contracts/examples" / name)
        target_ids = {scope["placement_id"] for scope in example["assessed_scope"]}
        for scope in example["assessed_scope"]:
            target = target_map[scope["placement_id"]]
            require(target["cve"] == example["cve"], f"Example CVE mismatch: {name}")
            require(scope["finding_ids"] == [target["finding_id"]], f"Example finding mismatch: {name}")
            require(scope["evidence_hash"] == target["synthetic_evidence_hash"], f"Example binding mismatch: {name}")
        for reference in example["supporting_evidence"]:
            ev = evidence.get(reference["evidence_id"])
            require(ev is not None and ev["placement_id"] in target_ids, f"Example evidence mismatch: {name}")
    return len(tasks), len(cases)


def validate_local_links() -> int:
    checked = 0
    for path in ROOT.rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for link in re.findall(r"\]\(([^)]+)\)", text):
            if "://" in link or link.startswith("#") or link.startswith("mailto:"):
                continue
            destination = (path.parent / link.split("#")[0]).resolve()
            require(destination == ROOT or ROOT in destination.parents, f"Link outside package: {path.name}: {link}")
            require(destination.exists(), f"Broken local Markdown link: {path.name}: {link}")
            checked += 1
    return checked


def validate_schemas(required: bool) -> bool:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        if required:
            raise ValueError("jsonschema is required for --require-jsonschema; install it in your own environment")
        print("SKIPPED: JSON Schema example validation (jsonschema not installed)")
        return False
    mappings = {
        "ai-recommendation.schema.json": ["ai-investigate.json", "ai-not-affected-candidate.json"],
        "reporting-target.schema.json": ["reporting-target.json"],
    }
    for schema_name, examples in mappings.items():
        schema = load_json(ROOT / "contracts" / schema_name)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for example in examples:
            validator.validate(load_json(ROOT / "contracts/examples" / example))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-jsonschema", action="store_true")
    args = parser.parse_args()
    try:
        files = validate_manifest()
        tasks, cases = validate_tasks_and_fixtures()
        links = validate_local_links()
        schemas = validate_schemas(args.require_jsonschema)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {files} package files; SHA-256 integrity and exact manifest coverage")
    print(f"PASS: JSON syntax, {tasks} acyclic tasks, {cases} linked acceptance requirements")
    print(f"PASS: synthetic fixture arithmetic/example references; {links} local Markdown links")
    if schemas:
        print("PASS: 2 JSON Schemas and 3 synthetic examples, with format validation")
    print("NOT TESTED: repository application, database, accessibility, or live integrations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
