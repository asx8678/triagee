# 01 · Design lock and source of truth

## 1.1 What Adam approved

A compact, crisp, professional PTV Triage interface: four primary destinations, a persistent shared scope bar, clear Overview metrics and ownership, one review workspace instead of a four-step wizard, a consistent large CVE inspector, and a refined timeline. The accepted artifact is `reference/approved/ptv-triage-prototype.html`.

The HTML's SHA-256 is recorded in `reference/baselines/capture-report.json` and the package manifest. The original seven previews are preserved in `reference/approved/previews/`. The 32 additional images are clean renders of that same HTML, not a second proposal.

## 1.2 Precedence

When documents disagree, apply this order:

1. User's accepted intent plus data integrity, truthful status, required action reachability and authorization constraints in this package.
2. The frozen reference HTML's actual CSS, DOM hierarchy, geometry and appearance at the stated viewport/fixture.
3. Measured computed styles and canonical captures generated from that HTML in `reference/baselines/`.
4. The detailed implementation requirements in this package.
5. The earlier proposal documents and original token JSON in `reference/original-design/`, retained for rationale and history.

A prose approximation such as “640–800px inspector” is not a license to choose any width: the accepted code is `width:min(780px,96vw)` and expanded `min(1240px,100vw)`. Likewise the original approximate 44–50px table advice is superseded by the reference's actual 49px base variable, with its documented component exceptions.

Read `13-REFERENCE-LIMITATIONS.md`: preserving visuals does not mean copying fake timestamps, simplified priority logic, unsafe target fallback, prototype-only storage, or other demo shortcuts.

## 1.3 Exact fidelity means

Match composition, navigation position, visible section order, grid columns, gutters, panel boundaries, type sizes/weights, text density, badge shapes, icon shapes, input geometry, scrollbar ownership, action placement, breakpoint behavior and selected/hover/focus/disabled states. Match the fixture text in the isolated visual-QA mode so line breaks are comparable.

The design is not satisfied by choosing approximately similar colors and inventing different cards. It is not satisfied by taking a generic admin template and inserting the same labels. Match the inspector and review workspace as carefully as the homepage.

Use the supplied selectors and computed-style measurements to remove guesswork. The accepted source has specific exceptions, including 2px badges, 4px confirmation-dialog corners and circular observation markers. “Sharp” does not mean turning every marker into a square.

## 1.4 Legitimate production differences

Real CVE identifiers, package descriptions, recorded times, owners, policy explanations, counts, integration states and data-health conditions replace synthetic content. Components can be framework-native and split across files. Test-only data labels disappear in normal operation; the status row instead gives truthful workspace/source context using the same dimensions. Existing licensed local fonts may need mapping, but visually material font substitution requires comparison and documentation.

Longer real content may wrap in intended text areas, expand internal scroll height, or use safe full-value disclosure. It must not widen the outer page or move fixed actions beyond the viewport. A backend that cannot supply a field must show Unknown/unavailable or an honest loading/error state, never a hardcoded mock value.

Unsupported actions cannot masquerade as successful operations. Add the agreed compatible backend support or visibly explain unavailability while recording the delivery limitation. UI-only work cannot quietly invent a remediation engine, RBAC system or authenticated approver.

## 1.5 Controlled corrections, not redesign

A minimal change necessary for keyboard access, safe scope handling, content overflow, approval integrity or preserving an essential action is permitted as an engineering correction. Record it with the requirement, reason, affected viewports and before/after screenshots. Keep the surrounding design unchanged. Do not use “accessibility” as a blanket justification to enlarge every panel or revert to a wizard.

Material aesthetic changes, new navigation destinations, different workflows, new frontend frameworks or changed domain policy are not routine corrections. Put them in the deviation register and obtain a decision before shipping that departure.

## 1.6 Baseline integrity

Reference HTML, extracted exact CSS/JS, original preview files and synthetic fixture are immutable inputs. `qa/verify_package.py` verifies them against the manifest. New application screenshots, local rerenders and diff outputs belong under `qa/results/` or the target repository's artifact directory.

Never update a baseline because the implementation failed. A genuine new design approval creates a separate version with a written change record, not an unannounced edit to this one.
