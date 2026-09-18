#!/usr/bin/env bash
# Regenerate the source-only checkpoint inventory for review.
#
# Read-only: lists paths and hashes. It never stages, commits, pushes, or prints
# file contents. Usage: scripts/checkpoint_inventory.sh [out-dir]
# Default output directory: evidence/checkpoint/
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
out=${1:-evidence/checkpoint}
mkdir -p "$out"

# Tracked files modified in place and reviewed individually for this checkpoint.
modified=(
  .gitignore
  IMPLEMENTATION_ROADMAP.md
)

# Untracked source trees taken whole; ignore rules inside them still apply.
# `.github` is a root dot-directory, so it is listed explicitly: the CI workflow
# is product configuration and belongs in the inventory rather than in the
# excluded classes.
trees=(
  app
  .github
)

# Root documents written by this workstream.
docs=(
  CURRENT_STATUS.md
  CHECKPOINT_REVIEW.md
  NEXT_STEPS_PLAN.md
  A_B_EXECUTION.md
  FINDINGS_PAGING_EXECUTION.md
  INTEL_WIRING_EXECUTION.md
  UI_REDESIGN_BRIEF.md
  UI_REDESIGN_PLAN.md
  UI_REDESIGN_REPORT.md
  UI_IMPROVEMENTS_PLAN.md
  UI_IMPROVEMENTS_REPORT.md
  OVERVIEW_INTELLIGENCE_PLAN.md
  CODE_REVIEW_FIXES_EXECUTION.md
  TAILWIND_EXECUTION.md
  scripts/checkpoint_inventory.sh
  scripts/tailwind_assets_probe.exs
)

present_docs=()
for d in "${docs[@]}"; do
  if [ -f "$d" ]; then present_docs+=("$d"); fi
done

# Durable text records under evidence/. Screenshots, logs, probe scripts, JSON
# results and diffs stay outside git.
mapfile -t evidence_docs < <(git ls-files --cached --others --exclude-standard evidence | grep -E '\.md$' || true)

{
  # Tracked and untracked alike: enumerating by git state would silently drop
  # every file once it is committed, so the inventory must be reproducible both
  # before and after the checkpoint commit.
  git ls-files --cached --others --exclude-standard -- "${modified[@]}"
  git ls-files --cached --others --exclude-standard -- "${trees[@]}"
  printf '%s\n' "${present_docs[@]}"
  if [ "${#evidence_docs[@]}" -gt 0 ]; then printf '%s\n' "${evidence_docs[@]}"; fi
} | sed '/^$/d' | sort -u > "$out/source-only.paths"

# Self-check: no credential, database, dependency, build or crash artifact may
# appear in the inventory. Fails loudly instead of producing a bad list.
if grep -nE '(^|/)\.env($|\.)|[.](pem|key|pat|p12|pfx|db|db-wal|db-shm|sqlite|sqlite3|dump|sql)$|(^|/)(node_modules|_build|deps|vendor|\.elixir_ls|\.fetch)/|(^|/)erl_crash[.]dump$' "$out/source-only.paths"; then
  echo "refusing: excluded artifact class present in inventory" >&2
  exit 1
fi

shasum -a 256 $(cat "$out/source-only.paths") | sed "s|$root/||" > "$out/MANIFEST.sha256"

{
  echo "# Paths present in the working tree but deliberately outside this checkpoint."
  echo "# Classes, not an exhaustive per-file dump."
  echo
  echo "## Harness state (tracked modifications plus untracked journals)"
  git status --short -- .pi | sed 's/^/  /'
  echo
  echo "## Root input document, excluded pending explicit owner approval"
  for f in 'architecture(3).md'; do
    if [ -f "$f" ]; then echo "  $f"; fi
  done
  echo
  echo "## Scratch screenshots and local verification output"
  for d in tmp; do
    if [ -d "$d" ]; then echo "  $d/ ($(find "$d" -type f | wc -l | tr -d ' ') files)"; fi
  done
  echo
  echo "## Evidence artifacts (binaries, logs, probes, JSON results, diffs)"
  for d in evidence; do
    if [ -d "$d" ]; then
      total=$(git ls-files --others --exclude-standard "$d" | wc -l | tr -d ' ')
      kept=${#evidence_docs[@]}
      echo "  $d/ ($total untracked files; $kept markdown records included)"
    fi
  done
  echo
  echo "## Ignored build/dependency/generated classes (not enumerated)"
  echo "  app/deps/ app/_build/ app/.elixir_ls/ app/priv/static/assets/vendor/ app/erl_crash.dump"
} > "$out/excluded.paths"

count=$(wc -l < "$out/source-only.paths" | tr -d ' ')
echo "inventory: $count source-only paths -> $out/source-only.paths"
echo "manifest:  $out/MANIFEST.sha256"
echo "excluded:  $out/excluded.paths"
