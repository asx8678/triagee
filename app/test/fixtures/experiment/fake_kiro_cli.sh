#!/bin/sh
# Synthetic runner: never contacts Kiro or a provider.
[ "$1" = chat ] || exit 41
interactive=no
agent=no
trust=no
for argument in "$@"; do
  case "$argument" in
    --no-interactive) interactive=yes ;;
    triage-classifier) agent=yes ;;
    --trust-tools=) trust=yes ;;
  esac
  prompt="$argument"
done
[ "$interactive:$agent:$trust" = yes:yes:yes ] || exit 42
[ -f .kiro/agents/triage-classifier.json ] || exit 43
[ -z "$TRIAGE_AZURE_PAT" ] || exit 44
mode="${TRIAGE_FAKE_RUNNER_MODE:-ok}"
[ -n "$TRIAGE_FAKE_RUNNER_LOG" ] && echo "$mode" >> "$TRIAGE_FAKE_RUNNER_LOG"
if [ -n "$TRIAGE_FAKE_RUNNER_CAPTURE" ]; then
  printf '%s' "$prompt" > "$TRIAGE_FAKE_RUNNER_CAPTURE"
  pwd > "$TRIAGE_FAKE_RUNNER_CAPTURE.cwd"
  cat .kiro/agents/triage-classifier.json > "$TRIAGE_FAKE_RUNNER_CAPTURE.agent"
fi
case "$mode" in
  ok) printf '%s\n' '{"danger_score":42,"whitelist_score":18,"recommendation":"investigate","rationale":"Fake runner fixture: deterministic pipeline response."}' ;;
  invalid_json) printf '%s\n' 'The assistant is unsure and produced no JSON this time.' ;;
  bad_score) printf '%s\n' '{"danger_score":500,"whitelist_score":18,"recommendation":"remediate","rationale":"Out of range score fixture."}' ;;
  bad_whitelist) printf '%s\n' '{"danger_score":42,"whitelist_score":101,"recommendation":"investigate","rationale":"Invalid suitability."}' ;;
  unsafe) printf '%s\n' '{"danger_score":10,"whitelist_score":95,"recommendation":"suggest_risk_acceptance","rationale":"Unsafe fixture; not a real assessment."}' ;;
  oversize) head -c 65537 /dev/zero | tr '\000' x ;;
  timeout) sleep 30 & wait $! ;;
  crash) exit 3 ;;
esac
