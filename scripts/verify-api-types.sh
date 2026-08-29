#!/bin/zsh
#
# verify-api-types.sh
# wxyc-swift-auth
#
# Verifies that the committed Sources/WXYCAuth/Generated tree matches what
# scripts/regenerate-api-types.sh produces from the wxyc-shared commit pinned in
# contract-version.json. Regenerates into a scratch temp directory -- the
# committed tree is never touched -- and diffs it against the committed tree
# with `git diff --no-index --exit-code`, so it fails loudly on drift: a
# hand-edit to a generated file, or a contract-version.json bump that wasn't
# followed by a regen (pin says one commit, vendored tree reflects another).
#
# Because this package vendors a SUBSET rather than the whole generated tree,
# the byte-for-byte diff is doing more work here than it does in the app repos:
# it is the check that the allow-list, the Infrastructure curation, the
# RequestTask strip and the access-level demotion are all REPRODUCIBLE. A
# transform that produced a different result on a second run -- or a subset
# quietly widened by hand -- fails here.
#
# This does NOT catch an api.yaml change upstream that never made it into this
# repo. The pin is a fixed SHA, this script only ever regenerates from that SHA,
# and .github/workflows/verify-api-types.yml has no `schedule:` trigger. A newer
# api.yaml on wxyc-shared's main sits unnoticed until someone deliberately bumps
# the pin -- by design: bumping the pin is the trigger for a human to re-run the
# generated-vs-hand-written evaluation, not something that should happen
# unreviewed on a cron.
#
# Nor does it prove api.yaml matches the handler that actually serves the
# endpoint. That is a mirror-drift check only; the upstream E2E guard
# (wxyc-shared's e2e/auth.test.ts, per the plan's mirror-guard decision) is what
# validates the deployed truth.
#
# Usage:
#   scripts/verify-api-types.sh [options]
#
# Options:
#   --remote <url>   wxyc-shared remote to clone. Forwarded to regenerate-api-types.sh.
#   -h, --help       Show this message.
#
# Exit codes: 0 = committed tree matches the pinned contract. Non-zero = drift
# detected (diff printed to stdout) or the regeneration itself failed.
#

set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
cd "$REPO_ROOT"

COMMITTED_DIR="Sources/WXYCAuth/Generated"
REMOTE=""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log()  { print -r -- "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
fail() { print -ru2 -- "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*"; exit 1; }

usage() {
    cat <<'EOF'
verify-api-types.sh

Regenerates Sources/WXYCAuth/Generated into a scratch temp dir (never touching
the committed tree) and diffs it against the committed tree. Exits non-zero,
with the diff on stdout, if they differ.

Usage:
  scripts/verify-api-types.sh [options]

Options:
  --remote <url>   wxyc-shared remote to clone. Forwarded to regenerate-api-types.sh.
  -h, --help       Show this message.
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --remote)
            if (( $# < 2 )); then
                fail "option --remote requires a value"
            fi
            REMOTE="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *)         echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -d "$COMMITTED_DIR" ]] || fail "committed tree not found: $COMMITTED_DIR"
[[ -x "$SCRIPT_DIR/regenerate-api-types.sh" ]] || fail "$SCRIPT_DIR/regenerate-api-types.sh not found or not executable"

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/wxyc-auth-types-verify.XXXXXX") || fail "mktemp failed"
trap 'rm -rf "$TMP_ROOT"' EXIT

TMP_DEST="$TMP_ROOT/Generated"
mkdir -p "$TMP_DEST"

log "Regenerating into scratch dir: $TMP_DEST"
regen_args=(--dest-dir "$TMP_DEST" --work-dir "$TMP_ROOT/wxyc-shared-codegen")
if [[ -n "$REMOTE" ]]; then
    regen_args+=(--remote "$REMOTE")
fi
"$SCRIPT_DIR/regenerate-api-types.sh" "${regen_args[@]}" || fail "regeneration into scratch dir failed"

log "Diffing scratch output against $COMMITTED_DIR"
set +e
git diff --no-index --exit-code -- "$COMMITTED_DIR" "$TMP_DEST"
diff_status=$?
set -e

if (( diff_status == 0 )); then
    log "No drift. Committed tree matches the pinned wxyc-shared contract."
    exit 0
elif (( diff_status == 1 )); then
    fail "Drift detected -- committed $COMMITTED_DIR does not match a fresh regen from the pinned contract. Run scripts/regenerate-api-types.sh and commit the diff, or update contract-version.json if the pin should move."
else
    fail "git diff failed unexpectedly (exit $diff_status) while comparing $COMMITTED_DIR to $TMP_DEST"
fi
