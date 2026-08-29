#!/bin/zsh
#
# regenerate-api-types.sh
# wxyc-swift-auth
#
# Regenerates Sources/WXYCAuth/Generated from wxyc-shared's OpenAPI spec
# (api.yaml). Clones wxyc-shared at the commit pinned in contract-version.json
# into a gitignored scratch dir, runs its `generate:swift` codegen target (the
# swift6 generator), then syncs an AUTH-ONLY SUBSET of the generated Models/
# plus a curated, access-level-demoted Infrastructure/ into the package.
#
# Ported from wxyc-dj-ios's scripts/regenerate-api-types.sh, which vendors the
# WHOLE of Models/ and says so in its own comments ("this package doesn't
# hand-pick a subset"). This package deliberately does the opposite, and the
# deviation is a ratified decision, not drift — see wiki plans/wxyc-swift-auth.md's
# DTO-source row. Whole-tree vendoring here would put a third public copy of
# every app-facing schema (AlbumSearchResult, BinEntry, …) into both consumer
# apps' dependency graphs, which is precisely the duplicate-public-name
# shadowing hazard wxyc-dj-ios's CLAUDE.md documents at length. So: an explicit
# AUTH_MODELS_KEEP allow-list, checked against a closure computed from api.yaml
# itself (see the tripwire discussion below).
#
# Usage:
#   scripts/regenerate-api-types.sh [options]
#
# Options:
#   --work-dir <path>   Scratch clone location. Default: .build/wxyc-shared-codegen.
#   --remote <url>      wxyc-shared remote to clone. Default: git@github.com:WXYC/wxyc-shared.git.
#   --dest-dir <path>   Where to sync the staged tree. Default: Sources/WXYCAuth/Generated
#                       (the committed tree). scripts/verify-api-types.sh overrides
#                       this to a scratch dir so it never touches the committed tree.
#   --keep-work-dir     Don't delete the scratch clone when done (skips a full
#                       re-clone on the next run -- useful for iterating).
#   -h, --help          Show this message.
#
# Reads the pinned commit from contract-version.json's `wxycSharedSha` field,
# which is the authoritative pin (the exact commit the vendored tree is
# generated from). `wxycSharedTag` is a human-readable label for where that
# commit lives and is NOT read by this script. To vendor a newer contract,
# update `wxycSharedSha` (and, for legibility, `wxycSharedTag` /
# `apiYamlVersion`) first, then run this script and commit the diff.
#
# Requires: git, npm (+ node), java (openapi-generator-cli runs on the JVM),
# rsync.
#

set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
cd "$REPO_ROOT"

CONTRACT_FILE="contract-version.json"
DEST_DIR="Sources/WXYCAuth/Generated"
WORK_DIR=".build/wxyc-shared-codegen"
REMOTE="git@github.com:WXYC/wxyc-shared.git"
KEEP_WORK_DIR=0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log()  { print -r -- "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
fail() { print -ru2 -- "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*"; exit 1; }

usage() {
    cat <<'EOF'
regenerate-api-types.sh

Regenerates Sources/WXYCAuth/Generated from the wxyc-shared commit pinned in
contract-version.json.

Usage:
  scripts/regenerate-api-types.sh [options]

Options:
  --work-dir <path>   Scratch clone location. Default: .build/wxyc-shared-codegen.
  --remote <url>      wxyc-shared remote to clone. Default: git@github.com:WXYC/wxyc-shared.git.
  --dest-dir <path>   Sync destination. Default: Sources/WXYCAuth/Generated.
  --keep-work-dir     Don't delete the scratch clone when done.
  -h, --help          Show this message.
EOF
}

require_value() {
    local flag="$1"
    local remaining="$2"
    if (( remaining < 2 )); then
        fail "option $flag requires a value"
    fi
}

while (( $# > 0 )); do
    case "$1" in
        --work-dir)       require_value "$1" "$#"; WORK_DIR="$2"; shift 2 ;;
        --remote)         require_value "$1" "$#"; REMOTE="$2"; shift 2 ;;
        --dest-dir)       require_value "$1" "$#"; DEST_DIR="$2"; shift 2 ;;
        --keep-work-dir)  KEEP_WORK_DIR=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# The auth subset
# ---------------------------------------------------------------------------
#
# Every generated model this package vendors. NOT hand-curated in the sense of
# "someone read the spec once and typed these out": this list must equal, name
# for name, the transitive `$ref` closure of wxyc-shared api.yaml's non-device
# `/auth/*` operations, which scripts/auth-schema-closure.mjs computes from the
# spec and the check below enforces in BOTH directions.
#
# That comparison is the tripwire, and it is worth being explicit about why the
# obvious alternative isn't one. wxyc-dj-ios's Infrastructure/ keep-list carries
# a staged-count assertion (`STAGED_INFRA == ${#INFRA_KEEP[@]}`) that its own
# comments concede can never fail — the staging directory is built by looping
# over the very array it is compared against, so the two are equal by
# construction. A count check over AUTH_MODELS_KEEP would be equally vacuous.
# The closure is not, because its input is api.yaml rather than this list: a
# schema added upstream and `$ref`'d from an auth operation appears in the
# closure, is absent from this array, and the run stops. That is the failure
# an allow-list otherwise absorbs silently — it DROPS what nobody classified,
# so the symptom would be a missing type far away from the cause.
AUTH_MODELS_KEEP=(
    # better-auth's uniform {message, code} error body, plus the two DIFFERENT
    # shapes a 429 can actually carry (its own per-path limiter vs. the express
    # layer in front of it — see each schema's description).
    AuthErrorResponse
    AuthPlainErrorResponse
    AuthRateLimitedResponse
    # Response bodies. AuthSignInResult covers both password routes;
    # AuthTokenAndUserResult covers anonymous + OTP; AuthTokenResponse is the
    # JWT mint; AuthUser is the shared `user` block all of them embed.
    AuthSendCodeResult
    AuthSignInResult
    AuthSignOutResult
    AuthTokenAndUserResult
    AuthTokenResponse
    AuthUser
    # Request bodies, and the named enum SendLoginCodeRequest.type carries.
    EmailSignInRequest
    LookupEmailRequest
    LookupEmailResponse
    OTPSignInRequest
    OTPType
    SendLoginCodeRequest
    UsernameSignInRequest
)

# Generated Infrastructure/ files this package vendors, determined empirically
# by compiling the staged subset (the same way wxyc-dj-ios determined its own,
# per that repo's review finding F3) — and re-checked on every run here, because
# unlike that repo this one BUILDS the vendored tree in CI, so a missing support
# type is a loud build failure rather than a silent drop.
#
# Only four are needed, because the auth subset is small: Models.swift supplies
# CaseIterableDefaultsLast + UnknownCaseCheckable (which OTPType and
# SendLoginCodeRequest conform to), and CodableHelper drags in
# OpenISO8601DateFormatter + OpenAPIMutex. Notably NOT needed today:
# Validation.swift, JSONValue.swift, and CalendarDate.swift — no auth schema
# carries a validated numeric, a free-form JSON value, or a `format: date`.
INFRA_KEEP=(Models.swift CodableHelper.swift OpenISO8601DateFormatter.swift OpenAPIMutex.swift)

# The deliberate-exclusion half of the classification. Anything the generator
# emits into Infrastructure/ that is in NEITHER list is output nobody has looked
# at, and the run stops rather than guessing — the allow-list would otherwise
# drop it silently. This is the mechanism that would have caught CalendarDate.swift
# arriving in wxyc-shared#358 (see that repo's postgenerate:swift hook), which in
# wxyc-dj-ios surfaced only as `cannot find type 'CalendarDate' in scope`.
INFRA_DROP=(
    # An unused URLSession HTTP client this models-only subset never calls.
    APIs.swift
    APIHelper.swift
    JSONDataEncoding.swift
    JSONEncodingHelper.swift
    SynchronizedDictionary.swift
    URLSessionImplementations.swift
    # Worse than unused: declares `extension String: @retroactive CodingKey`,
    # whose String.init?(intValue:) wins overload resolution over String.init(_:)
    # wherever String.init is passed as a bare function value over an Int --
    # `[1, 2, 3].map(String.init)` becomes `[nil, nil, nil]`, and the conformance
    # leaks to every file in any app that links this package, no import required
    # at the use site. Verified empirically in wxyc-dj-ios#75.
    Extensions.swift
    # Not needed by the auth subset (see INFRA_KEEP). Each would be dead weight
    # in every consumer's binary, and Validation/JSONValue additionally export
    # public names that already exist publicly in wxyc-dj-ios's WXYCAPIModels.
    Validation.swift
    JSONValue.swift
    CalendarDate.swift
)

# Top-level Infrastructure types the access-level transform below demotes to
# `internal`. See that section for the argument; this list exists separately so
# the "no public auth model surfaces an Infrastructure type" assertion has
# something precise to check.
INFRA_DEMOTED_TYPES=(
    CodableHelper
    NullEncodable
    ErrorResponse
    DownloadException
    DecodableRequestBuilderError
    Response
    OpenISO8601DateFormatter
)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

for tool in git npm node java rsync; do
    command -v "$tool" > /dev/null 2>&1 || fail "'$tool' is required but not found on PATH"
done

[[ -f "$CONTRACT_FILE" ]] || fail "contract manifest not found: $CONTRACT_FILE"
[[ -f "$SCRIPT_DIR/auth-schema-closure.mjs" ]] || fail "$SCRIPT_DIR/auth-schema-closure.mjs not found"

# Pass the manifest path as argv (not string-interpolated into the JS source),
# so a repo path containing a quote or backslash can't corrupt the program.
SHA=$(node -e 'process.stdout.write(require(process.argv[1]).wxycSharedSha || "")' "$REPO_ROOT/$CONTRACT_FILE")
[[ -n "$SHA" ]] || fail "wxycSharedSha missing or empty in $CONTRACT_FILE"
# Must be a full 40-hex-char commit SHA, not a branch/tag name. The sibling
# `wxycSharedTag` field (e.g. "main") is a human-readable label only, but it
# sits right next to this one, which invites pasting a branch name into the
# wrong field. `git checkout` accepts a branch name just as happily as a SHA,
# so that mistake wouldn't fail here -- it would silently turn the pin into a
# moving target that reddens unrelated PRs indistinguishably from real drift.
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || fail "wxycSharedSha in $CONTRACT_FILE is not a 40-character hex commit SHA: '$SHA' -- did a branch/tag name (e.g. \"main\") end up in wxycSharedSha instead of wxycSharedTag?"

log "Pinned wxyc-shared commit: $SHA"
log "Remote: $REMOTE"
log "Work dir: $WORK_DIR"

# ---------------------------------------------------------------------------
# Clone (or reuse) wxyc-shared at the pinned commit
# ---------------------------------------------------------------------------

if [[ -d "$WORK_DIR/.git" ]]; then
    log "Reusing existing clone at $WORK_DIR"
    git -C "$WORK_DIR" fetch --quiet origin || fail "fetch in $WORK_DIR failed"
else
    log "Cloning $REMOTE into $WORK_DIR"
    rm -rf "$WORK_DIR"
    mkdir -p "${WORK_DIR:h}"
    git clone --quiet "$REMOTE" "$WORK_DIR" || fail "clone of $REMOTE failed"
fi

log "Checking out $SHA"
git -C "$WORK_DIR" checkout --quiet "$SHA" || fail "checkout of $SHA in $WORK_DIR failed -- does the commit exist on $REMOTE?"

# ---------------------------------------------------------------------------
# Generate
# ---------------------------------------------------------------------------

log "Installing wxyc-shared dependencies (npm ci)"
(cd "$WORK_DIR" && npm ci --silent) || fail "npm ci failed in $WORK_DIR"

# generated/ is gitignored in wxyc-shared, so a --keep-work-dir-reused clone
# never has it cleaned by `git checkout`. The generator doesn't prune stale
# output either -- a schema deleted upstream since the last run would linger
# and get staged below as if it were still current.
rm -rf "$WORK_DIR/generated"

log "Running npm run generate:swift"
(cd "$WORK_DIR" && npm run generate:swift) || fail "npm run generate:swift failed in $WORK_DIR"

GENERATED_ROOT="$WORK_DIR/generated/swift/Sources/WXYCAPI"
[[ -d "$GENERATED_ROOT/Models" ]] || fail "generated Models/ not found at $GENERATED_ROOT -- did the generator's SPM file layout change?"
[[ -d "$GENERATED_ROOT/Infrastructure" ]] || fail "generated Infrastructure/ not found at $GENERATED_ROOT"

# wxyc-shared's `postgenerate:swift` hook (scripts/copy-swift-support-files.js,
# added in that repo's PR #358) copies hand-authored support files from
# openapi-config/swift-support/ into the generator's output. It writes them
# into Infrastructure/, so by the time this script reads $GENERATED_ROOT they
# are indistinguishable from generator output and need no separate handling --
# the INFRA_KEEP/INFRA_DROP classification below covers them like anything else.
# (The plan anticipated they might land OUTSIDE Models/ and Infrastructure/ and
# reserved a third staging bucket for them; they don't, so there isn't one.)
# Assert the layout assumption rather than leave it implicit: a future support
# file written somewhere else would be silently unclassified and undropped.
STRAY=$(find "$WORK_DIR/generated/swift/Sources" -type f ! -path '*/Models/*' ! -path '*/Infrastructure/*' ! -path '*/APIs/*' | sed "s|^$WORK_DIR/generated/swift/Sources/||" | tr '\n' ' ')
[[ -z "${STRAY// /}" ]] || fail "generator (or its postgenerate:swift hook) emitted file(s) outside Models/, Infrastructure/ and APIs/: $STRAY -- classify them before they are silently dropped"

# ---------------------------------------------------------------------------
# Assemble the new tree in a staging dir, then swap it in at the end
# ---------------------------------------------------------------------------
#
# Everything below builds into $STAGE_DIR, and $DEST_DIR isn't touched until
# the final swap. That ordering is the point: the swap is an
# `rsync -a --delete`, and every guard here has to run BEFORE it, not after.
STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wxycauth-generated-stage.XXXXXX") || fail "could not create staging dir"
trap 'rm -rf "$STAGE_DIR" "$STAGE_DIR-comment-stripped"' EXIT INT TERM

# --- The allow-list tripwire (see AUTH_MODELS_KEEP's comment) ---------------

log "Computing the auth \$ref closure from api.yaml"
CLOSURE=("${(@f)$(node "$SCRIPT_DIR/auth-schema-closure.mjs" "$WORK_DIR")}") || fail "auth-schema-closure.mjs failed"
(( ${#CLOSURE[@]} > 0 )) || fail "auth-schema-closure.mjs produced no schemas"

MISSING_FROM_KEEP=("${(@)CLOSURE:|AUTH_MODELS_KEEP}")
NOT_IN_CLOSURE=("${(@)AUTH_MODELS_KEEP:|CLOSURE}")
if (( ${#MISSING_FROM_KEEP[@]} > 0 )); then
    fail "api.yaml's auth surface reaches schema(s) that AUTH_MODELS_KEEP does not list: ${MISSING_FROM_KEEP[*]} -- an allow-list DROPS what it doesn't name, so these would be missing from the vendored tree. Add them to AUTH_MODELS_KEEP (and to the repo CLAUDE.md's model table), or, if a schema genuinely shouldn't be vendored, record the exclusion explicitly rather than leaving it to fall through."
fi
if (( ${#NOT_IN_CLOSURE[@]} > 0 )); then
    fail "AUTH_MODELS_KEEP lists schema(s) no auth operation reaches any more: ${NOT_IN_CLOSURE[*]} -- upstream removed or re-scoped them. Drop them from the list (and from the repo CLAUDE.md's model table)."
fi
log "Closure matches AUTH_MODELS_KEEP (${#AUTH_MODELS_KEEP[@]} schemas)"

# --- Stage the auth models -------------------------------------------------

log "Staging ${#AUTH_MODELS_KEEP[@]} auth model(s)"
mkdir -p "$STAGE_DIR/Models"
for name in "${AUTH_MODELS_KEEP[@]}"; do
    src="$GENERATED_ROOT/Models/$name.swift"
    [[ -f "$src" ]] || fail "expected generated Models/$name.swift not found -- api.yaml declares the schema but the generator emitted no file for it under that name (an inline-only schema, or a generator naming change?)"
    cp "$src" "$STAGE_DIR/Models/$name.swift"
done

# --- Stage the curated Infrastructure subset -------------------------------

log "Staging curated Infrastructure/ subset: ${INFRA_KEEP[*]}"
mkdir -p "$STAGE_DIR/Infrastructure"
for f in "${INFRA_KEEP[@]}"; do
    [[ -f "$GENERATED_ROOT/Infrastructure/$f" ]] || fail "expected generated Infrastructure/$f not found -- did the generator's output change?"
    cp "$GENERATED_ROOT/Infrastructure/$f" "$STAGE_DIR/Infrastructure/$f"
done

EMITTED_INFRA=("${(@f)$(find "$GENERATED_ROOT/Infrastructure" -name '*.swift' -exec basename {} \; | sort)}")
UNCLASSIFIED=("${(@)EMITTED_INFRA:|INFRA_KEEP}")
UNCLASSIFIED=("${(@)UNCLASSIFIED:|INFRA_DROP}")
if (( ${#UNCLASSIFIED[@]} > 0 )); then
    fail "generator emitted unclassified Infrastructure/ file(s): ${UNCLASSIFIED[*]} -- decide whether each belongs in INFRA_KEEP (vendored; the auth models need it) or INFRA_DROP (deliberately excluded, with the reason recorded), then update the repo CLAUDE.md's Code generation section to match. Do NOT ignore this: an unclassified file is silently dropped."
fi

# --- Strip RequestTask from Infrastructure/Models.swift --------------------
#
# Infrastructure/Models.swift is the generator's static support-type file
# (confusingly sharing a name with the Models/ directory), emitted
# unconditionally. It supplies CaseIterableDefaultsLast and UnknownCaseCheckable,
# which OTPType and SendLoginCodeRequest conform to. It also declares a trailing
# RequestTask class that exists only to support the excluded APIs/ output -- it
# references URLSessionDataTaskProtocol, declared only in the also-excluded
# URLSessionImplementations.swift. Rather than pull the whole HTTP client back
# in to satisfy one dead class, strip it here: a scripted, reproducible
# transform, never a hand-edit of the committed tree.

MODELS_INFRA="$STAGE_DIR/Infrastructure/Models.swift"
REQUEST_TASK_MARKER='public final class RequestTask: @unchecked Sendable {'
if ! grep -qF "$REQUEST_TASK_MARKER" "$MODELS_INFRA"; then
    fail "RequestTask class not found at its expected declaration in $MODELS_INFRA -- generator output changed; update the strip logic in $0"
fi

# The strip is a truncation, so it silently eats anything the generator might
# one day emit AFTER RequestTask, and it unconditionally drops the line
# immediately before the marker. Both are safe only under assumptions that hold
# today and could stop holding on any generator bump. Assert them explicitly.
#
# (1) Nothing top-level follows RequestTask. Its own members are indented, so
#     any line in the tail starting at column 0 with a declaration keyword or
#     attribute means the generator appended a declaration this truncation
#     would silently delete -- e.g. the `extension Response : Sendable where
#     T : Sendable {}` that sits just above RequestTask today would be lost if
#     it ever moved below it.
TAIL_AFTER_MARKER=$(awk -v marker="$REQUEST_TASK_MARKER" 'found { print } $0 == marker { found = 1 }' "$MODELS_INFRA")
if print -r -- "$TAIL_AFTER_MARKER" | grep -qE '^(@|public|internal|open|private|fileprivate|final|extension|struct|class|enum|protocol|func|var|let|typealias|actor)\b'; then
    fail "found a top-level declaration after RequestTask in $MODELS_INFRA, which the strip would silently truncate -- generator output changed; update the strip logic in $0"
fi

# (2) The line immediately before the marker is blank. The strip drops it to
#     avoid leaving a trailing blank line; if the generator ever puts a
#     declaration, a doc comment, or an attribute there instead, dropping it
#     would corrupt the file rather than tidy it.
LINE_BEFORE_MARKER=$(awk -v marker="$REQUEST_TASK_MARKER" '$0 == marker { print prev; exit } { prev = $0 }' "$MODELS_INFRA")
[[ -z "${LINE_BEFORE_MARKER//[[:space:]]/}" ]] || fail "expected a blank line before RequestTask in $MODELS_INFRA but found '$LINE_BEFORE_MARKER' -- the strip would delete it; update the strip logic in $0"

# A one-line-delayed buffer, tracked with an explicit `have_buffered` flag
# rather than the buffered line's truthiness -- the file has other blank lines
# mid-file that a truthiness check would also, wrongly, eat.
awk -v marker="$REQUEST_TASK_MARKER" '
    $0 == marker { exit }
    { if (have_buffered) print buffered; buffered = $0; have_buffered = 1 }
' "$MODELS_INFRA" > "$MODELS_INFRA.stripped"
mv "$MODELS_INFRA.stripped" "$MODELS_INFRA"
if grep -qE 'RequestTask|URLSessionDataTaskProtocol' "$MODELS_INFRA"; then
    fail "RequestTask strip left a dangling reference in $MODELS_INFRA -- generator output changed; update the strip logic in $0"
fi

# --- Demote Infrastructure/ to `internal` ----------------------------------
#
# The generator emits these support types `public`. wxyc-dj-ios's WXYCAPIModels
# vendors its own public copies of the same names, and WXYCAPI depends on both
# modules -- so two public `CodableHelper`s, two public `Response<T>`s, and so
# on would land in one dependency graph, ambiguous at any call site importing
# both. They are an implementation detail of the vendored models here, not part
# of this package's contract, so demote them.
#
# The transform is deliberately narrow: `public`/`open` at COLUMN 0 only, plus
# members inside an `extension` on one of the demoted types. It is NOT a blanket
# demotion of every `public` keyword, and the difference is load-bearing --
# CaseIterableDefaultsLast's default `init(from:)` is inherited by the PUBLIC
# OTPType, which conforms to the public `Decodable`, so that member must stay
# public or the build fails with "initializer 'init(from:)' must be declared
# public because it matches a requirement in public protocol 'Decodable'".
# (CaseIterableDefaultsLast and UnknownCaseCheckable are themselves already
# emitted without an access modifier, i.e. internal, so they are untouched here;
# a public type may conform to an internal protocol -- only the conformance is
# internal -- which is why the auth models compile against them at all.)
#
# The narrow form leaves exactly one gap the extension clause closes: a
# CONDITIONAL conformance extension on a demoted type (`extension NullEncodable:
# Codable where Wrapped: Codable`) whose members are public fails with "cannot
# declare a public initializer in an extension with internal requirements".
log "Demoting Infrastructure/ declarations to internal"
for f in "$STAGE_DIR/Infrastructure/"*.swift; do
    DEMOTED_TYPES="${(j:|:)INFRA_DEMOTED_TYPES}" perl -i -pe '
        BEGIN { $demoted = qr/^(?:@[\w.:()"\s]+\s+)*extension\s+($ENV{DEMOTED_TYPES})\b/; }
        if (/^\}/) { $in_demoted_extension = 0; }
        elsif ($_ =~ $demoted) { $in_demoted_extension = 1; }
        s/^(public|open) /internal /;
        s/^(\s+)(?:public|open) /$1internal /  if $in_demoted_extension;
    ' "$f"
done

# Assert the demotion actually took: nothing at column 0 may still be public or
# open. A generator bump that introduces a new top-level shape the regex misses
# (say `@frozen public struct`) would otherwise re-export a colliding public
# name and only surface as an ambiguity in a consumer app.
STILL_PUBLIC=$(grep -lE '^(@[A-Za-z]+ +)*(public|open) ' "$STAGE_DIR/Infrastructure/"*.swift 2>/dev/null | xargs -I{} basename {} | tr '\n' ' ' || true)
[[ -z "${STILL_PUBLIC// /}" ]] || fail "staged Infrastructure file(s) still declare public/open API at column 0 after the demotion transform: $STILL_PUBLIC -- generator output changed; update the transform in $0"

# ---------------------------------------------------------------------------
# Verify the staged tree, then swap it in
# ---------------------------------------------------------------------------

# The Swift-level companion to the api.yaml $ref closure. The generator does not
# emit one file per component schema and nothing else: it also flattens inline
# path schemas into named models (e.g. the `oneOf` 429 bodies on the two password
# sign-in paths generate as AuthSignInEmailPost429Response), and it flattens
# `allOf` composition. So a staged model can reference a generated type that no
# `$ref` in the spec points at, which the closure check cannot see. Catch it by
# name: if a staged file mentions any generated model NOT staged alongside it,
# stop.
#
# Comments are stripped first, and that is not a nicety: these schemas'
# descriptions discuss OTHER schemas by name in prose ("purpose-built rather
# than a $ref to the shared ApiErrorResponse", "per the DeviceAuthActionResponse
# precedent above"), so scanning raw text reports leaks that are only citations.
# Stripping is safe for this generator's output specifically -- the descriptions
# it emits are HTML-escaped (&#39;, &quot;), so no comment carries a raw quote,
# and no string literal in a model carries `//` or `/*`.
log "Checking staged models reference no unstaged generated model"
# Outside $STAGE_DIR on purpose -- the final swap is an `rsync -a --delete`
# of $STAGE_DIR, so a scratch subdirectory inside it would be vendored.
STRIPPED_DIR="$STAGE_DIR-comment-stripped"
mkdir -p "$STRIPPED_DIR"
for f in "$STAGE_DIR/Models/"*.swift; do
    perl -0pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$f" > "$STRIPPED_DIR/${f:t}"
done
STAGED_IDENTIFIERS=$(grep -ohE '\b[A-Z][A-Za-z0-9_]*\b' "$STRIPPED_DIR/"*.swift | sort -u)
LEAKED=()
while IFS= read -r emitted; do
    name="${emitted%.swift}"
    [[ -f "$STAGE_DIR/Models/$name.swift" ]] && continue
    print -r -- "$STAGED_IDENTIFIERS" | grep -qxF "$name" && LEAKED+=("$name")
done < <(find "$GENERATED_ROOT/Models" -name '*.swift' -exec basename {} \;)
if (( ${#LEAKED[@]} > 0 )); then
    fail "staged auth model(s) reference generated model(s) this package does not vendor: ${LEAKED[*]} -- either add them to AUTH_MODELS_KEEP, or the referencing schema has grown a dependency outside the auth surface and needs a decision. (This catches what the \$ref closure cannot: generator-flattened inline and allOf models have no \$ref pointing at them.)"
fi

# The plan's Infrastructure assertion: no vendored auth model's PUBLIC API may
# surface a demoted (now-internal) Infrastructure type, since a public signature
# mentioning an internal type does not compile. The models are public by design
# -- this package OWNS the auth wire schemas, and both consumer apps' orchestrators
# name them -- so this is the constraint that keeps `internal` viable for the
# support tree. If it ever fires, the recorded fallback is a scripted rename
# transform or hand-written mirror types for the offending schema; NOT module
# isolation, which doesn't rename symbols, it only re-scopes the ambiguity onto
# any file importing both modules.
log "Checking no public auth model surfaces a demoted Infrastructure type"
SURFACED=()
for t in "${INFRA_DEMOTED_TYPES[@]}"; do
    # Against the comment-stripped copies, for the same reason as above: these
    # descriptions are prose about HTTP, so "Response" appears in nearly every
    # one of them ("Response body for POST /auth/sign-out").
    hits=$(grep -lw "$t" "$STRIPPED_DIR/"*.swift 2>/dev/null | xargs -I{} basename {} | tr '\n' ' ' || true)
    [[ -n "${hits// /}" ]] && SURFACED+=("$t (in $hits)")
done
if (( ${#SURFACED[@]} > 0 )); then
    fail "vendored auth model(s) reference Infrastructure type(s) this script demotes to internal: ${SURFACED[*]} -- a public model cannot surface an internal type. Fall back to a scripted rename transform or hand-written mirror types for the offending schema (see the repo CLAUDE.md); do NOT reach for module isolation, which re-scopes the ambiguity rather than removing it."
fi

# Any model reaching for a String-keyed container needs `String: CodingKey`,
# which this package deliberately does not vendor (Extensions.swift is in
# INFRA_DROP), so such a model would not compile. Catching it here names the
# cause; letting it through surfaces as an opaque build failure instead.
if grep -rqF 'keyedBy: String.self' "$STAGE_DIR"; then
    OFFENDERS=$(grep -rlF 'keyedBy: String.self' "$STAGE_DIR" | sed "s|^$STAGE_DIR/||" | tr '\n' ' ')
    fail "staged model(s) need a String-keyed container (String: CodingKey), which this package deliberately doesn't vendor: $OFFENDERS -- exclude them, or reconsider the Extensions.swift exclusion (and read its INFRA_DROP comment first)"
fi

STAGED_MODELS=$(find "$STAGE_DIR/Models" -name '*.swift' | wc -l | tr -d ' ')
(( STAGED_MODELS == ${#AUTH_MODELS_KEEP[@]} )) || fail "staged Models/ has $STAGED_MODELS files, expected ${#AUTH_MODELS_KEEP[@]}"
STAGED_INFRA=$(find "$STAGE_DIR/Infrastructure" -name '*.swift' | wc -l | tr -d ' ')
(( STAGED_INFRA == ${#INFRA_KEEP[@]} )) || fail "staged Infrastructure/ has $STAGED_INFRA files, expected ${#INFRA_KEEP[@]}"

# `--delete` at the $DEST_DIR root, not per-subdirectory: the whole vendored
# tree is machine-owned (never hand-edit anything under it), so anything not in
# the staged tree is stale output and should go -- including a top-level file or
# a whole directory the generator stopped emitting.
log "Syncing $STAGED_MODELS Models/ + $STAGED_INFRA Infrastructure/ files into $DEST_DIR"
mkdir -p "$DEST_DIR"
rsync -a --delete "$STAGE_DIR/" "$DEST_DIR/" || fail "rsync into $DEST_DIR failed"

if (( KEEP_WORK_DIR == 0 )); then
    log "Cleaning up $WORK_DIR"
    rm -rf "$WORK_DIR"
else
    log "Leaving scratch clone in place at $WORK_DIR (--keep-work-dir)"
fi

FILE_COUNT=$(find "$DEST_DIR" -name '*.swift' | wc -l | tr -d ' ')
log "Done. $FILE_COUNT Swift files vendored into $DEST_DIR"
