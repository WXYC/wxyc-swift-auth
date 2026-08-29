# wxyc-swift-auth — Claude Code Instructions

The shared Swift better-auth wire client for WXYC's two credentialed apps. Read `README.md` for the user-facing tour. The full decision record — ratified 2026-08-18, survived a nine-round adversarial plan review — is [`WXYC/wiki` `plans/wxyc-swift-auth.md`](https://github.com/WXYC/wiki/blob/main/plans/wxyc-swift-auth.md); **changes to those decisions are plan amendments, not local calls.**

## Tag Stability Policy (read before tagging)

**`vX.Y.Z` release tags are immutable.** A bad release is re-cut as a new patch version; a tag is **never** re-pointed at a different commit.

This deliberately **inverts** the policy in `wxyc-shared` and `wxyc-etl`, whose `gha/v1` is explicitly a *moving* major tag re-pointed forward on every non-breaking change. Do not port that model here by analogy — the two solve opposite problems:

- A reusable GitHub Actions workflow's consumers pin `@gha/v1` precisely so they get fixes without a fan-out; a moving tag is the feature.
- This package's consumers include **pin-less Xcode Cloud app builds**. A resolved version changing out from under one produces a binary nobody can reproduce from the tag, and the failure is silent — it ships. Immutability is the only thing that makes an unpinned consumer safe.

Consequences:

- Never `git tag -f`, never delete and re-push a release tag.
- A release that shipped a bug gets `vX.Y.Z+1`, even if the bad tag is minutes old.
- The version stays `0.x` until **both** apps have adopted (Phase C and Phase D2); Phase E tags `1.0`.

## Core conventions

- **Swift 6.2**, strict concurrency. Foundation + Security only — **no third-party dependencies, and no first-party ones either.** The charter is auth-only; if something here needs a dependency, it probably belongs in the consumer.
- Platforms `.iOS(.v18)`, `.macOS(.v14)`, `.watchOS(.v11)`. These are the *lowest* floor across consumers, not the highest: they are wxyc-dj-ios's, while wxyc-ios-64's packages all floor higher and contribute only the watchOS slice. **Sources must stay macOS-14 / iOS-18 compatible even though ios-64 never builds there** — `swift test` on a modern host will not catch a violation, which is why CI builds all three destinations explicitly.
- TDD per the org mandate: failing test → minimum implementation → refactor. The package's *value is its wire behaviors*, so each one lands red-green.
- File headers follow the org convention (filename, module, one-line purpose, created-by, copyright). The one exception is everything under `Sources/WXYCAuth/Generated/`, which carries the generator's own header — it is machine output, regenerated verbatim, never hand-edited.

## The line this package will not cross

`AuthWireClient` returns **facts**; the orchestrators decide what they **mean**.

There is no `.invalidCredentials` case, no `.rateLimited`, no retry policy on a 429. A served non-2xx arrives as `AuthWireError.status(Int, body: Data)` with the number and the bytes. This is not squeamishness about opinions — the two consumers genuinely map the same statuses differently (dj-ios turns a 403 into a reason-bearing rejection where a 401 is "wrong password"; ios-64's anonymous path has no such distinction), and a wire client that arbitrated would force one app's policy onto the other.

**A PR that adds a policy case to `AuthWireError` is a design change, not a convenience.** The same goes for "helpful" normalization: `MintedJWT.rotatedSessionToken` surfaces an empty header as `""` and not `nil` on purpose, because a consumer reading `if let` must not be told an absent header and an empty one are the same thing.

## Layout

```
Sources/WXYCAuth/
  AuthRequestSession.swift   The transport seam; URLSession conforms.
  AuthWireClient.swift       The eight endpoints, the session-token capture, the cookie guards.
  AuthWireError.swift        The error surface + better-auth's {message, code} body.
  JWTClaims.swift            Claims, the signature-free decoder, the three-case error taxonomy.
  KeychainStore.swift        Query building, OSStatus mapping, the sync-with-local-fallback write.
  RequestOutcome.swift       .answered / .transportFailure / .cancelled.
  SessionTokenProvider.swift The consumer seam + the retry-once transport helper.
  Generated/                 VENDORED api.yaml codegen -- never hand-edit. See "Code generation".
    Models/                    The 16 auth wire schemas.
    Infrastructure/            Generator support types, demoted to `internal`.
Sources/WXYCAuthTesting/     Canned-response session stub, in-memory storage double.
Tests/WXYCAuthTests/
contract-version.json        Pins the wxyc-shared commit Generated/ came from.
scripts/                     regenerate-api-types.sh, verify-api-types.sh, auth-schema-closure.mjs
```

## Non-obvious invariants (each of these closed a real defect)

- **`JWTClaims.exp` is coded by hand as epoch seconds, and must stay that way.** It is an **at-rest** format, not just a wire shape: wxyc-dj-ios persists this JSON into the Keychain as its offline grace anchor (its issue #57). A synthesized `Codable` would ride the *caller's* `dateEncodingStrategy` — `.iso8601` under dj-ios's `JSONCoders` — and silently orphan every installed build's stored anchor, which presents as "the update signed me out" and is unrecoverable offline. `JWTClaimsCodingTests` decodes a captured legacy anchor byte-for-byte; do not "simplify" past it.
- **`JWTClaims` ships `expiration` and a public memberwise `init` as members**, not as consumer-side extensions, because dj-ios adopts this type via `typealias` and a typealias can add neither a property nor an initializer.
- **The cookie guard is doubled on purpose.** `makeCookieFreeSession()` handles the session this package builds; `httpShouldHandleCookies = false` on every request is the only half that survives an **injected** session, which the `AuthRequestSession` seam makes routine (a consumer adapting its own session type bypasses the factory entirely). An unwanted cookie jar is fatal in two different ways — it wedges ios-64's anonymous sign-in ("Anonymous users cannot sign in again anonymously") and it arms better-auth's global `originCheckMiddleware`, which refuses dj-ios's next sign-in with `403 MISSING_OR_NULL_ORIGIN` *before any credential check*. Neither is a hypothetical; both shipped.
- **`.cancelled` is a case in `RequestOutcome`, not a condition inside a `catch`.** A cancelled request is neither reachability evidence nor an auth failure. Both apps learned this the hard way — dj-ios's search debounce cancels the in-flight request on every keystroke, so treating cancellation as a transport failure latched its offline state on every keystroke — and both then encoded the carve-out where the next author has to notice it. Here the type carries it.
- **`.decoding` is distinct from `.transport`.** ios-64's request-line analytics reports a failure *phase*; flattening the two makes its "event shapes unchanged" adoption criterion unreachable.
- **`.missingLookupResult` is distinct from `.decoding`.** `{"email": null}` is a well-formed *rejection* the caller has copy for, not a malformed response.
- **`AuthWireErrorBody.message` is required**, and that is what makes `init?(decoding:)` discriminating: Backend-Service's own routes and its Express rate limiter answer `{error: …}`, a different vocabulary, which must fail to decode rather than arrive as an all-`nil` value that reads like a parsed better-auth error. The requirement is now the *contract's*, not ours — `AuthWireErrorBody` is an alias for the generated `AuthErrorResponse` — so `GeneratedModelsContractTests` pins it, since a pin bump could otherwise relax it silently.
- **`KeychainAccessibility` is a required initializer parameter.** dj-ios writes `afterFirstUnlockThisDeviceOnly` and ios-64 writes `afterFirstUnlock` (plus an access group and iCloud sync). A default here would silently downgrade dj-ios's device-only posture on the next write, and nothing would fail — the item would just become more available than intended.
- **`MintedJWT.rotatedSessionToken` is not a rotation.** better-auth's session `token` column is assigned once and never rewritten; the `set-auth-token` header is a deterministic HMAC re-encoding of that same unchanged token. dj-ios persisting it and ios-64 ignoring it are *both* correct. Do not add logic that treats it as a new credential.

## Testing

`swift test` runs everything on the host. Two notes:

- **Keychain tests are real-Keychain and host-only.** There is deliberately no `SecItem*` shim: the value of `KeychainStore` is the query shapes it builds, and a shim would let the tests pass everywhere while proving nothing. A Swift Package unit-test bundle in a Simulator has no Keychain entitlement and fails every call with `errSecMissingEntitlement` (-34018) — wxyc-ios-64's `KeychainTokenStorageTests` documents the same wall. The round-trip suite is gated on a write probe and **skips** where the Keychain is unavailable; the query-shape suite touches no Keychain and always runs. If the round-trip suite skips in CI, investigate the runner — don't add a shim.
- **Access groups cannot be round-tripped** from a package test bundle (they need an entitled, signed host), so that plumbing is asserted by introspecting `baseQuery(account:)`.

Test fixtures use WXYC-representative artists — Juana Molina, Jessica Pratt, Chuquimamani-Condori. Not Queen, Radiohead, or The Beatles. The canonical pool is `wxyc-shared/src/test-utils/wxyc-example-data.json`.

## Consumers

| Repo | Layer that imports this | Status |
|---|---|---|
| `wxyc-dj-ios` | `Packages/WXYCAPI` | Phase C — not yet adopted |
| `wxyc-ios-64` | `Shared/MusicShareKit` | Phase D2 — not yet adopted |

Apps import `WXYCAuth` **from their networking layers, never from app-layer UI code** — the same rule dj-ios applies to `WXYCAPIModels`.

Note what does *not* adopt: ios-64's `Core` keeps its own identically-shaped `SessionTokenProvider` and its `URLSession.authedData`. `Core` is the dependency-free layer with 13 path-dependents including the widget and watch graphs, so it takes no remote dependency, and that duplication is accepted residue rather than an oversight.

## Code generation (`Sources/WXYCAuth/Generated/`)

The auth wire schemas are **generated from `wxyc-shared`'s `api.yaml`**, not hand-written. `contract-version.json` pins the exact `wxyc-shared` commit they came from (`wxycSharedSha` is the authoritative field the scripts read; `wxycSharedTag` / `apiYamlVersion` are labels for humans).

```bash
# Bump contract-version.json's wxycSharedSha first, then:
scripts/regenerate-api-types.sh

# Drift check -- regenerates into a scratch dir, never touching the committed
# tree, and diffs. This is what CI runs.
scripts/verify-api-types.sh
```

Needs `git`, `npm`/`node`, `java` (the generator runs on the JVM) and `rsync`. An ordinary `swift build` needs none of them. **Never hand-edit anything under `Sources/WXYCAuth/Generated/`** — the next regen discards it and `verify-api-types.sh` exists to catch anyone who tries.

### This package vendors a subset, and that is the deliberate opposite of the app repos

`wxyc-dj-ios`'s equivalent script vendors the **whole** of `Models/` and says so in its own comments. This one vendors 16 files. The reason is the whole point of the package existing: `WXYCAuth` ends up in both apps' dependency graphs alongside their own `WXYCAPIModels` trees, so vendoring every schema would put a third *public* `AlbumSearchResult`, `BinEntry`, and so on into those graphs — the duplicate-public-name shadowing hazard dj-ios's `CLAUDE.md` documents at length, recreated at package scope. This is a ratified decision (see the wiki plan's DTO-source row), not drift.

The 16 are exactly the transitive `$ref` closure of api.yaml's **non-device** `/auth/*` operations. The device-authorization (QR) surface is a documented non-goal — dj-ios is its sole consumer and already vendors its own `DeviceAuth*` types.

| Vendored | What it is |
|---|---|
| `AuthErrorResponse` | better-auth's `{message, code}`. Aliased as `AuthWireErrorBody`, plus an extension carrying `init?(decoding:)`. |
| `AuthPlainErrorResponse`, `AuthRateLimitedResponse` | The two *different* shapes a 429 can carry — better-auth's own limiter vs. the Express layer in front of it. |
| `AuthSignInResult` | Both password routes. `url` is **absent**, not null, when no `callbackURL` was sent. |
| `AuthTokenAndUserResult` | OTP and anonymous. Vendored for completeness; see below for why the anonymous path doesn't decode it. |
| `AuthTokenResponse` | `GET /auth/token`. What `mintJWT` decodes. |
| `AuthSendCodeResult`, `AuthSignOutResult` | `{success: true}`. |
| `AuthUser` | The shared `user` block. Requires `email`, `emailVerified`, `name`. |
| `LookupEmailRequest` / `LookupEmailResponse` | WXYC's own lookup route. `email` is nullable — a no-match is a well-formed rejection. |
| `EmailSignInRequest`, `UsernameSignInRequest`, `OTPSignInRequest`, `SendLoginCodeRequest`, `OTPType` | Request bodies and the named enum `SendLoginCodeRequest.type` carries. |

### Three hand-written shapes survive, each for a checked reason

`AuthWireClient` still declares three private structs. None of them is a leftover:

- **`SessionTokenCarrier`** (`{token}`) — the body fallback in `capturedSessionToken`. Three *different* declared bodies can reach that path (`AuthSignInResult`, `AuthTokenAndUserResult`, `AuthTokenResponse`), so decoding any one of them would reject the other two on their required fields, which is the opposite of what a fallback is for.
- **`AnonymousSignInBody`** (`{token?, user:{id}}`) — deliberately **not** `AuthTokenAndUserResult`. That schema embeds the full `AuthUser`, which requires `email`, `emailVerified` and `name`; decoding it would make anonymous sign-in fail over fields `AnonymousSignInResult` never exposes and no caller reads. Anonymous sign-in is wxyc-ios-64's cold-start path, run on every launch — the shared package must not turn a benign upstream field change into a launch failure. `GeneratedModelsContractTests` pins both halves: that `AuthUser` really does require those fields, and that a sparse body still signs in. If that first assertion ever fails because upstream relaxed the schema, that is the signal to delete this struct.
- **`JWTClaims`** — a JWT payload is not an HTTP schema; it is never in api.yaml, and its `exp` coding is an at-rest Keychain format (see the invariants above).

### The guards, and which of them can actually fail

An allow-list is a dangerous shape: it **drops** whatever nobody classified, so the symptom of an omission is a missing type far from its cause. dj-ios's `Infrastructure/` keep-list carries a staged-count assertion that its own comments concede can never fail — the staging directory is built by looping over the array it is compared against. A count check over `AUTH_MODELS_KEEP` would be equally vacuous, so the real guard is elsewhere:

- **The `$ref` closure comparison is the tripwire.** `scripts/auth-schema-closure.mjs` computes the closure from `api.yaml` — an input independent of the list it checks — and the script compares the two **in both directions**. A schema added upstream and `$ref`'d from an auth operation fails the run; so does a list entry that stops being reachable.
- **A Swift-level reference check** catches what the closure cannot: the generator also flattens *inline* path schemas and `allOf` composition into named models that no `$ref` points at. If a staged model mentions a generated model that isn't staged beside it, the run stops. It scans comment-stripped copies, because these schemas' descriptions discuss other schemas by name in prose.
- **`INFRA_KEEP` ∪ `INFRA_DROP` must cover every emitted `Infrastructure/` file.** Anything in neither is output nobody has looked at. This is the mechanism that would have caught `CalendarDate.swift` arriving via wxyc-shared's `postgenerate:swift` hook, which in dj-ios surfaced only as `cannot find type 'CalendarDate' in scope`.
- **A layout assertion** that the generator and its postgenerate hook emit nothing outside `Models/`, `Infrastructure/` and `APIs/`. (The plan reserved a third staging bucket for postgenerate support files on the assumption they'd land elsewhere. They land in `Infrastructure/`, so the classification above already covers them and there is no third bucket — but a future support file written somewhere else would otherwise be silently dropped.)
- **The byte-for-byte verify diff** is what proves all of the above, plus the two transforms below, are *reproducible*. A subset widened by hand fails there.

All four of the first group have been negative-tested by deliberately breaking each one; they fire.

### Two scripted transforms

Neither is ever a hand-edit of the committed tree.

- **The `RequestTask` strip.** `Infrastructure/Models.swift` supplies `CaseIterableDefaultsLast` and `UnknownCaseCheckable` (which `OTPType` and `SendLoginCodeRequest` conform to), and also a trailing `RequestTask` class that exists only to support the excluded `APIs/` output. It is truncated off, guarded by two assertions: that nothing top-level follows it, and that the line before it is blank. Ported verbatim from dj-ios.
- **The access-level demotion.** The generator emits its support types `public`; dj-ios's `WXYCAPIModels` vendors its own public copies of the same names, and `WXYCAPI` will depend on both modules. So `CodableHelper`, `Response`, `NullEncodable`, `ErrorResponse`, `DownloadException`, `DecodableRequestBuilderError` and `OpenISO8601DateFormatter` are rewritten to `internal`.

  **The transform is narrow on purpose and must stay that way.** It rewrites `public`/`open` at **column 0**, plus members inside an `extension` on one of those types. A blanket demotion of every `public` keyword does not compile: `CaseIterableDefaultsLast`'s default `init(from:)` is inherited by the **public** `OTPType`, which conforms to the public `Decodable`, so that member must stay public. (`CaseIterableDefaultsLast` and `UnknownCaseCheckable` are themselves already emitted without an access modifier — a public type may conform to an internal protocol, only the conformance is internal, which is why the models compile against them at all.) The extension clause exists for exactly one case: a *conditional* conformance extension on a demoted type fails with "cannot declare a public initializer in an extension with internal requirements".

  A companion assertion fails the run if anything at column 0 is still `public`/`open` afterwards — it catches a shape the rewrite regex misses, e.g. a future `@frozen public struct`.

  This is what makes `internal` viable, and the script asserts it: **no vendored auth model may reference a demoted type**, since a public model cannot surface an internal one. If that ever fires, the recorded fallback is a scripted rename or hand-written mirror types for the offending schema — **not** module isolation, which does not rename symbols, it only re-scopes the ambiguity onto any file importing both modules.

### What this guard does not prove

`verify-api-types.sh` proves the vendored tree matches `api.yaml`. It proves **nothing** about whether `api.yaml` matches the handler that actually serves the endpoint — dj-ios's `/djs/bin` failure (its issue #77) is the case where the mirror and the spec agreed and were *both* wrong. That job belongs to wxyc-shared's E2E auth guard. **Generating a DTO is safe only once you have read the handler, not just the schema.**

There is also no `schedule:` trigger on the workflow: a newer `api.yaml` upstream sits unnoticed until someone bumps the pin, which is the point — bumping the pin is when a human re-runs the generated-vs-hand-written evaluation.
