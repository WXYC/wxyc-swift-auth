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
- File headers follow the org convention (filename, module, one-line purpose, created-by, copyright).

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
Sources/WXYCAuthTesting/     Canned-response session stub, in-memory storage double.
Tests/WXYCAuthTests/
```

## Non-obvious invariants (each of these closed a real defect)

- **`JWTClaims.exp` is coded by hand as epoch seconds, and must stay that way.** It is an **at-rest** format, not just a wire shape: wxyc-dj-ios persists this JSON into the Keychain as its offline grace anchor (its issue #57). A synthesized `Codable` would ride the *caller's* `dateEncodingStrategy` — `.iso8601` under dj-ios's `JSONCoders` — and silently orphan every installed build's stored anchor, which presents as "the update signed me out" and is unrecoverable offline. `JWTClaimsCodingTests` decodes a captured legacy anchor byte-for-byte; do not "simplify" past it.
- **`JWTClaims` ships `expiration` and a public memberwise `init` as members**, not as consumer-side extensions, because dj-ios adopts this type via `typealias` and a typealias can add neither a property nor an initializer.
- **The cookie guard is doubled on purpose.** `makeCookieFreeSession()` handles the session this package builds; `httpShouldHandleCookies = false` on every request is the only half that survives an **injected** session, which the `AuthRequestSession` seam makes routine (a consumer adapting its own session type bypasses the factory entirely). An unwanted cookie jar is fatal in two different ways — it wedges ios-64's anonymous sign-in ("Anonymous users cannot sign in again anonymously") and it arms better-auth's global `originCheckMiddleware`, which refuses dj-ios's next sign-in with `403 MISSING_OR_NULL_ORIGIN` *before any credential check*. Neither is a hypothetical; both shipped.
- **`.cancelled` is a case in `RequestOutcome`, not a condition inside a `catch`.** A cancelled request is neither reachability evidence nor an auth failure. Both apps learned this the hard way — dj-ios's search debounce cancels the in-flight request on every keystroke, so treating cancellation as a transport failure latched its offline state on every keystroke — and both then encoded the carve-out where the next author has to notice it. Here the type carries it.
- **`.decoding` is distinct from `.transport`.** ios-64's request-line analytics reports a failure *phase*; flattening the two makes its "event shapes unchanged" adoption criterion unreachable.
- **`.missingLookupResult` is distinct from `.decoding`.** `{"email": null}` is a well-formed *rejection* the caller has copy for, not a malformed response.
- **`AuthWireErrorBody.message` is required**, and that is what makes `init?(decoding:)` discriminating: Backend-Service's own routes and its Express rate limiter answer `{error: …}`, a different vocabulary, which must fail to decode rather than arrive as an all-`nil` value that reads like a parsed better-auth error.
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

## Not yet built (Phase B, second PR)

The vendored generated auth-subset tree (`Models/` from `wxyc-shared`'s `api.yaml`) with its own `contract-version.json` pin, the `regenerate-api-types.sh` / `verify-api-types.sh` ports, and the drift workflow. Design constraints already settled and not to be relitigated: an explicit `AUTH_MODELS_KEEP` allowlist with a staged-count assertion **and** a `$ref`-closure check; `Infrastructure/` vendored **`internal`** via a scripted access-level transform, with the assertion that no public auth model surfaces an Infrastructure type; a third staging bucket for `postgenerate:swift` support files. The subsetting is a scripted allowlist, **never a hand-prune** — the verify script proves the tree by full diff against a scratch regeneration, so the allowlist must reproduce byte-for-byte on every run.
