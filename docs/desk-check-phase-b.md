# Desk-check: are both apps' auth flows expressible against this surface?

Phase B's acceptance criterion is that both consumers' existing flows can be expressed against `WXYCAuth` **before** either adopts it, so a surface gap is found here rather than halfway through Phase C. This walks every call site in both apps against the shipped API. No adoption is implied by anything below.

Checked against `wxyc-dj-ios@d69bb48` (`Packages/WXYCAPI/Sources/WXYCAPI/`) and `wxyc-ios-64` (`Shared/MusicShareKit/Sources/MusicShareKit/Auth/`, `Shared/Core`).

## wxyc-dj-ios — `AuthService`

| Existing behavior | Expressed as | Notes |
|---|---|---|
| `performSignIn` routing one field to two routes | `signIn(email:password:)` / `signIn(username:password:)` | `SignInIdentifier` (which route, which body key) migrates into the package during Phase C; both routes exist here precisely so it can. |
| `establishSession`'s status table (401 / 429 / 400+403 / other) | `AuthWireError.status(_:body:)` + `AuthWireErrorBody(decoding:)` | The mapping stays in `AuthService` — deliberately. `rejectionCopy` and `OTPRejection` are presentation policy and never enter this package. |
| `set-auth-token` capture with body fallback | `SignInResult.sessionToken` | Same precedence, same empty-value handling. |
| `AuthError.missingSessionToken` | `AuthWireError.missingSessionToken` | Direct. |
| `lookUpEmail` incl. `{"email": null}` | `lookUpEmail(identifier:)` + `.missingLookupResult` | The no-match rejection stays distinguishable from a decode failure, which is what dj-ios's "No account matches that username" copy needs. |
| `sendVerificationCode` | `sendVerificationOTP(email:)` | The 400 whose body must render verbatim arrives as `.status(400, body:)`. |
| `signIn(email:otp:)`, digits-only normalization | `signIn(email:otp:)` | The `filter(\.isNumber)` normalization stays orchestrator-side; the wire client sends what it is given. |
| `refreshJWT` — GET, bearer, 401-vs-other, decode, `captureRotatedSessionToken` | `mintJWT(sessionToken:deviceFingerprint:)` → `MintedJWT` | `.status(401, …)` is what the `#53` terminal arm keys on; every other status stays a distinct number for the transient arm. |
| `callSignOut` | `signOut(sessionToken:)` | Direct. |
| `send`'s `onOutcome` with the cancellation carve-out | `RequestOutcome` | `.answered` → online, `.transportFailure` → offline, `.cancelled` → ignored. The carve-out that was a condition inside a `catch` becomes a case the consumer's switch cannot omit. |
| "Non-HTTP response" → `.network` | `AuthWireError.nonHTTPResponse` | Preserved as a *defect* signal, not a connectivity one, matching `AuthError.network`'s existing meaning on that path. |
| `CookielessSession` | `makeCookieFreeSession()` + the per-request flag | Both halves. The per-request flag is what survives dj-ios injecting an adapter over its own `RequestSession`. |
| `JWTPayload` / `JWTDecoder` / `JWTDecodeError` | `JWTClaims` / `JWTDecoder` / `JWTDecodeError` | Same three error cases (its tests assert by case), same `expiration`, same public memberwise init, same epoch-seconds at-rest coding. A `typealias` adoption. |
| `KeychainTokenStorage`'s four slots | `KeychainStore` keyed by account | `TokenSlot` and the `TokenStorage` protocol stay app-side; only the queries are shared. `afterFirstUnlockThisDeviceOnly` is passed explicitly. |

**No gap found.** One thing the package deliberately does not carry: `AuthService`'s `sessionEpoch` generation guard (its issue #66) and the whole `.signedIn(payload: nil)` pending window. Those are orchestration, and they stay.

## wxyc-ios-64 — `DefaultAuthNetworkClient`, `AuthenticationService`, `Core`

| Existing behavior | Expressed as | Notes |
|---|---|---|
| `signInAnonymously(baseURL:deviceFingerprint:)` | `signInAnonymously(deviceFingerprint:)` | `AnonymousSignInResult` carries the same `(sessionToken, userId)`. |
| `X-Device-Fingerprint` on both endpoints, omitted when nil | Same, both endpoints | Pinned by test. |
| `Origin` and `User-Agent` headers | `defaultHeaders` at init | Kept as caller data rather than baked in: dj-ios sends neither, and adding an `Origin` to its requests would change which better-auth middleware they arm. |
| `fetchJWT` → `JWTExchangeResult(jwt:capturedSessionToken:)` | `mintJWT` → `MintedJWT(jwt:claims:rotatedSessionToken:)` | Superset. The raw-capture semantics ios-64 documents (empty header is `""`, not `nil`) are preserved and pinned by test. |
| `AuthenticationError.networkError(error)` | `AuthWireError.transport(_:)` | The underlying error survives, which ios-64's coalescing classifies on. |
| `.invalidResponse` for a non-HTTP response and for a decode failure | `.nonHTTPResponse` / `.decoding(_:)` | **Split, not merged** — this is the distinction `RequestLineAnalytics`'s `.parse`-vs-`.network` phase reporting needs, and the reason D2 can claim unchanged event shapes. |
| `.serverError(statusCode:)` | `.status(_:body:)` | Superset (the body is now available). |
| `makeCookieFreeSession()` + per-request flag (its #948) | Same, verbatim | This is where the doubled guard came from. |
| `KeychainTokenStorage` with access group, `synchronizable`, and the local-only fallback add | `KeychainStore(service:accessibility:accessGroup:synchronizable:)` | Including the read that falls back to a non-synchronizable query, which is what makes an iCloud-unavailable write readable later. |
| `Core.SessionTokenProvider` | `WXYCAuth.SessionTokenProvider` | Same two methods, same `previousToken` coalescing contract. |
| `Core.URLSession.authedData(for:tokenProvider:)` | `AuthenticatedRequest.perform(_:using:tokenProvider:)` | See the deliberate difference below. |

**Two deliberate differences, neither a gap:**

1. `AuthenticatedRequest.perform` does **not** validate a 2xx; `Core.authedData` does. The consumers' status policies differ (dj-ios's conditional catalog GET treats a 304 as success), so validation stays with the caller. ios-64's adapter adds its existing `validateSuccessStatus()` call after the helper returns. This is moot for `Core` itself, which per the plan keeps its own copy and takes no remote dependency.
2. `mintJWT` accepts any 2xx where `fetchJWT` accepted only `200`. A `201` from `/auth/token` would now be honoured rather than raised as a server error. That is a widening, and an intentional one — the anonymous sign-in path already accepted `200` *or* `201`, so the old asymmetry was an accident of two hand-written status checks rather than a contract.

## Conclusion

Both apps' flows are expressible. The surface needs no additions for Phase C or Phase D2.

What was *not* desk-checked, because it is out of the package's charter: `AuthenticationService`'s refresh coalescing, dj-ios's offline grace window and epoch guard, and every piece of user-facing copy. All of that stays in the apps by design.
