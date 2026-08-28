# wxyc-swift-auth

Shared Swift client for WXYC's [better-auth](https://better-auth.com) surface: the wire mechanics that [wxyc-dj-ios](https://github.com/WXYC/wxyc-dj-ios) and [wxyc-ios-64](https://github.com/WXYC/wxyc-ios-64) had each implemented, independently, twice over.

Two products:

| Product | What it is |
|---|---|
| `WXYCAuth` | The wire client, JWT decoding, the request-outcome taxonomy, the retry-once helper, and Keychain plumbing. Foundation + Security only. |
| `WXYCAuthTesting` | A canned-response transport stub and an in-memory storage double, so a consumer can exercise its own auth orchestration without a network. |

## What it is not

It is **not** an auth orchestrator. It owns no tokens, touches no app state, and decides nothing about what a status *means* — a 401 arrives as `AuthWireError.status(401, body:)` and the app decides whether that is "wrong password", "session expired", or "sign the DJ out". The two consumers genuinely disagree on several of those mappings, and each keeps its own state machine.

It is also auth-only by charter. Library search, flowsheet, catalog — those stay in the apps.

## Install

```swift
.package(url: "https://github.com/WXYC/wxyc-swift-auth.git", from: "0.1.0")
```

Platforms: iOS 18, macOS 14, watchOS 11, Swift 6.2 strict concurrency. Those floors are the *lowest* across consumers, not the highest — see `Package.swift`.

## Use

```swift
import WXYCAuth

let client = AuthWireClient(
    authBaseURL: URL(string: "https://api.wxyc.org/auth")!,
    onOutcome: { outcome in
        // Attach connectivity tracking, analytics, whatever — see RequestOutcome.
    }
)

let signIn = try await client.signIn(email: "dj@wxyc.org", password: password)
let minted = try await client.mintJWT(sessionToken: signIn.sessionToken, deviceFingerprint: nil)
print(minted.claims.expiration)
```

Sign-in is one call per credential — `signIn(email:password:)`, `signIn(username:password:)`, `signIn(email:otp:)`, `signInAnonymously(deviceFingerprint:)` — plus `lookUpEmail(identifier:)` and `sendVerificationOTP(email:)` for the mailed-code flow, and `signOut(sessionToken:)`.

## Testing against it

```swift
import WXYCAuthTesting

let session = StubAuthRequestSession(.json(#"{"token":"session"}"#, headers: ["set-auth-token": "session"]))
let client = AuthWireClient(authBaseURL: url, session: session)
```

## Develop

```bash
swift test                                                    # behavior, on the host
xcodebuild build -scheme WXYCAuth -destination 'generic/platform=iOS'
xcodebuild build -scheme WXYCAuth -destination 'generic/platform=watchOS'
xcodebuild build -scheme WXYCAuth -destination 'generic/platform=macOS' MACOSX_DEPLOYMENT_TARGET=14.0
```

The `swift test` run exercises behavior against the host SDK; the three `xcodebuild` builds are what actually verify the declared floors.

## Releases

**Release tags are immutable.** A bad `v1.2.3` is re-cut as `v1.2.4`, never re-pointed. See `CLAUDE.md`'s Tag Stability Policy before tagging anything — the guarantee here is the *opposite* of the moving `gha/v1` tags in `wxyc-shared` and `wxyc-etl`.

## License

[PolyForm Noncommercial 1.0.0](./LICENSE). Student stations, schools, and nonprofits are already licensed — see [COMMERCIAL.md](./COMMERCIAL.md).
