//
//  AuthModelCoding.swift
//  WXYCAuth
//
//  The JSON decoder the vendored auth models need. Public because the models
//  are public and are not decodable from real traffic without it.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// Coding configuration for the generated auth wire models.
///
/// **This is not a convenience.** Several vendored models — `AuthUser` above
/// all, which every sign-in response embeds — carry `Date` properties
/// (`createdAt`, `updatedAt`, `banExpires`). A stock `JSONDecoder()` uses
/// `.deferredToDate`, which expects a *number*, so decoding a real
/// `POST /auth/sign-in/anonymous` body fails with
/// `typeMismatch … Expected to decode Double but found a string instead`.
/// Without a configured decoder the package would export public types that
/// cannot read the responses they were generated from.
///
/// The generator's own answer does not survive contact with this server
/// either: `OpenISO8601DateFormatter` (vendored, `internal`) is a fixed
/// `yyyy-MM-dd'T'HH:mm:ssZZZZZ` format with **no fractional-seconds branch**,
/// and Backend-Service emits both forms — the same fact `wxyc-dj-ios`'s
/// `JSONCoders` was written for. Measured on this toolchain: that formatter
/// accepts `2026-08-01T12:00:00Z` and rejects `2026-08-01T12:00:00.000Z`.
///
/// So the strategy here tries fractional seconds first, then plain, and both
/// are pinned by tests. It deliberately does **not** delegate to Foundation's
/// `.iso8601`: that strategy is `ISO8601DateFormatter` with
/// `.withInternetDateTime`, whose tolerance for a fractional component has
/// varied across OS versions, and this package's floor spans iOS 18 / macOS 14
/// / watchOS 11. Spelling both formats out makes the behaviour the package's
/// own rather than the platform's.
public enum AuthModelCoding {

    /// A decoder configured for the generated auth models.
    ///
    /// Use this rather than a bare `JSONDecoder()` for anything under
    /// `Generated/`. A fresh instance each call: `JSONDecoder` is a mutable
    /// class, so a shared one would let any caller reconfigure every other
    /// caller's decoding.
    public static func makeJSONDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let text = try container.decode(String.self)
            guard let date = iso8601WithFractionalSeconds.date(from: text)
                ?? iso8601.date(from: text) else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Expected an ISO-8601 date-time, with or without fractional seconds, but found '\(text)'"
                )
            }
            return date
        }
        return decoder
    }

    // `DateFormatter` is documented as thread-safe for formatting and parsing
    // once configured, and these two are never mutated after construction, so
    // they are shared rather than rebuilt per call. `nonisolated(unsafe)` is
    // the accurate annotation: the compiler cannot verify the no-mutation
    // half, but nothing here mutates them.
    private nonisolated(unsafe) static let iso8601WithFractionalSeconds = makeFormatter("yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ")
    private nonisolated(unsafe) static let iso8601 = makeFormatter("yyyy-MM-dd'T'HH:mm:ssZZZZZ")

    private static func makeFormatter(_ format: String) -> DateFormatter {
        let formatter = DateFormatter()
        // The POSIX locale is load-bearing, not boilerplate: a fixed format
        // string parsed under the user's locale can pick up a non-Gregorian
        // calendar and fail on perfectly valid input.
        formatter.calendar = Calendar(identifier: .iso8601)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = format
        return formatter
    }
}
