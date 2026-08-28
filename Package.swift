// swift-tools-version: 6.2
//
//  Package.swift
//  WXYCAuth
//
//  Copyright © 2026 WXYC. All rights reserved.
//

import PackageDescription

let package = Package(
    name: "wxyc-swift-auth",
    // The *lowest* floor across consumers, not the highest: iOS 18 / macOS 14
    // are wxyc-dj-ios's (`Packages/WXYCAPI/Package.swift`), and wxyc-ios-64's
    // packages all floor higher — they contribute only the watchOS 11 slice.
    // Consequence: these sources must stay macOS-14 / iOS-18 compatible even
    // though ios-64 never builds there. tvOS rides the SPM default.
    platforms: [.iOS(.v18), .macOS(.v14), .watchOS(.v11)],
    products: [
        .library(name: "WXYCAuth", targets: ["WXYCAuth"]),
        .library(name: "WXYCAuthTesting", targets: ["WXYCAuthTesting"]),
    ],
    targets: [
        .target(name: "WXYCAuth"),
        .target(name: "WXYCAuthTesting", dependencies: ["WXYCAuth"]),
        .testTarget(name: "WXYCAuthTests", dependencies: ["WXYCAuth", "WXYCAuthTesting"]),
    ]
)
