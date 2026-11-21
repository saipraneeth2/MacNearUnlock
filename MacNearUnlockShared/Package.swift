// swift-tools-version: 6.0
//
// MacNearUnlockShared — protocol, canonical encoding, cryptographic verification,
// pairing, transport and engine logic shared by the macOS menu bar app and the
// iPhone companion. Everything here is platform-neutral and unit-testable with
// `swift test` on a Mac without code signing or physical hardware.

import PackageDescription

let package = Package(
    name: "MacNearUnlockShared",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "MacNearUnlockShared", targets: ["MacNearUnlockShared"]),
    ],
    targets: [
        .target(
            name: "MacNearUnlockShared",
            path: "Sources/MacNearUnlockShared"
        ),
        .testTarget(
            name: "MacNearUnlockSharedTests",
            dependencies: ["MacNearUnlockShared"],
            path: "Tests/MacNearUnlockSharedTests"
        ),
    ]
)
