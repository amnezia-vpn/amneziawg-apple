// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "WireGuardKit",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        .library(name: "WireGuardKit", targets: ["WireGuardKit"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "WireGuardKit",
            dependencies: ["WireGuardFoundation", "WireGuardKitC"]
        ),
        .target(
            name: "WireGuardKitC",
            dependencies: [],
            publicHeadersPath: "."
        ),
        .binaryTarget(
            name: "WireGuardFoundation",
            url: "https://github.com/StarProxima/amneziawg-apple/releases/download/1.1.0/WireGuardFoundation.xcframework.zip",
            checksum: "c30371789290f4a07ad7af3d31623332bc10f3eede398432aaad89496e39f0c7"
        )
    ]
)
