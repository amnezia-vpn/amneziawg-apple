// swift-tools-version:5.5
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
            url: "https://github.com/StarProxima/amneziawg-apple/releases/download/1.0.0/WireGuardFoundation.xcframework.zip",
            checksum: "b546dc09726f18ea8a59f3c8c3df94825694ff3d5163c477a9f381328f8059c5"
        )
    ]
)
