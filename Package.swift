// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Keychain",
    platforms: [
        .macOS(.v26), .iOS(.v26), .tvOS(.v26), .watchOS(.v26), .visionOS(.v26),
    ],
    products: [
        .library(
            name: "Keychain",
            targets: ["Keychain"])
    ],
    dependencies: [
        .package(url: "https://github.com/velocityzen/fp-swift.git", from: "4.0.0")
    ],
    targets: [
        .target(
            name: "Keychain",
            dependencies: [
                .product(name: "FP", package: "fp-swift")
            ]),
        .testTarget(
            name: "KeychainTests",
            dependencies: ["Keychain"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
