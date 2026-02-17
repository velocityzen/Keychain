// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Keychain",
    platforms: [
        .macOS(.v14), .iOS(.v17), .tvOS(.v17), .watchOS(.v10),
    ],
    products: [
        .library(
            name: "Keychain",
            targets: ["Keychain"])
    ],
    dependencies: [
        .package(url: "https://github.com/velocityzen/fp-swift.git", from: "1.1.1")
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
