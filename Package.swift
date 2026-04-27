// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftBSV",
    platforms: [
        // iOS 16 / macOS 13 floor — covers everything Swift 5.9+ ships.
        // Consumers (Henceforth, etc.) target iOS 18+ already; the library
        // can be loosened later without breaking the wider Apple ecosystem.
        .macOS(.v13), .iOS(.v16), .tvOS(.v16)
    ],
    products: [
        .library(
            name: "SwiftBSV",
            targets: ["SwiftBSV"]),
    ],
    dependencies: [
        // Minimum versions track what the major consumer (FORTHapp) actually
        // resolves — bumping the floor here prevents older transitive
        // resolutions from sneaking through.
        .package(url: "https://github.com/Boilertalk/secp256k1.swift.git", from: "0.1.7"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.9.0"),
    ],
    targets: [
        .target(
            name: "SwiftBSV",
            dependencies: [
                // Explicit `.product(name:package:)` is required since
                // swift-tools 5.2 because the package's repo identity
                // ("secp256k1.swift") differs from its product name
                // ("secp256k1"). Without this, SPM can't resolve the
                // product and the build fails with "product 'secp256k1'
                // required by package 'swiftbsv' target 'SwiftBSV' not
                // found."
                .product(name: "secp256k1", package: "secp256k1.swift"),
                "CryptoSwift"
            ]
        ),
        .testTarget(
            name: "SwiftBSVTests",
            dependencies: ["SwiftBSV"]),
    ]
)
