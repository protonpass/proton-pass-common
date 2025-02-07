// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AuthenticatorRustCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v13),
        .tvOS(.v16),
        .watchOS(.v8),
        .visionOS(.v2)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "AuthenticatorRustCore",
            targets: ["AuthenticatorRustCore"]),
    ],
    targets: [
        .binaryTarget(name: "RustFrameworkFFI", path: "./RustFramework.xcframework"),

        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "AuthenticatorRustCore",
            dependencies: [
                .target(name: "RustFrameworkFFI")
            ],
            swiftSettings: [
                .unsafeFlags(["-suppress-warnings"]),
            ]
        )
    ]
)
