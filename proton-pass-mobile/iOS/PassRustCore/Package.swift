// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PassRustCore",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "PassRustCore",
            targets: ["PassRustCore"]),
    ],
    targets: [
        .binaryTarget(name: "RustFrameworkFFI", path: "./RustFramework.xcframework"),

        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "PassRustCore",
            dependencies: [
                .target(name: "RustFrameworkFFI")
            ]
        ),
        .testTarget(
            name: "PassRustCoreTests",
            dependencies: ["PassRustCore"]),
    ]
)
