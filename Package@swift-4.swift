// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "BCrypt",
    products: [
        .library(name: "BCrypt", targets: ["BCrypt"]),
    ],
    dependencies: [
        // Module for generating random bytes and numbers.
        .package(url: "https://github.com/vapor/random.git", .upToNextMajor(from: "1.2.0")),
    ],
    targets: [
        .target(name: "BCrypt", dependencies: ["Random"]),
        .testTarget(name: "BCryptTests", dependencies: ["BCrypt"]),
    ]
)
