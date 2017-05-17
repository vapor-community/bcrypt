// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "BCrypt",
    dependencies: [
        // Module for generating random bytes and numbers.
        .Package(url: "https://github.com/vapor/random.git", majorVersion: 1),
    ]
)
