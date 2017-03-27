// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "BCrypt",
    dependencies: [
        // Module for generating random bytes and numbers.
        .Package(url: "https://github.com/vapor/random.git", Version(1,0,0, prereleaseIdentifiers: ["beta"]))
    ]
)
