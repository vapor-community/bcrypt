# BCrypt

![Swift](http://img.shields.io/badge/swift-3.1-brightgreen.svg)
[![CircleCI](https://circleci.com/gh/vapor/bcrypt.svg?style=shield)](https://circleci.com/gh/vapor/bcrypt)
[![Slack Status](http://vapor.team/badge.svg)](http://vapor.team)

Swift implementation of the BCrypt password hashing function used in [Vapor](https://github.com/vapor/vapor)'s packages.

## Usage

### Hash

```swift
import BCrypt

let digest = try BCrypt.Hash.make(message: "foo")
print(digest.string)
```

### Verify

```swift
import BCrypt

let digest = "$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm"
let result = try BCrypt.Hash.verify(message: "vapor", matches: digest)
print(result)
```

## 📖 Documentation

Visit the Vapor web framework's [documentation](https://docs.vapor.codes) for instructions on how to use this package. 

## 💧 Community

Join the welcoming community of fellow Vapor developers in [slack](http://vapor.team).

## 🔧 Compatibility

This package has been tested on macOS and Ubuntu.
