import Core

// MARK: Serializer

extension Hash {
    public static func make(message: Bytes, with salt: Salt? = nil) throws -> Bytes {
        let hash = try Hash(salt)
        let digest = hash.digest(message: message)
        let serializer = Serializer(hash.salt, digest: digest)
        return serializer.serialize()
    }

    public static func make(message: BytesConvertible, with salt: Salt? = nil) throws -> Bytes {
        return try make(
            message: message.makeBytes(),
            with: salt
        )
    }
}

// MARK: Parser

extension Hash {
    public static func verify(message: Bytes, matches input: Bytes) throws -> Bool {
        let parser = try Parser(input)
        let salt = try parser.parseSalt()
        let hasher = try Hash(salt)
        let testDigest = hasher.digest(message: message)
        return try testDigest == parser.parseDigest() ?? []
    }

    public static func verify(message: BytesConvertible, matches digest: BytesConvertible) throws -> Bool {
        return try verify(
            message: message.makeBytes(),
            matches: digest.makeBytes()
        )
    }

    public static func verify(message: Bytes, matches digest: BytesConvertible) throws -> Bool {
        return try verify(
            message: message,
            matches: digest.makeBytes()
        )
    }

    public static func verify(message: BytesConvertible, matches digest: Bytes) throws -> Bool {
        return try verify(
            message: message.makeBytes(),
            matches: digest
        )
    }
}
