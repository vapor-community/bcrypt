import Random

public struct Salt {
    public static var defaultRandom: RandomProtocol = OSRandom()
    public static var defaultCost: UInt = 6

    public enum Version {
        case two(Scheme)

        public enum Scheme {
            case none
            case a
            case x
            case y
        }
    }

    public let version: Version
    public let cost: UInt
    public let bytes: Bytes

    public init(_ version: Version = .two(.y), cost: UInt = Salt.defaultCost, bytes: Bytes? = nil) throws {
        let bytes = try bytes ?? Salt.defaultRandom.bytes(count: 16)

        guard bytes.count == 16 else {
            throw BCryptError.invalidSaltByteCount
        }

        self.version = version
        self.cost = cost
        self.bytes = bytes
    }
}
