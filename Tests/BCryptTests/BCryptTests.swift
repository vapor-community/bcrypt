import XCTest
import BCrypt

class BCryptTests: XCTestCase {
    static let allTests = [
        ("testVersion", testVersion),
        ("testFail", testFail),
        ("testSanity", testSanity),
        ("testInvalidSalt", testInvalidSalt),
        ("testVerify", testVerify)
    ]

    func testVersion() throws {
        let digest = try Hash.make(message: "foo")
        XCTAssert(digest.makeString().hasPrefix("$2y$06$"))
    }

    func testFail() throws {
        let salt = try Salt()
        let digest = try Hash.make(message: "foo", with: salt)
        let res = try Hash.verify(message: "bar", matches: digest)
        XCTAssertEqual(res, false)
    }

    func testSanity() throws {
        let secret = "passwordpassword"

        let salt = try Salt(.two(.y), cost: 4, bytes: secret.makeBytes())
        let res = try Hash.make(message: "foo", with: salt)

        let parser = try Parser(res)
        let parsedSalt = try parser.parseSalt()

        XCTAssertEqual(secret, parsedSalt.bytes.makeString())
    }

    func testInvalidSalt() throws {
        do {
            _ = try Parser("foo".makeBytes())
            XCTFail("Should have failed")
        } catch let error as BCryptError {
            print(error)
        }
    }

    func testVerify() throws {
        for (desired, message) in tests {
            let result = try Hash.verify(message: message, matches: desired)
            XCTAssert(result, "Message '\(message)' did not create \(desired)")
        }
    }
}

let tests = [
    "$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm": "vapor",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.": "",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe": "a",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i": "abc",
    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC": "abcdefghijklmnopqrstuvwxyz",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO": "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"
]
