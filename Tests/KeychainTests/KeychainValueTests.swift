import Foundation
import Security
import Testing

@testable import Keychain

@Suite("KeychainValue encoding")
struct KeychainValueTests {
    @Test("Bool needs exactly one 0 or 1 byte")
    func boolDecoding() {
        #expect(Bool.fromKeychainData(Data([1])) == .success(true))
        #expect(Bool.fromKeychainData(Data([0])) == .success(false))
        #expect(Bool.fromKeychainData(Data()) == .failure(.notBoolean))
        #expect(Bool.fromKeychainData(Data([2])) == .failure(.notBoolean))
        #expect(Bool.fromKeychainData(Data([1, 0])) == .failure(.notBoolean))
    }

    @Test("String rejects invalid UTF-8")
    func stringDecoding() {
        #expect(String.fromKeychainData(Data("héllo".utf8)) == .success("héllo"))
        #expect(String.fromKeychainData(Data([0xFF, 0xFE])) == .failure(.notString))
    }

    @Test("UUID is stored as its string")
    func uuidEncoding() {
        let uuid = UUID()
        #expect(uuid.keychainData == Data(uuid.uuidString.utf8))
        #expect(UUID.fromKeychainData(uuid.keychainData) == .success(uuid))
        #expect(UUID.fromKeychainData(Data("nope".utf8)) == .failure(.notUUID))
        #expect(UUID.fromKeychainData(Data([0xFF])) == .failure(.notString))
    }
}

@Suite("KeychainConstant")
struct KeychainConstantTests {
    @Test("init(rawValue:) maps Security constants back to cases")
    func rawValueRoundTrip() {
        #expect(
            KeychainAccessibilityValues(rawValue: kSecAttrAccessibleWhenUnlocked as String)
                == .whenUnlocked)
        #expect(
            KeychainClassValues(rawValue: kSecClassGenericPassword as String) == .genericPassword)
        #expect(KeychainClassValues(rawValue: "genericPassword") == nil)

        for value in KeychainAccessibilityValues.allCases {
            #expect(KeychainAccessibilityValues(rawValue: value.rawValue) == value)
        }

        for value in KeychainProtocolValues.allCases {
            #expect(KeychainProtocolValues(rawValue: value.rawValue) == value)
        }
    }
}

@Suite("KeychainError")
struct KeychainErrorTests {
    @Test("every error has a description")
    func descriptions() {
        let errors: [KeychainError] = [
            .duplicateItem, .notFound, .notString, .notUUID, .notBoolean,
            .unexpectedValueData, .noSecCode, .noAccessGroups, .error(errSecItemNotFound),
        ]

        for error in errors {
            #expect(!error.description.isEmpty)
            #expect(error.errorDescription == error.description)
        }

        #expect(KeychainError.error(errSecItemNotFound).description != "Unknown error")
    }
}

#if os(macOS)
    @Suite("Access groups")
    struct AccessGroupTests {
        @Test("withCurrentAccessGroup uses the first entitled group")
        func currentAccessGroup() {
            let groups = getKeychainAccessGroups()
            let attributes = withCurrentAccessGroup()([:])

            switch groups {
            case .success(let groups):
                let group = try? attributes.get()[KeychainItemAttributeKeys.AccessGroup]
                #expect(group as? String == groups.first)

            case .failure(let error):
                // An unsigned test runner has no keychain-access-groups entitlement.
                #expect(error == .noAccessGroups)
                #expect(attributes.map { _ in true } == .failure(error))
            }
        }
    }
#endif
