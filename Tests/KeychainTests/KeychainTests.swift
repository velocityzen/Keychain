import Foundation
import Testing

@testable import Keychain

enum TestValue {
    case string(String)
    case bool(Bool)
    case data(Data)
}
typealias TestType = (TestValue, TestValue, KeychainError?)

@Suite("Values") struct KeychainValuesTests {
    @Test(
        "values",
        arguments: [
            (.string("string"), .string("string"), nil),
            (.data("string".data(using: .utf8)!), .string("string"), nil),
            (.bool(true), .bool(true), nil),
            (.bool(false), .bool(false), nil),
            (.string("true"), .bool(true), .notBoolean),
            (.string("false"), .bool(false), .notBoolean),
        ] as [TestType])

    func setAndGetString(args: TestType) async throws {
        let testKey = "test-" + UUID().uuidString
        let (setValue, expectedValue, expectedError) = args
        let attributes = withClass(.genericPassword, withAccessibility(.whenUnlocked))

        let setResult =
            switch setValue {
            case .string(let value):
                await keychainSet(testKey, value, attributes)
            case .bool(let value):
                await keychainSet(testKey, value, attributes)
            case .data(let value):
                await keychainSet(testKey, value, attributes)
            }

        switch setResult {
        case .success:
            break
        case .failure(let error):
            throw error
        }

        switch expectedValue {
        case .string(let value):
            let result = await keychainGetString(testKey, withClass(.genericPassword))
            try expect(result, value, expectedError)

        case .bool(let value):
            let result = await keychainGetBool(testKey, withClass(.genericPassword))
            try expect(result, value, expectedError)

        case .data(let value):
            let result = await keychainGetData(testKey, withClass(.genericPassword))
            try expect(result, value, expectedError)
        }

        await keychainDelete(testKey, withClass(.genericPassword))
    }

}

func expect<A: Equatable, B: Equatable>(
    _ result: Result<A, KeychainError>, _ expectedValue: B,
    _ expectedError: KeychainError?
) throws {
    if let expectedError {
        switch result {
        case .success(let value):
            #expect(
                value == nil,
                "Expected error \(expectedError), but got success with value \(value)")

        case .failure(let error):
            #expect(error == expectedError)
        }

        return
    }

    switch result {
    case .success(let value):
        #expect(value as? B == expectedValue)

    case .failure(let error):
        throw error
    }
}
