import FP
import Foundation
import Testing

@testable import Keychain

enum TestValue {
    case string(String)
    case bool(Bool)
    case data(Data)
}
typealias TestType = (TestValue, TestValue, KeychainError?)

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
    let setAttributes = [:] |> withClass(.genericPassword) |> withAccessibility(.whenUnlocked)

    let setResult =
        switch setValue {
        case .string(let value):
            await keychainSet(testKey, value, setAttributes)
        case .bool(let value):
            await keychainSet(testKey, value, setAttributes)
        case .data(let value):
            await keychainSet(testKey, value, setAttributes)
        }

    try setResult.get()

    let getAttributes = [:] |> withClass(.genericPassword)

    switch expectedValue {
    case .string(let value):
        let result = await keychainGetString(testKey, getAttributes)
        try expect(result, value, expectedError)

    case .bool(let value):
        let result = await keychainGetBool(testKey, getAttributes)
        try expect(result, value, expectedError)

    case .data(let value):
        let result = await keychainGetData(testKey, getAttributes)
        try expect(result, value, expectedError)
    }

    await keychainDelete(testKey, getAttributes)
}

func expect<A: Equatable, B: Equatable>(
    _ result: Result<A, KeychainError>, _ expectedValue: B,
    _ expectedError: KeychainError?
) throws {
    if let expectedError {
        result.match(
            { value in
                #expect(
                    Bool(false),
                    "Expected error \(expectedError), but got success with value \(value)")
            },
            { error in #expect(error == expectedError) }
        )

        return
    }

    result.match(
        { value in #expect(value as? B == expectedValue) },
        { error in Issue.record("Unexpected error: \(error)") }
    )
}
