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

let defaultAttributes = [:] |> withClass(.genericPassword) |> withAccessibility(.whenUnlocked)

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

func setAndGetValue(args: TestType) async throws {
    let testKey = "test-" + UUID().uuidString
    let (setValue, expectedValue, expectedError) = args

    let setResult =
        switch setValue {
        case .string(let value):
            await keychainSet(testKey, value, defaultAttributes)
        case .bool(let value):
            await keychainSet(testKey, value, defaultAttributes)
        case .data(let value):
            await keychainSet(testKey, value, defaultAttributes)
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

@Test("UUID round-trip")
func setAndGetUUID() async throws {
    let testKey = "test-" + UUID().uuidString
    let expectedUUID = UUID()

    try await keychainSet(testKey, expectedUUID, defaultAttributes).get()

    let result = await keychainGetUUID(testKey, defaultAttributes)
    #expect(try result.get() == expectedUUID)

    await keychainDelete(testKey, defaultAttributes)
}

@Test("update value")
func updateValue() async throws {
    let testKey = "test-" + UUID().uuidString

    try await keychainSet(testKey, "initial", defaultAttributes).get()

    let updateResult = await keychainUpdateValue(testKey, "updated", defaultAttributes)
    try updateResult.get()

    let result = await keychainGetString(testKey, defaultAttributes)
    #expect(try result.get() == "updated")

    await keychainDelete(testKey, defaultAttributes)
}

@Test("update bool value")
func updateBoolValue() async throws {
    let testKey = "test-" + UUID().uuidString

    try await keychainSet(testKey, false, defaultAttributes).get()
    #expect(try await keychainGetBool(testKey, defaultAttributes).get() == false)

    try await keychainUpdateValue(testKey, true, defaultAttributes).get()
    #expect(try await keychainGetBool(testKey, defaultAttributes).get() == true)

    await keychainDelete(testKey, defaultAttributes)
}

@Test("update UUID value")
func updateUUIDValue() async throws {
    let testKey = "test-" + UUID().uuidString
    let newUUID = UUID()

    try await keychainSet(testKey, UUID(), defaultAttributes).get()
    try await keychainUpdateValue(testKey, newUUID, defaultAttributes).get()

    let result = await keychainGetUUID(testKey, defaultAttributes)
    #expect(try result.get() == newUUID)

    await keychainDelete(testKey, defaultAttributes)
}

@Test("delete returns success")
func deleteValue() async throws {
    let testKey = "test-" + UUID().uuidString

    try await keychainSet(testKey, "value", defaultAttributes).get()

    let deleteResult = await keychainDelete(testKey, defaultAttributes)
    #expect(deleteResult.toBool)

    let getResult = await keychainGetString(testKey, defaultAttributes)
    #expect(!getResult.toBool)
}

@Test("delete non-existent key succeeds")
func deleteNonExistent() async throws {
    let testKey = "test-" + UUID().uuidString
    let result = await keychainDelete(testKey, defaultAttributes)
    #expect(result.toBool)
}

@Test("get non-existent key returns error")
func getNonExistent() async throws {
    let testKey = "test-" + UUID().uuidString

    let result = await keychainGetString(testKey, defaultAttributes)
    result.match(
        { value in Issue.record("Expected error, but got success with value \(value)") },
        { error in #expect(error == .error(-25300)) }
    )
}

@Test("duplicate item error")
func duplicateItem() async throws {
    let testKey = "test-" + UUID().uuidString

    try await keychainSet(testKey, "first", defaultAttributes).get()

    let result = await keychainSet(testKey, "second", defaultAttributes)
    result.match(
        { _ in Issue.record("Expected duplicateItem error, but got success") },
        { error in #expect(error == .duplicateItem) }
    )

    await keychainDelete(testKey, defaultAttributes)
}

@Test("update non-existent key returns notFound")
func updateNonExistent() async throws {
    let testKey = "test-" + UUID().uuidString

    let result = await keychainUpdateValue(testKey, "value", defaultAttributes)
    result.match(
        { _ in Issue.record("Expected notFound error, but got success") },
        { error in #expect(error == .notFound) }
    )
}

@Test("setOrUpdate creates new item")
func setOrUpdateNew() async throws {
    let testKey = "test-" + UUID().uuidString

    try await keychainSetOrUpdate(testKey, "value", defaultAttributes).get()

    let result = await keychainGetString(testKey, defaultAttributes)
    #expect(try result.get() == "value")

    await keychainDelete(testKey, defaultAttributes)
}

@Test("setOrUpdate updates existing item")
func setOrUpdateExisting() async throws {
    let testKey = "test-" + UUID().uuidString

    try await keychainSet(testKey, "initial", defaultAttributes).get()
    try await keychainSetOrUpdate(testKey, "updated", defaultAttributes).get()

    let result = await keychainGetString(testKey, defaultAttributes)
    #expect(try result.get() == "updated")

    await keychainDelete(testKey, defaultAttributes)
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
