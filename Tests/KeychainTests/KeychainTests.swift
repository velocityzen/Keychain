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

let defaultAttributes = testAttributes |> withAccessibility(.whenUnlocked)

@Test(
    "values",
    arguments: [

        (.string("string"), .string("string"), nil),
        (.data(Data("string".utf8)), .string("string"), nil),
        (.bool(true), .bool(true), nil),
        (.bool(false), .bool(false), nil),
        (.string("true"), .bool(true), .notBoolean),
        (.string("false"), .bool(false), .notBoolean),
        (.data(Data([0, 1])), .bool(false), .notBoolean),
        (.data(Data([0xFF, 0xFE])), .string(""), .notString),

    ] as [TestType])

func setAndGetValue(args: TestType) async throws {
    let (setValue, expectedValue, expectedError) = args

    try await withTestKey { testKey in
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

        switch expectedValue {
        case .string(let value):
            let result = await keychainGetString(testKey, testAttributes)
            expect(result, value, expectedError)

        case .bool(let value):
            let result = await keychainGetBool(testKey, testAttributes)
            expect(result, value, expectedError)

        case .data(let value):
            let result = await keychainGetData(testKey, testAttributes)
            expect(result, value, expectedError)
        }
    }
}

@Test("UUID round-trip")
func setAndGetUUID() async throws {
    try await withTestKey { testKey in
        let expectedUUID = UUID()

        try await keychainSet(testKey, expectedUUID, defaultAttributes).get()

        let result = await keychainGetUUID(testKey, defaultAttributes)
        #expect(try result.get() == expectedUUID)
    }
}

@Test("UUID from a non-UUID string returns notUUID")
func getInvalidUUID() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, "not-a-uuid", defaultAttributes).get()

        expectFailure(await keychainGetUUID(testKey, defaultAttributes), .notUUID)
    }
}

@Test("generic get decodes the requested type")
func genericGet() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, "value", defaultAttributes).get()

        let result = await keychainGet(testKey, as: String.self, defaultAttributes)
        #expect(try result.get() == "value")
    }
}

@Test("default attributes store a generic password")
func defaultAttributesRoundTrip() async throws {
    // No class and no service: the item is a generic password found by its key.
    try await withTestKey([:]) { testKey in
        try await keychainSet(testKey, "value").get()
        #expect(try await keychainGetString(testKey).get() == "value")

        try await keychainUpdateValue(testKey, "updated").get()
        #expect(try await keychainGetString(testKey).get() == "updated")

        try await keychainDelete(testKey).get()
        expectFailure(await keychainGetString(testKey), .notFound)
    }
}

@Test("update value")
func updateValue() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, "initial", defaultAttributes).get()

        let updateResult = await keychainUpdateValue(testKey, "updated", defaultAttributes)
        try updateResult.get()

        let result = await keychainGetString(testKey, defaultAttributes)
        #expect(try result.get() == "updated")
    }
}

@Test("update bool value")
func updateBoolValue() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, false, defaultAttributes).get()
        #expect(try await keychainGetBool(testKey, defaultAttributes).get() == false)

        try await keychainUpdateValue(testKey, true, defaultAttributes).get()
        #expect(try await keychainGetBool(testKey, defaultAttributes).get() == true)
    }
}

@Test("update UUID value")
func updateUUIDValue() async throws {
    try await withTestKey { testKey in
        let newUUID = UUID()

        try await keychainSet(testKey, UUID(), defaultAttributes).get()
        try await keychainUpdateValue(testKey, newUUID, defaultAttributes).get()

        let result = await keychainGetUUID(testKey, defaultAttributes)
        #expect(try result.get() == newUUID)
    }
}

@Test("update finds the item when descriptive attributes change")
func updateWithNewLabel() async throws {
    try await withTestKey { testKey in
        let labeled = { (label: String) in
            testAttributes
                |> withKeychainItemAttributes([KeychainItemAttributeKeys.Label: label])
        }

        try await keychainSet(testKey, "initial", labeled("first")).get()
        try await keychainUpdateValue(testKey, "updated", labeled("second")).get()

        #expect(try await keychainGetString(testKey, labeled("second")).get() == "updated")
        expectFailure(await keychainGetString(testKey, labeled("first")), .notFound)
    }
}

@Test("delete returns success")
func deleteValue() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, "value", defaultAttributes).get()

        let deleteResult = await keychainDelete(testKey, defaultAttributes)
        #expect(deleteResult.isSuccess)

        expectFailure(await keychainGetString(testKey, defaultAttributes), .notFound)
    }
}

@Test("delete non-existent key succeeds")
func deleteNonExistent() async throws {
    let testKey = "test-" + UUID().uuidString
    let result = await keychainDelete(testKey, defaultAttributes)
    #expect(result.isSuccess)
}

@Test("get non-existent key returns notFound")
func getNonExistent() async throws {
    let testKey = "test-" + UUID().uuidString

    expectFailure(await keychainGetString(testKey, defaultAttributes), .notFound)
    expectFailure(await keychainGetDataAll(testKey, defaultAttributes), .notFound)
}

@Test("duplicate item error")
func duplicateItem() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, "first", defaultAttributes).get()

        expectFailure(await keychainSet(testKey, "second", defaultAttributes), .duplicateItem)
    }
}

@Test("update non-existent key returns notFound")
func updateNonExistent() async throws {
    let testKey = "test-" + UUID().uuidString

    expectFailure(await keychainUpdateValue(testKey, "value", defaultAttributes), .notFound)
}

@Test("setOrUpdate creates new item")
func setOrUpdateNew() async throws {
    try await withTestKey { testKey in
        try await keychainSetOrUpdate(testKey, "value", defaultAttributes).get()

        let result = await keychainGetString(testKey, defaultAttributes)
        #expect(try result.get() == "value")
    }
}

@Test("setOrUpdate updates existing item")
func setOrUpdateExisting() async throws {
    try await withTestKey { testKey in
        try await keychainSet(testKey, "initial", defaultAttributes).get()
        try await keychainSetOrUpdate(testKey, "updated", defaultAttributes).get()

        let result = await keychainGetString(testKey, defaultAttributes)
        #expect(try result.get() == "updated")
    }
}

@Test("setOrUpdate stores Bool and Data values")
func setOrUpdateOtherTypes() async throws {
    try await withTestKey { testKey in
        try await keychainSetOrUpdate(testKey, true, defaultAttributes).get()
        try await keychainSetOrUpdate(testKey, false, defaultAttributes).get()
        #expect(try await keychainGetBool(testKey, defaultAttributes).get() == false)

        let data = Data([0x01, 0x02, 0x03])
        try await keychainSetOrUpdate(testKey, data, defaultAttributes).get()
        #expect(try await keychainGetData(testKey, defaultAttributes).get() == data)
    }
}

@Test("setOrUpdate updates an item stored with different descriptive attributes")
func setOrUpdateWithNewAttributes() async throws {
    try await withTestKey { testKey in
        let stored =
            testAttributes
            |> withAccessibility(.afterFirstUnlock)
            |> withKeychainItemAttributes([KeychainItemAttributeKeys.Label: "first"])
        let updated =
            testAttributes
            |> withAccessibility(.whenUnlocked)
            |> withKeychainItemAttributes([KeychainItemAttributeKeys.Label: "second"])

        try await keychainSet(testKey, "initial", stored).get()
        try await keychainSetOrUpdate(testKey, "updated", updated).get()

        #expect(try await keychainGetString(testKey, testAttributes).get() == "updated")
    }
}

@Test("getDataAll returns the key from every service")
func getDataAll() async throws {
    let secondService = [:] |> withService(testService + ".second")

    try await withTestKey { testKey in
        try await keychainSet(testKey, "first", testAttributes).get()
        try await keychainSet(testKey, "second", secondService).get()

        let all = await keychainGetDataAll(testKey)
        let scoped = await keychainGetDataAll(testKey, testAttributes)
        await keychainDelete(testKey, secondService)

        let values = try all.get().compactMap { String(data: $0, encoding: .utf8) }
        #expect(Set(values) == ["first", "second"])
        #expect(try scoped.get() == [Data("first".utf8)])
    }
}

@Test("the same key in two services doesn't collide")
func servicesAreIsolated() async throws {
    let otherService = [:] |> withService(testService + ".other")

    try await withTestKey { testKey in
        try await keychainSet(testKey, "mine", testAttributes).get()
        try await keychainSet(testKey, "theirs", otherService).get()

        let mine = await keychainGetString(testKey, testAttributes)
        let theirs = await keychainGetString(testKey, otherService)
        await keychainDelete(testKey, otherService)

        #expect(try mine.get() == "mine")
        #expect(try theirs.get() == "theirs")
    }
}

@Test("concurrent calls all complete")
func concurrentCalls() async throws {
    let keys = (0..<20).map { _ in "test-" + UUID().uuidString }

    let results = await withTaskGroup(of: Result<String, KeychainError>.self) { group in
        for key in keys {
            group.addTask {
                await keychainSet(key, key, testAttributes)
                    .flatMapAsync { await keychainGetString(key, testAttributes) }
            }
        }

        return await group.reduce(into: []) { $0.append($1) }
    }

    for key in keys {
        await keychainDelete(key, testAttributes)
    }

    #expect(Set(results.compactMap { try? $0.get() }) == Set(keys))
}

func expect<A: Equatable, B: Equatable>(
    _ result: Result<A, KeychainError>, _ expectedValue: B,
    _ expectedError: KeychainError?,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    if let expectedError {
        expectFailure(result, expectedError, sourceLocation: sourceLocation)
        return
    }

    result.match(
        { value in #expect(value as? B == expectedValue, sourceLocation: sourceLocation) },
        { error in Issue.record("Unexpected error: \(error)", sourceLocation: sourceLocation) }
    )
}
