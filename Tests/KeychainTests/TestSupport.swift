import FP
import Foundation
import Testing

@testable import Keychain

/// Every test item lives in this service, so leftovers are easy to find and
/// never collide with real items.
let testService = "com.velocityzen.Keychain.tests"
let testAttributes = [:] |> withService(testService)

/// Runs `body` with a fresh key and deletes the item afterwards, even when
/// `body` throws.
func withTestKey(
    _ attributes: KeychainItemAttributes = testAttributes,
    _ body: (String) async throws -> Void
) async throws {
    let key = "test-" + UUID().uuidString

    do {
        try await body(key)
    } catch {
        await keychainDelete(key, attributes)
        throw error
    }

    await keychainDelete(key, attributes)
}

func expectFailure<Value>(
    _ result: Result<Value, KeychainError>, _ expectedError: KeychainError,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    result.match(
        { value in
            Issue.record(
                "Expected \(expectedError), but got success with \(value)",
                sourceLocation: sourceLocation)
        },
        { error in #expect(error == expectedError, sourceLocation: sourceLocation) }
    )
}
