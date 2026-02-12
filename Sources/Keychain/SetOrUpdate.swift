import FP
import Foundation

public func keychainSetOrUpdate(
    _ key: String, _ value: Bool, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let bytes: [UInt8] = value ? [1] : [0]
    let data = Data(bytes)

    return await keychainSetOrUpdate(key, data, attributes)
}

public func keychainSetOrUpdate(
    _ key: String, _ value: String, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    return
        await Result
        .fromOptional(value.data(using: .utf8), error: .unexpectedValueData)
        .flatMapAsync { await keychainSetOrUpdate(key, $0, attributes) }
}

public func keychainSetOrUpdate(
    _ key: String, _ value: UUID, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    return await keychainSetOrUpdate(key, value.uuidString, attributes)
}

public func keychainSetOrUpdate(
    _ key: String, _ value: Data, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let result = await keychainSet(key, value, attributes)

    if case .failure(.duplicateItem) = result {
        return await keychainUpdateValue(key, value, attributes)
    }

    return result
}
