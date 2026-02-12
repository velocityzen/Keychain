import FP
import Foundation
import Security

public typealias KeychainItemAttributes = [String: Sendable]
public typealias KeychainItemAttributesBuilder = (_ attributes: KeychainItemAttributes?) ->
    KeychainItemAttributes

public func withAccessibility(_ accessible: KeychainAccessibilityValues)
    -> KeychainItemAttributesBuilder
{
    return withKeychainItemAttributes([KeychainItemAttributeKeys.Accessible: accessible.rawValue])
}

public func withAccessGroup(_ group: String) -> KeychainItemAttributesBuilder {
    return withKeychainItemAttributes([KeychainItemAttributeKeys.AccessGroup: group])
}

public func withClass(_ itemClass: KeychainClassValues) -> KeychainItemAttributesBuilder {
    return withKeychainItemAttributes([KeychainItemAttributeKeys.Class: itemClass.rawValue])
}

public func withKeychainItemAttributes(
    _ add: KeychainItemAttributes,
) -> KeychainItemAttributesBuilder {
    return { (_ attributes: KeychainItemAttributes?) in
        (attributes ?? [:]).merging(add) { attr, add in add }
    }
}

public func keychainSet(
    _ key: String, _ value: Bool, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let bytes: [UInt8] = value ? [1] : [0]
    let data = Data(bytes)

    return await keychainSet(key, data, attributes)
}

public func keychainSet(
    _ key: String, _ value: String, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    return
        await Result
        .fromOptional(value.data(using: .utf8), error: .unexpectedValueData)
        .flatMapAsync { await keychainSet(key, $0, attributes) }
}

public func keychainSet(
    _ key: String, _ value: UUID, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    return await keychainSet(key, value.uuidString, attributes)
}

public func keychainSet(
    _ key: String, _ value: Data,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let query =
        attributes
        |> withKeychainItemAttributes([
            KeychainPasswordAttributeKeys.Account: key,
            KeychainValueTypeKeys.Data: value,
        ])

    return await keychainItemAdd(query)
}

public func keychainUpdateValue(
    _ key: String, _ value: Bool,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let bytes: [UInt8] = value ? [1] : [0]
    let value = Data(bytes)

    return await keychainUpdateValue(key, value, attributes)
}

public func keychainUpdateValue(
    _ key: String, _ value: String,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    return
        await Result
        .fromOptional(value.data(using: .utf8), error: .unexpectedValueData)
        .flatMapAsync { await keychainUpdateValue(key, $0, attributes) }
}

public func keychainUpdateValue(
    _ key: String, _ value: UUID,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    return await keychainUpdateValue(key, value.uuidString, attributes)
}

public func keychainUpdateValue(
    _ key: String, _ value: Data,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let query =
        attributes |> withKeychainItemAttributes([KeychainPasswordAttributeKeys.Account: key])
    return await keychainItemUpdate(query, [KeychainValueTypeKeys.Data: value])
}

public func keychainGetString(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<String, KeychainError>
{
    return await keychainGetData(key, attributes).flatMap {
        .fromOptional(String(data: $0, encoding: .utf8), error: .notString)
    }
}

public func keychainGetUUID(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<UUID, KeychainError>
{
    return await keychainGetString(key, attributes).flatMap {
        .fromOptional(UUID(uuidString: $0), error: .notUUID)
    }
}

public func keychainGetBool(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<Bool, KeychainError>
{
    return await keychainGetData(key, attributes).flatMap { (data: Data) in
        .fromOptional(
            data.first.flatMap {
                $0 == 0 ? false : $0 == 1 ? true : nil
            },
            error: .notBoolean
        )
    }
}

public func keychainGetData(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<Data, KeychainError>
{
    let query =
        attributes
        |> withKeychainItemAttributes([
            KeychainPasswordAttributeKeys.Account: key,
            KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.one.rawValue,
            KeychainValueResultReturn.data.rawValue: true,
        ])

    return await keychainItemCopyMatching(query)
}

public func keychainGetDataAll(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<[Data], KeychainError>
{
    let query =
        attributes
        |> withKeychainItemAttributes([
            KeychainPasswordAttributeKeys.Account: key,
            KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.all.rawValue,
            KeychainValueResultReturn.data.rawValue: true,
        ])

    return await keychainItemCopyMatchingAll(query)
}

@discardableResult
public func keychainDelete(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<Void, KeychainError>
{
    let query =
        attributes |> withKeychainItemAttributes([KeychainPasswordAttributeKeys.Account: key])
    return await keychainItemDelete(query)
}

func keychainItemAdd(
    _ attributes: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    let task = Task.detached { () -> Result<Void, KeychainError> in
        sharedSecItemLock.withLock {
            let status = SecItemAdd(attributes as CFDictionary, nil)

            switch status {
            case noErr:
                return .success(())

            case errSecDuplicateItem:
                return .failure(KeychainError.duplicateItem)

            default:
                return .failure(KeychainError.error(status))
            }
        }
    }

    return await task.value
}

func keychainItemUpdate(
    _ query: KeychainItemAttributes,
    _ update: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    let task = Task.detached { () -> Result<Void, KeychainError> in
        sharedSecItemLock.withLock {
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)

            switch status {
            case noErr:
                return .success(())

            case errSecItemNotFound:
                return .failure(KeychainError.notFound)

            default:
                return .failure(KeychainError.error(status))
            }
        }
    }

    return await task.value
}

func keychainItemDelete(
    _ attributes: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    let task = Task.detached { () -> Result<Void, KeychainError> in
        sharedSecItemLock.withLock {
            let status = SecItemDelete(attributes as CFDictionary)
            if status == noErr || status == errSecItemNotFound {
                return .success(())
            }

            return .failure(KeychainError.error(status))
        }
    }

    return await task.value
}

func keychainItemCopyMatching(
    _ attributes: KeychainItemAttributes
) async -> Result<Data, KeychainError> {
    let task = Task.detached { () -> Result<Data, KeychainError> in
        sharedSecItemLock.withLock {
            var data: CFTypeRef?
            let status = SecItemCopyMatching(attributes as CFDictionary, &data)

            guard status == noErr else {
                return .failure(KeychainError.error(status))
            }

            return .fromOptional(data as? Data, error: .notFound)
        }
    }

    return await task.value
}

func keychainItemCopyMatchingAll(
    _ attributes: KeychainItemAttributes
) async -> Result<[Data], KeychainError> {
    let task = Task.detached { () -> Result<[Data], KeychainError> in
        sharedSecItemLock.withLock {
            var data: CFTypeRef?
            let status = SecItemCopyMatching(attributes as CFDictionary, &data)

            guard status == noErr else {
                return .failure(KeychainError.error(status))
            }

            return .fromOptional(data as? [Data], error: .notFound)
        }
    }

    return await task.value
}

private let sharedSecItemLock = NSLock()
