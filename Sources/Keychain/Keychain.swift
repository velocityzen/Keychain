import Foundation
import Security

public typealias KeychainItemAttributes = [String: Sendable]

public func withAccessibility(
    _ accessible: KeychainAccessibilityValues, _ attributes: KeychainItemAttributes = [:]
)
    -> KeychainItemAttributes
{
    return withKeychainItemAttributes(
        attributes,
        [
            KeychainItemAttributeKeys.Accessible: accessible.rawValue
        ])

}

public func withAccessGroup(_ group: String, _ attributes: KeychainItemAttributes = [:])
    -> KeychainItemAttributes
{
    return withKeychainItemAttributes(
        attributes,
        [
            KeychainItemAttributeKeys.AccessGroup: group
        ])

}

public func withClass(
    _ itemClass: KeychainClassValues, _ attributes: KeychainItemAttributes = [:]
)
    -> KeychainItemAttributes
{
    return withKeychainItemAttributes(
        attributes,
        [
            KeychainItemAttributeKeys.Class: itemClass.rawValue
        ])

}

public func withKeychainItemAttributes(
    _ attributes: KeychainItemAttributes, _ add: KeychainItemAttributes
) -> KeychainItemAttributes {
    return attributes.merging(add) { attr, add in add }
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
    guard let value = value.data(using: String.Encoding.utf8) else {
        return .failure(.unexpectedPasswordData)
    }

    return await keychainSet(key, value, attributes)
}

public func keychainSet(
    _ key: String, _ value: Data,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let query = withKeychainItemAttributes(
        attributes,
        [
            KeychainPasswordAttributeKeys.Account: key,
            KeychainValueTypeKeys.Data: value,
        ])

    return await keychainItemAdd(query)
}

public func keychainGetString(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<
        String, KeychainError
    >
{
    return await keychainGetData(key, attributes).flatMap {
        guard let str = String(data: $0, encoding: .utf8) else {
            return .failure(.notString)
        }
        return .success(str)
    }
}

public func keychainGetBool(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<
        Bool, KeychainError
    >
{
    return await keychainGetData(key, attributes).flatMap { (data: Data) in
        if let firstByte = data.first {
            if firstByte == 0 {
                return .success(false)
            } else if firstByte == 1 {
                return .success(true)
            }
        }

        return .failure(.notBoolean)
    }
}

public func keychainGetData(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<
        Data, KeychainError
    >
{
    let query = withKeychainItemAttributes(
        attributes,
        [
            KeychainPasswordAttributeKeys.Account: key,
            KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.one.rawValue,
            KeychainValueResultReturn.data.rawValue: 1,
        ])

    return await keychainItemCopyMatching(query)
}

public func keychainGetDataAll(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<
        Data, KeychainError
    >
{
    let query = withKeychainItemAttributes(
        attributes,
        [
            KeychainPasswordAttributeKeys.Account: key,
            KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.all.rawValue,
            KeychainValueResultReturn.data.rawValue: 1,
        ])

    return await keychainItemCopyMatching(query)
}

@discardableResult
public func keychainDelete(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<
        Void, KeychainError
    >
{
    let query = attributes.merging([KeychainPasswordAttributeKeys.Account: key]) { attr, query in
        query
    }

    return await keychainItemDelete(query)
}

func keychainItemAdd(
    _ attributes: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    let task = Task.detached { () -> Result<Void, KeychainError> in
        sharedSecItemLock.withLock {
            let status = SecItemAdd(attributes as CFDictionary, nil)
            if status == noErr {
                return .success(())
            }

            return .failure(KeychainError.error(status))
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

            if status == noErr {
                guard let data = data as? Data else {
                    return .failure(KeychainError.notFound)
                }

                return .success(data)
            }

            return .failure(KeychainError.error(status))
        }
    }

    return await task.value
}

private let sharedSecItemLock = NSLock()
