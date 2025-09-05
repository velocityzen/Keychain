import Foundation
import Security

public func keychainSet(
    _ key: String, _ value: Bool, withAccess access: KeychainAccessibilityValues? = nil
) async -> Result<Void, KeychainError> {
    let bytes: [UInt8] = value ? [1] : [0]
    let data = Data(bytes)

    return await keychainSet(key, data, withAccess: access)
}

public func keychainSet(
    _ key: String, _ value: String, withAccess access: KeychainAccessibilityValues? = nil
) async -> Result<Void, KeychainError> {
    guard let value = value.data(using: String.Encoding.utf8) else {
        return .failure(.unexpectedPasswordData)
    }

    return await keychainSet(key, value, withAccess: access)
}

public func keychainSet(
    _ key: String, _ value: Data,
    withAccess access: KeychainAccessibilityValues? = nil
) async -> Result<Void, KeychainError> {
    let query: [String: Any] = [
        KeychainItemAttributeKeys.Class: KeychainClassValues.GenericPassword,
        KeychainItemAttributeKeys.Accessible: access ?? KeychainAccessibilityValues.WhenUnlocked,

        KeychainPasswordAttributeKeys.Account: key,
        KeychainValueTypeKeys.Data: value,
    ]

    let status = await keychainItemAdd(query as CFDictionary)

    if status == noErr {
        return .success(())
    }

    return .failure(KeychainError.error(status))
}

public func keychainGetString(_ key: String) async -> Result<
    String, KeychainError
> {
    return await keychainGet(key).flatMap {
        guard let str = String(data: $0, encoding: .utf8) else {
            return .failure(.notString)
        }
        return .success(str)
    }
}

public func keychainGetBool(_ key: String) async -> Result<
    Bool, KeychainError
> {
    return await keychainGet(key).flatMap { (data: Data) in
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

public func keychainGet(_ key: String) async -> Result<
    Data, KeychainError
> {
    let query: [String: Any] = [
        KeychainItemAttributeKeys.Class: KeychainClassValues.GenericPassword,
        KeychainPasswordAttributeKeys.Account: key,

        KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.One,
        KeychainValueResultReturn.Data: kCFBooleanTrue!,
    ]

    let (status, data) = await keychainItemCopyMatching(query as CFDictionary)

    if status == noErr {
        guard let data else {
            return .failure(KeychainError.notFound)
        }

        return .success(data)
    }

    return .failure(KeychainError.error(status))
}

struct SendableCFDictionary: @unchecked Sendable {
    let value: CFDictionary

    init(_ value: CFDictionary) {
        self.value = value
    }
}

func keychainItemAdd(
    _ attributes: CFDictionary
) async -> OSStatus {
    let sendableAttrs = SendableCFDictionary(attributes)
    let task = Task.detached { () -> OSStatus in
        let status = SecItemAdd(sendableAttrs.value, nil)
        return status
    }

    return await task.value
}

func keychainItemDelete(
    _ attributes: CFDictionary
) async -> OSStatus {
    let sendableAttrs = SendableCFDictionary(attributes)
    let task = Task.detached { () -> OSStatus in
        return SecItemDelete(sendableAttrs.value)
    }

    return await task.value
}

func keychainItemCopyMatching(
    _ attributes: CFDictionary
) async -> (OSStatus, Data?) {
    let sendableAttrs = SendableCFDictionary(attributes)
    let task = Task.detached { () -> (OSStatus, Data?) in
        var item: CFTypeRef?
        let result = SecItemCopyMatching(sendableAttrs.value, &item)
        guard let data = item as? Data else {
            return (result, nil)
        }

        return (result, data)
    }

    return await task.value
}
