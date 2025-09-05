import Foundation
import Security

@discardableResult
public func set(
    _ key: String, _ value: Bool, withAccess access: KeychainSwiftAccessOptions? = nil
) async -> Result<Bool, KeychainError> {
    let bytes: [UInt8] = value ? [1] : [0]
    let data = Data(bytes)

    return keychainSet(key, data, withAccess: access)
}

@discardableResult
public func set(
    _ key: String, _ value: String, withAccess access: KeychainSwiftAccessOptions? = nil
) async -> Bool {
    if let value = value.data(using: String.Encoding.utf8) {
        return keychainSet(key, value, withAccess: access)
    }

    return false
}

@discardableResult
public func keychainSet(
    _ key: String, _ value: Data, withAccess access: KeychainSwiftAccessOptions? = nil
) async -> Result<Bool, KeychainError> {
    var query: [String: Any] = [
        KeychainSwiftConstants.klass: kSecClassGenericPassword,
        KeychainSwiftConstants.attrAccount: prefixedKey,
        KeychainSwiftConstants.valueData: value,
        KeychainSwiftConstants.accessible: accessible,
    ]

    let status = await asyncSecItemAdd(query as CFDictionary, nil)

    if status == noErr {
        return .success(true)
    }

    return .failure(KeychainError.error(status))
}

public func keychainGetData(_ key: String, asReference: Bool = false) async -> Result<
    Data, KeychainError
> {
    var query: [String: Any] = [
        KeychainSwiftConstants.klass: kSecClassGenericPassword,
        KeychainSwiftConstants.attrAccount: key,
        KeychainSwiftConstants.matchLimit: kSecMatchLimitOne,
    ]

    if asReference {
        query[KeychainSwiftConstants.returnReference] = kCFBooleanTrue
    } else {
        query[KeychainSwiftConstants.returnData] = kCFBooleanTrue
    }
}

func asyncSecItemAdd(
    attributes attrs: CFDictionary
) async -> OSStatus {
    Task.detached {
        return SecItemAdd(attrs, nil)
    }
}

func asyncSecItemDelete(
    attributes attrs: CFDictionary
) async -> OSStatus {
    Task.detached {
        return SecItemDelete(attrs)
    }
}

func asyncSecItemCopyMatching(
    attributes attrs: CFDictionary
) async -> (OSStatus, CFTypeRef?) {
    Task.detached {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attrs, &item)
        return (status, item)
    }
}
