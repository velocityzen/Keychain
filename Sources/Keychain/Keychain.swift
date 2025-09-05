import Foundation
import Security

public func keychainSet(
    _ key: String, _ value: Data, withAccess access: KeychainSwiftAccessOptions? = nil
) async -> OSStatus {

}

func asyncSecItemAdd(
    attributes attrs: CFDictionary
) async throws -> OSStatus {
    Task.detached {
        return SecItemAdd(attrs, nil)
    }
}

func asyncSecItemDelete(
    attributes attrs: CFDictionary
) async throws -> OSStatus {
    Task.detached {
        return SecItemDelete(attrs)
    }
}
