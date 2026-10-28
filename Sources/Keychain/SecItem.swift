import FP
import Foundation
import Security

#if os(macOS)
    /// SecItem calls are not thread-safe on macOS, so they run one at a time on
    /// this actor. Callers waiting for their turn suspend instead of blocking a
    /// thread, even while another call waits on an access prompt.
    private actor SecItemSerializer {
        func run<T: Sendable>(_ body: @Sendable () -> T) -> T {
            body()
        }
    }

    private let serializer = SecItemSerializer()

    private func secItem<T: Sendable>(_ body: @Sendable () -> T) async -> T {
        return await serializer.run(body)
    }
#else
    /// SecItem calls are thread-safe here. They can still block while the
    /// system checks access, so they run off the caller's actor.
    @concurrent
    private func secItem<T: Sendable>(_ body: @Sendable () -> T) async -> T {
        return body()
    }
#endif

func keychainItemAdd(
    _ attributes: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    return await secItem {
        result(of: SecItemAdd(attributes as CFDictionary, nil))
    }
}

func keychainItemUpdate(
    _ query: KeychainItemAttributes,
    _ update: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    return await secItem {
        result(of: SecItemUpdate(query as CFDictionary, update as CFDictionary))
    }
}

/// Deleting an item that doesn't exist succeeds.
func keychainItemDelete(
    _ query: KeychainItemAttributes
) async -> Result<Void, KeychainError> {
    return await secItem {
        switch result(of: SecItemDelete(query as CFDictionary)) {
        case .failure(.notFound):
            return .success(())
        case let other:
            return other
        }
    }
}

func keychainItemCopyMatching<T: Sendable>(
    _ query: KeychainItemAttributes,
    as type: T.Type
) async -> Result<T, KeychainError> {
    return await secItem {
        copyMatching(query, as: type)
    }
}

/// Reads the data of every item that matches the query.
///
/// The file-based macOS keychain can't return data for more than one item in
/// a single call, so this finds the items' persistent references first and
/// then reads each item's data.
func keychainItemCopyAllData(
    _ query: KeychainItemAttributes
) async -> Result<[Data], KeychainError> {
    return await secItem {
        let refsQuery =
            query
            |> withKeychainItemAttributes([
                KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.all.rawValue,
                KeychainValueResultReturn.persistentRef.rawValue: true,
            ])

        return copyMatching(refsQuery, as: [Data].self).flatMap { refs in
            refs.traverse { ref in
                let dataQuery =
                    query
                    |> withKeychainItemAttributes([
                        KeychainValueTypeKeys.PersistentRef: ref,
                        KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.one.rawValue,
                        KeychainValueResultReturn.data.rawValue: true,
                    ])

                return copyMatching(dataQuery, as: Data.self)
            }
        }
    }
}

private func copyMatching<T>(
    _ query: KeychainItemAttributes,
    as type: T.Type
) -> Result<T, KeychainError> {
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    return result(of: status).flatMap {
        .fromOptional(item as? T, error: .notFound)
    }
}

private func result(of status: OSStatus) -> Result<Void, KeychainError> {
    switch status {
    case errSecSuccess:
        return .success(())
    case errSecDuplicateItem:
        return .failure(.duplicateItem)
    case errSecItemNotFound:
        return .failure(.notFound)
    default:
        return .failure(.error(status))
    }
}
