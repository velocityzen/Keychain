import FP
import Foundation
import Security

/// Stores a new item under `key`.
///
/// Items are generic passwords unless `attributes` names another class.
/// Fails with ``KeychainError/duplicateItem`` if the item already exists.
public func keychainSet<Value: KeychainValue>(
    _ key: String, _ value: Value, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let query =
        itemQuery(key, attributes)
        |> withKeychainItemAttributes([KeychainValueTypeKeys.Data: value.keychainData])

    return await keychainItemAdd(query)
}

/// Replaces the value of an existing item.
///
/// Attributes that identify the item (class, service, access group and so on)
/// find it. Attributes that only describe it, such as accessibility, label or
/// comment, are applied to it along with the new value.
/// Fails with ``KeychainError/notFound`` if the item doesn't exist.
public func keychainUpdateValue<Value: KeychainValue>(
    _ key: String, _ value: Value, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let (query, changes) = updateQuery(key, attributes)

    return await keychainItemUpdate(
        query,
        changes |> withKeychainItemAttributes([KeychainValueTypeKeys.Data: value.keychainData])
    )
}

/// Stores the item, or updates it with ``keychainUpdateValue(_:_:_:)`` if it
/// already exists.
public func keychainSetOrUpdate<Value: KeychainValue>(
    _ key: String, _ value: Value, _ attributes: KeychainItemAttributes = [:]
) async -> Result<Void, KeychainError> {
    let result = await keychainSet(key, value, attributes)

    guard case .failure(.duplicateItem) = result else {
        return result
    }

    return await keychainUpdateValue(key, value, attributes)
}

/// Reads the item under `key` and decodes it as `Value`.
///
/// Fails with ``KeychainError/notFound`` if the item doesn't exist.
public func keychainGet<Value: KeychainValue>(
    _ key: String, as type: Value.Type = Value.self,
    _ attributes: KeychainItemAttributes = [:]
) async -> Result<Value, KeychainError> {
    let query =
        itemQuery(key, attributes)
        |> withKeychainItemAttributes([
            KeychainSearchKeys.MatchLimit: KeychainMatchLimitValues.one.rawValue,
            KeychainValueResultReturn.data.rawValue: true,
        ])

    return await keychainItemCopyMatching(query, as: Data.self).flatMap(Value.fromKeychainData)
}

public func keychainGetString(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<String, KeychainError>
{
    return await keychainGet(key, as: String.self, attributes)
}

public func keychainGetUUID(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<UUID, KeychainError>
{
    return await keychainGet(key, as: UUID.self, attributes)
}

public func keychainGetBool(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<Bool, KeychainError>
{
    return await keychainGet(key, as: Bool.self, attributes)
}

public func keychainGetData(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<Data, KeychainError>
{
    return await keychainGet(key, as: Data.self, attributes)
}

/// Reads the data of every item stored under `key`, for example the same key
/// in several services or access groups.
public func keychainGetDataAll(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<[Data], KeychainError>
{
    return await keychainItemCopyAllData(itemQuery(key, attributes))
}

/// Deletes every item that matches `key` and `attributes`.
///
/// Deleting an item that doesn't exist succeeds. Pass a service (see
/// ``withService(_:)``) to avoid deleting items with the same key that other
/// code stored under a different service.
@discardableResult
public func keychainDelete(_ key: String, _ attributes: KeychainItemAttributes = [:]) async
    -> Result<Void, KeychainError>
{
    return await keychainItemDelete(itemQuery(key, attributes))
}

/// The query for one item: a generic password unless the attributes name
/// another class, then the caller's attributes, then the key as the account.
func itemQuery(_ key: String, _ attributes: KeychainItemAttributes) -> KeychainItemAttributes {
    return [KeychainItemAttributeKeys.Class: KeychainClassValues.genericPassword.rawValue]
        |> withKeychainItemAttributes(attributes)
        |> withKeychainItemAttributes([KeychainPasswordAttributeKeys.Account: key])
}

/// Splits an item query into the attributes that find the item and the
/// descriptive attributes to change on it.
func updateQuery(_ key: String, _ attributes: KeychainItemAttributes) -> (
    query: KeychainItemAttributes, changes: KeychainItemAttributes
) {
    let query = itemQuery(key, attributes)

    return (
        query.filter { !descriptiveAttributeKeys.contains($0.key) },
        query.filter { descriptiveAttributeKeys.contains($0.key) }
    )
}

/// Attributes that describe an item rather than identify it. An update sets
/// them instead of searching by them, so updating with a new label or
/// accessibility still finds the existing item.
private let descriptiveAttributeKeys: Set<String> = {
    var keys: Set<String> = [
        KeychainItemAttributeKeys.Accessible,
        KeychainItemAttributeKeys.AccessControl,
        KeychainItemAttributeKeys.Label,
        KeychainItemAttributeKeys.Description,
        KeychainItemAttributeKeys.Comment,
        KeychainItemAttributeKeys.Creator,
        KeychainItemAttributeKeys.ItemType,
        KeychainItemAttributeKeys.IsInvisible,
        KeychainItemAttributeKeys.IsNegative,
        KeychainPasswordAttributeKeys.Generic,
    ]

    #if os(macOS)
        keys.insert(KeychainItemAttributeKeys.Access)
    #endif

    return keys
}()
