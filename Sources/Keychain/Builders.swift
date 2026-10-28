import FP

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

/// Scopes items to a service, so keys from different services never collide.
public func withService(_ service: String) -> KeychainItemAttributesBuilder {
    return withKeychainItemAttributes([KeychainPasswordAttributeKeys.Service: service])
}

#if os(macOS)
    /// Uses the data protection keychain, which behaves like the keychain on iOS:
    /// accessibility values apply and access is controlled by access groups
    /// instead of per-item prompts.
    ///
    /// The process must be signed with a `keychain-access-groups` entitlement,
    /// otherwise calls fail with `errSecMissingEntitlement`. Items in the
    /// data protection keychain are separate from items in the file-based
    /// keychain that macOS uses by default.
    public func withDataProtectionKeychain() -> KeychainItemAttributesBuilder {
        return withKeychainItemAttributes([KeychainSearchKeys.UseDataProtectionKeychain: true])
    }
#endif

public func withKeychainItemAttributes(
    _ add: KeychainItemAttributes,
) -> KeychainItemAttributesBuilder {
    return { (_ attributes: KeychainItemAttributes?) in
        (attributes ?? [:]).merging(add) { attr, add in add }
    }
}
