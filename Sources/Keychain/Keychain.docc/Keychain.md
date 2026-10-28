# ``Keychain``

A type-safe, async wrapper for Keychain Services with typed `Result` errors.

## Overview

Keychain stores values as keychain items and returns `Result<Value, KeychainError>` from every call, so failures such as a missing item or a value of the wrong type are part of the signature.

Build attributes with composable builders and the `|>` operator from [fp-swift](https://github.com/velocityzen/fp-swift), then pass them to every call:

```swift
import FP
import Keychain

let appKeychain = [:] |> withService("com.example.app")

let tokenAttributes = appKeychain |> withAccessibility(.afterFirstUnlock)

if case .failure(let error) = await keychainSetOrUpdate("token", tokenData, tokenAttributes) {
    print("Couldn't store token: \(error)")
}

switch await keychainGet("token", as: Data.self, appKeychain) {
case .success(let token):
    use(token)
case .failure(.notFound):
    signIn()
case .failure(let error):
    print(error.description)
}
```

Items are generic passwords unless the attributes name another class, and the key is the item's account.

### Thread safety

Calls run off the caller's actor. On macOS, where the keychain API isn't thread-safe, calls run one at a time; callers waiting for their turn suspend instead of blocking a thread.

### macOS keychains

macOS stores items in the file-based login keychain by default. Add ``withDataProtectionKeychain()`` to use the data protection keychain, which behaves like the iOS keychain but needs a signed app with a `keychain-access-groups` entitlement.

## Topics

### Storing and updating

- ``keychainSet(_:_:_:)``
- ``keychainUpdateValue(_:_:_:)``
- ``keychainSetOrUpdate(_:_:_:)``

### Reading

- ``keychainGet(_:as:_:)``
- ``keychainGetString(_:_:)``
- ``keychainGetBool(_:_:)``
- ``keychainGetUUID(_:_:)``
- ``keychainGetData(_:_:)``
- ``keychainGetDataAll(_:_:)``

### Deleting

- ``keychainDelete(_:_:)``

### Values

- ``KeychainValue``

### Errors

- ``KeychainError``

### Attribute builders

- ``KeychainItemAttributes``
- ``KeychainItemAttributesBuilder``
- ``withService(_:)``
- ``withAccessibility(_:)``
- ``withAccessGroup(_:)``
- ``withClass(_:)``
- ``withDataProtectionKeychain()``
- ``withKeychainItemAttributes(_:)``
- ``withCurrentAccessGroup()``
- ``getKeychainAccessGroups()``

### Attribute keys

- ``KeychainItemAttributeKeys``
- ``KeychainPasswordAttributeKeys``
- ``KeychainSearchKeys``
- ``KeychainValueTypeKeys``
- ``KeychainValueResultReturn``
- ``KeychainCertificateAttributeKeys``
- ``KeychainCryptographicKeyAttributeKeys``
- ``KeychainCryptographicKeyUsageAttributeKeys``

### Attribute values

- ``KeychainConstant``
- ``KeychainClassValues``
- ``KeychainAccessibilityValues``
- ``KeychainMatchLimitValues``
- ``KeychainSynchronizabilityValues``
- ``KeychainUIAuthenticationValues``
- ``KeychainProtocolValues``
- ``KeychainAuthenticationTypeValues``
- ``KeychainKeyClassValues``
- ``KeychainKeyTypeValues``
- ``KeychainTokenIdValues``
- ``KeychainAccessGroupValues``
- ``KeychainPseudorandomFunctionValues``
