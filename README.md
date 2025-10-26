# Keychain

A modern, type-safe Swift wrapper for iOS, macOS, tvOS, and watchOS Keychain Services.

## Features

- Async/await API with Result types
- Type-safe value storage (String, Bool, UUID, Data)
- Thread-safe operations
- Comprehensive attribute support
- Platform-specific functionality
- Swift 6 compatible with full Sendable support

## Requirements

- Swift 6.2+
- macOS 12.0+
- iOS 15.0+
- tvOS 15.0+
- watchOS 8.0+

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/velocityzen/Keychain.git", from: "1.0.0")
]
```

Or add it via Xcode: File > Add Package Dependencies...

## Usage

### Basic Operations

#### Storing Values

```swift
import Keychain

// Store a string
let result = await keychainSet("username", "john.doe")

// Store a boolean
await keychainSet("isEnabled", true)

// Store a UUID
let id = UUID()
await keychainSet("userId", id)

// Store raw data
let data = Data([0x01, 0x02, 0x03])
await keychainSet("token", data)
```

#### Retrieving Values

```swift
// Get a string
let username = await keychainGetString("username")
switch username {
case .success(let value):
    print("Username: \(value)")
case .failure(let error):
    print("Error: \(error)")
}

// Get a boolean
let isEnabled = await keychainGetBool("isEnabled")

// Get a UUID
let userId = await keychainGetUUID("userId")

// Get raw data
let token = await keychainGetData("token")
```

#### Updating Values

```swift
// Update existing value
await keychainUpdateValue("username", "jane.doe")
```

#### Deleting Values

```swift
await keychainDelete("username")
```

### Using Attributes

The package supports all Keychain attributes through a composable builder pattern:

```swift
// Set accessibility level
await keychainSet(
    "password",
    "secret123",
    withAccessibility(.whenUnlockedThisDeviceOnly)([:])
)

// Use access groups (for app groups)
await keychainSet(
    "sharedToken",
    tokenData,
    withAccessGroup("group.com.example.app")([:])
)

// Combine multiple attributes
let attributes = withAccessibility(.afterFirstUnlock)
let attributesWithGroup = withAccessGroup("group.com.example.app")

await keychainSet(
    "key",
    "value",
    attributesWithGroup(attributes([:]))
)
```

### Custom Attributes

You can add any Keychain attribute using the attribute keys:

```swift
let attributes: KeychainItemAttributes = [
    KeychainItemAttributeKeys.Accessible: KeychainAccessibilityValues.whenUnlocked.rawValue,
    KeychainItemAttributeKeys.Synchronizable: true,
    KeychainPasswordAttributeKeys.Service: "com.example.app"
]

await keychainSet("key", "value", attributes)
```

## Error Handling

All operations return `Result<T, KeychainError>` types:

```swift
let result = await keychainGetString("key")

switch result {
case .success(let value):
    print("Value: \(value)")
    
case .failure(.notFound):
    print("Key not found")
    
case .failure(.notString):
    print("Value is not a string")
    
case .failure(let error):
    print("Error: \(error.description)")
}
```

### Available Errors

- `duplicateItem` - Item already exists
- `notFound` - Item not found
- `notString` - Value is not a string
- `notUUID` - Value is not a UUID
- `notBoolean` - Value is not a boolean
- `unexpectedValueData` - Unexpected data format
- `error(OSStatus)` - System error with status code

## Advanced Usage

### Accessibility Options

Control when keychain items are accessible:

```swift
// Most restrictive - requires passcode
withAccessibility(.whenPasscodeSetThisDeviceOnly)

// Only when device is unlocked
withAccessibility(.whenUnlockedThisDeviceOnly)
withAccessibility(.whenUnlocked) // Syncs via iCloud

// After first unlock (survives reboot)
withAccessibility(.afterFirstUnlockThisDeviceOnly)
withAccessibility(.afterFirstUnlock) // Syncs via iCloud
```

### Access Groups (App Groups)

Share keychain items between apps:

```swift
// In both apps, use the same access group
let attributes = withAccessGroup("group.com.example.shared")([:])

await keychainSet("sharedKey", "sharedValue", attributes)
```

### Querying Multiple Items

```swift
// Get all matching items
let result = await keychainGetDataAll("key")
```

## Thread Safety

All keychain operations are thread-safe and use internal locking mechanisms. You can safely call these functions from any async context.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
