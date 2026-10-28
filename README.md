# Keychain

A modern, type-safe Swift wrapper for Keychain Services on macOS, iOS, tvOS, watchOS, and visionOS.

## Features

- Async/await API with typed `Result` errors
- Type-safe values: `String`, `Bool`, `UUID`, `Data`, or your own types via `KeychainValue`
- Composable attribute builders: `[:] |> withService(...) |> withAccessibility(...)`
- Safe to call from any task or actor

## Requirements

- Swift 6.3+
- macOS 26.0+
- iOS 26.0+
- tvOS 26.0+
- watchOS 26.0+
- visionOS 26.0+

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/velocityzen/Keychain.git", from: "3.0.0")
]
```

Or add it via Xcode: File > Add Package Dependencies...

## Usage

### Basic Operations

Every operation returns a `Result<Value, KeychainError>`. Handle it like any other `Result`: with `switch`, `if case`, or [fp-swift](https://github.com/velocityzen/fp-swift) helpers such as `match`, `flatMapAsync` and `withAll`. Write functions aren't `@discardableResult`, so the compiler warns when you ignore one: a failed write means the value wasn't stored.

Items are generic passwords unless you pass another class, and the key is the item's account. Without a service, an item is identified by its key alone, so scope your items with `withService` (see [Using Attributes](#using-attributes)) for anything beyond a quick prototype.

#### Storing Values

```swift
import FP
import Keychain

switch await keychainSet("username", "john.doe") {
case .success:
    print("Username stored")
case .failure(.duplicateItem):
    print("Username already stored; use keychainSetOrUpdate to replace it")
case .failure(let error):
    print("Couldn't store username: \(error)")
}
```

Booleans, UUIDs, raw data and your own `KeychainValue` types work the same way. Chain writes with `flatMapAsync`; the first failure skips the rest:

```swift
func storeDefaults() async -> Result<Void, KeychainError> {
    await keychainSet("isEnabled", true)
        .flatMapAsync { await keychainSet("userId", UUID()) }
        .flatMapAsync { await keychainSet("token", Data([0x01, 0x02, 0x03])) }
}
```

#### Retrieving Values

```swift
// Get any KeychainValue type
switch await keychainGet("username", as: String.self) {
case .success(let username):
    print("Username: \(username)")
case .failure(.notFound):
    print("No username stored")
case .failure(let error):
    print("Couldn't read username: \(error)")
}

// Or use the typed shortcuts. withAll runs the reads concurrently and
// returns the first failure, so the caller handles one Result
struct Defaults {
    let isEnabled: Bool
    let userId: UUID
    let token: Data
}

func loadDefaults() async -> Result<Defaults, KeychainError> {
    await withAll(
        await keychainGetBool("isEnabled"),
        await keychainGetUUID("userId"),
        await keychainGetData("token")
    )
    .map { isEnabled, userId, token in
        Defaults(isEnabled: isEnabled, userId: userId, token: token)
    }
}
```

#### Updating Values

```swift
// Fails with .notFound if the key doesn't exist
if case .failure(let error) = await keychainUpdateValue("username", "jane.doe") {
    print("Couldn't update username: \(error)")
}
```

Attributes that identify the item (class, service, access group, synchronizable) are used to find it. Attributes that only describe it, such as accessibility, label or comment, are applied to it along with the new value.

#### Set or Update Values

```swift
// Creates the item if it doesn't exist, updates it if it does
if case .failure(let error) = await keychainSetOrUpdate("username", "jane.doe") {
    print("Couldn't save username: \(error)")
}
```

#### Deleting Values

```swift
if case .failure(let error) = await keychainDelete("username") {
    print("Couldn't delete username: \(error)")
}
```

`keychainDelete` deletes every item that matches, and succeeds when nothing matches.

### Using Attributes

Attributes are built with composable builders and the `|>` operator from [fp-swift](https://github.com/velocityzen/fp-swift). Import `FP` to use the operator:

```swift
import FP
import Keychain

// Define your app's attributes once and pass them to every call,
// so your keys never collide with items stored by other code
let appKeychain = [:] |> withService("com.example.app")

if case .failure(let error) = await keychainSetOrUpdate("password", "secret123", appKeychain) {
    print("Couldn't store password: \(error)")
}

// Add more attributes per call
let tokenAttributes = appKeychain |> withAccessibility(.whenUnlockedThisDeviceOnly)

if case .failure(let error) = await keychainSetOrUpdate("token", tokenData, tokenAttributes) {
    print("Couldn't store token: \(error)")
}
```

### Custom Attributes

You can add any Keychain attribute using the attribute keys:

```swift
let attributes: KeychainItemAttributes = [
    KeychainItemAttributeKeys.Accessible: KeychainAccessibilityValues.whenUnlocked.rawValue,
    KeychainItemAttributeKeys.Synchronizable: true,
    KeychainPasswordAttributeKeys.Service: "com.example.app",
]

if case .failure(let error) = await keychainSetOrUpdate("key", "value", attributes) {
    print("Couldn't store key: \(error)")
}
```

The value enums map back from Security constants too, for example `KeychainAccessibilityValues(rawValue: kSecAttrAccessibleWhenUnlocked as String)` is `.whenUnlocked`.

### Custom Value Types

Conform a type to `KeychainValue` to store it with the same API. Return `.unexpectedValueData` when stored data can't be decoded:

```swift
struct PIN: KeychainValue {
    let digits: String

    var keychainData: Data {
        Data(digits.utf8)
    }

    static func fromKeychainData(_ data: Data) -> Result<PIN, KeychainError> {
        String.fromKeychainData(data).flatMap { digits in
            digits.count == 4 && digits.allSatisfy(\.isNumber)
                ? .success(PIN(digits: digits))
                : .failure(.unexpectedValueData)
        }
    }
}

if case .failure(let error) = await keychainSetOrUpdate("pin", PIN(digits: "1234"), appKeychain) {
    print("Couldn't store PIN: \(error)")
}

switch await keychainGet("pin", as: PIN.self, appKeychain) {
case .success(let pin):
    print("PIN has \(pin.digits.count) digits")
case .failure(.unexpectedValueData):
    print("Stored PIN is invalid")
case .failure(let error):
    print("Couldn't read PIN: \(error)")
}
```

## Error Handling

All operations return `Result<T, KeychainError>` types:

```swift
switch await keychainGetString("key") {
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

`KeychainError` is a `LocalizedError`, so `error.localizedDescription` gives the same message.

### Available Errors

- `duplicateItem` - Item already exists
- `notFound` - Item not found
- `notString` - Value is not a string
- `notUUID` - Value is not a UUID
- `notBoolean` - Value is not a boolean
- `unexpectedValueData` - Item data can't be decoded (for custom `KeychainValue` types)
- `noSecCode` - The running code's signature can't be read (macOS access groups)
- `noAccessGroups` - The app has no `keychain-access-groups` entitlement (macOS access groups)
- `error(OSStatus)` - System error with status code

## Advanced Usage

### Accessibility Options

Control when keychain items are accessible. Values without `ThisDeviceOnly` let the item move to a new device through backups and device migration; iCloud Keychain sync is controlled separately by `KeychainItemAttributeKeys.Synchronizable`.

```swift
// Most restrictive - requires a device passcode, never leaves this device
withAccessibility(.whenPasscodeSetThisDeviceOnly)

// Only while the device is unlocked
withAccessibility(.whenUnlockedThisDeviceOnly)
withAccessibility(.whenUnlocked) // Can move to a new device via backups

// After first unlock (survives reboot, readable in the background)
withAccessibility(.afterFirstUnlockThisDeviceOnly)
withAccessibility(.afterFirstUnlock) // Can move to a new device via backups
```

If you don't set one, the system default is `.whenUnlocked`.

### Access Groups (App Groups)

Share keychain items between apps:

```swift
// In both apps, use the same access group
let shared = [:] |> withService("com.example.shared") |> withAccessGroup("group.com.example.shared")

if case .failure(let error) = await keychainSetOrUpdate("sharedKey", "sharedValue", shared) {
    print("Couldn't share key: \(error)")
}
```

On macOS, `withCurrentAccessGroup()` adds the first access group from the running app's entitlements.

### Querying Multiple Items

```swift
// Get the data of every item stored under the key, across services and access groups
switch await keychainGetDataAll("key") {
case .success(let items):
    print("Found \(items.count) items")
case .failure(.notFound):
    print("No items stored under this key")
case .failure(let error):
    print("Couldn't read items: \(error)")
}
```

### macOS: Data Protection Keychain

By default, macOS stores items in the file-based login keychain. There, accessibility values have no effect and access is controlled by per-app prompts. To get the iOS behavior, use the data protection keychain:

```swift
let appKeychain = [:] |> withService("com.example.app") |> withDataProtectionKeychain()
```

The app must be signed with a `keychain-access-groups` entitlement; otherwise calls fail with `errSecMissingEntitlement` (-34018). Items in the two keychains are separate, so items already stored in the file-based keychain aren't visible through the data protection keychain.

## Thread Safety

All functions are async and safe to call from any task or actor. Keychain calls always run off the caller's actor, so they never block the main actor.

On macOS, the keychain API isn't thread-safe, so calls run one at a time. A caller waiting for its turn suspends instead of blocking a thread, so one call waiting on an access prompt doesn't stall the rest of the app's concurrent work. On iOS, tvOS, watchOS and visionOS, calls run concurrently.

Cancelling a task doesn't cancel a keychain call that has already started; the call runs to completion.

## License

MIT License - See [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
