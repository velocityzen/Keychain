import Foundation

/// A value the keychain can store as an item's data.
///
/// `Data`, `String`, `Bool` and `UUID` conform out of the box. Conform your own
/// types to store them with the same functions; return
/// ``KeychainError/unexpectedValueData`` when the data can't be decoded.
public protocol KeychainValue: Sendable {
    /// The bytes stored as the item's data.
    var keychainData: Data { get }

    /// Decodes a value from an item's data.
    static func fromKeychainData(_ data: Data) -> Result<Self, KeychainError>
}
