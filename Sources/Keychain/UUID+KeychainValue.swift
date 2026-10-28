import FP
import Foundation

/// Stored as its string form, so the item can also be read as a `String`.
extension UUID: KeychainValue {
    public var keychainData: Data {
        return uuidString.keychainData
    }

    public static func fromKeychainData(_ data: Data) -> Result<UUID, KeychainError> {
        return String.fromKeychainData(data).flatMap {
            .fromOptional(UUID(uuidString: $0), error: .notUUID)
        }
    }
}
