import FP
import Foundation

/// Stored as UTF-8.
extension String: KeychainValue {
    public var keychainData: Data {
        return Data(utf8)
    }

    public static func fromKeychainData(_ data: Data) -> Result<String, KeychainError> {
        return .fromOptional(String(validating: data, as: UTF8.self), error: .notString)
    }
}
