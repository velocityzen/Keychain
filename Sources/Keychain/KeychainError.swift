import Foundation
import Security

public enum KeychainError: LocalizedError, Equatable, CustomStringConvertible, Codable {
    case duplicateItem
    case notFound
    case notString
    case notUUID
    case notBoolean
    /// The item's data can't be decoded as the requested ``KeychainValue`` type.
    case unexpectedValueData

    case noSecCode
    case noAccessGroups
    case error(_ status: OSStatus)

    public var description: String {
        switch self {
        case .duplicateItem:
            return "Keychain item already exists"
        case .notFound:
            return "Keychain item not found"
        case .notString:
            return "Keychain item is not a string"
        case .notUUID:
            return "Keychain item is not a UUID"
        case .notBoolean:
            return "Keychain item is not a boolean"
        case .unexpectedValueData:
            return "Keychain item data can't be decoded as the requested type"
        case .noSecCode:
            return "No SecCode"
        case .noAccessGroups:
            return "No access groups found"
        case .error(let status):
            if let message = SecCopyErrorMessageString(status, nil) {
                return message as String
            } else {
                return "Unknown error"
            }
        }
    }

    public var errorDescription: String? {
        return description
    }
}
