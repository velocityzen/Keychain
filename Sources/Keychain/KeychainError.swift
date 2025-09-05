import Foundation

public enum KeychainError: Error, Equatable, CustomStringConvertible {
    case notFound
    case notString
    case notBoolean
    case unexpectedPasswordData

    case noSecCode
    case noAccessGroups
    case error(_ status: OSStatus)

    public var description: String {
        switch self {
        case .notFound:
            return "Keychain item not found"
        case .notString:
            return "Keychain item is not a string"
        case .notBoolean:
            return "Keychain item is not a boolean"
        case .unexpectedPasswordData:
            return "Unexpected password data"
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
}
