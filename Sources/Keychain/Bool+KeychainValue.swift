import Foundation

/// Stored as a single byte: 1 for true, 0 for false.
extension Bool: KeychainValue {
    public var keychainData: Data {
        return Data([self ? 1 : 0])
    }

    public static func fromKeychainData(_ data: Data) -> Result<Bool, KeychainError> {
        switch data {
        case Data([0]):
            return .success(false)
        case Data([1]):
            return .success(true)
        default:
            return .failure(.notBoolean)
        }
    }
}
