import Foundation

extension Data: KeychainValue {
    public var keychainData: Data {
        return self
    }

    public static func fromKeychainData(_ data: Data) -> Result<Data, KeychainError> {
        return .success(data)
    }
}
