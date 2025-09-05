import Foundation

enum KeychainError: Error {
    case notFound
    case unexpectedPasswordData
    case error(_ status: OSStatus)
}
