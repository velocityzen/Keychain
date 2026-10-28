/// An enum whose cases stand for Security framework constants.
///
/// `rawValue` is the constant, and `init(rawValue:)` maps a constant read back
/// from the keychain to its case.
public protocol KeychainConstant: RawRepresentable, CaseIterable, Sendable
where RawValue == String {}

extension KeychainConstant {
    public init?(rawValue: String) {
        guard let match = Self.allCases.first(where: { $0.rawValue == rawValue }) else {
            return nil
        }

        self = match
    }
}
