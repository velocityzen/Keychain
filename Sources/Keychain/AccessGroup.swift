import FP
import Foundation
import Security

#if os(macOS)
    public func getKeychainAccessGroups() -> Result<[String], KeychainError> {
        var secCode: SecCode?
        let status = SecCodeCopySelf([], &secCode)

        guard status == errSecSuccess else {
            return .failure(.error(status))
        }

        guard let secCode else {
            return .failure(.noSecCode)
        }

        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(secCode, [], &staticCode)

        guard staticStatus == errSecSuccess else {
            return .failure(.error(staticStatus))
        }

        guard let staticCode else {
            return .failure(.noSecCode)
        }

        var secInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &secInfo
        )

        guard infoStatus == errSecSuccess else {
            return .failure(.error(infoStatus))
        }

        guard
            let info = secInfo as? [String: Any],
            let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
            let groups = entitlements["keychain-access-groups"] as? [String]
        else {
            return .failure(.noAccessGroups)
        }

        return .success(groups)
    }

    /// Adds the first access group from the running app's entitlements.
    public func withCurrentAccessGroup() -> (_ attributes: KeychainItemAttributes) -> Result<
        KeychainItemAttributes, KeychainError
    > {
        return { attributes in
            currentAccessGroup.map { attributes |> withAccessGroup($0) }
        }
    }

    /// Entitlements don't change while the app runs, so they're read once, on first use.
    private let currentAccessGroup: Result<String, KeychainError> =
        getKeychainAccessGroups()
        .flatMap { .fromOptional($0.first, error: .noAccessGroups) }
#endif
