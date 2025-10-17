import Foundation
import Security

#if os(macOS)
    public func getKeychainAccessGroups() -> Result<[String], KeychainError> {
        var secCode: SecCode?
        let status = SecCodeCopySelf([], &secCode)

        guard status == errSecSuccess else {
            return .failure(.error(status))
        }

        guard let code = secCode else {
            return .failure(.noSecCode)
        }

        var secInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code as! SecStaticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &secInfo
        )

        guard infoStatus == errSecSuccess else {
            return .failure(.error(status))
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

    public func withCurrentAccessGroup() -> (_ attributes: KeychainItemAttributes) -> Result<
        KeychainItemAttributes, KeychainError
    > {
        var currentAccessGroup: String?

        func with(_ attributes: KeychainItemAttributes) -> Result<
            KeychainItemAttributes, KeychainError
        > {
            guard let currentAccessGroup else {
                return getKeychainAccessGroups()
                    .flatMap { groups -> Result<String, KeychainError> in
                        guard let accessGroup = groups.first else {
                            return .failure(.noAccessGroups)
                        }

                        return .success(accessGroup)
                    }
                    .map { accessGroup -> KeychainItemAttributes in
                        currentAccessGroup = accessGroup
                        return withAccessGroup(accessGroup)(attributes)
                    }
            }

            return .success(withAccessGroup(currentAccessGroup)(attributes))
        }

        return with
    }
#endif
