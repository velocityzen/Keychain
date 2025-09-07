import Security

public struct KeychainItemAttributeKeys: Sendable {
    /// An item class key used to construct a Keychain search dictionary.
    static let Class = kSecClass as String
    /// A key with a value that indicates access control list settings for the item.
    static let Access = kSecAttrAccess as String
    /// A key with a value that’s an access control instance indicating access control settings for the item.
    static let AccessControl = kSecAttrAccessControl as String
    /// A key with a value that indicates when the keychain item is accessible.
    static let Accessible = kSecAttrAccessible as String
    /// A key with a value that’s a string indicating the access group the item is in.
    static let AccessGroup = kSecAttrAccessGroup as String
    /// A key with a value that’s a string indicating whether the item synchronizes through iCloud.
    static let Synchronizable = kSecAttrSynchronizable as String
    /// A key with a value that indicates the item’s creation date.
    static let CreationDate = kSecAttrCreationDate as String
    /// A key with a value that indicates the item’s most recent modification date.
    static let ModificationDate = kSecAttrModificationDate as String
    /// A key with a value that’s a string indicating the item’s description.
    static let Description = kSecAttrDescription as String
    /// A key with a value that’s a string indicating a comment associated with the item.
    static let Comment = kSecAttrComment as String
    /// A key with a value that indicates the item’s creator.
    static let Creator = kSecAttrCreator as String
    /// A key with a value that indicates the item’s type.
    static let ItemType = kSecAttrType as String
    /// A key with a value that’s a string indicating the item’s label.
    static let Label = kSecAttrLabel as String
    /// A key with a value that’s a Boolean indicating the item’s visibility.
    static let IsInvisible = kSecAttrIsInvisible as String
    /// A key with a value that’s a Boolean indicating whether the item has a valid password.
    static let IsNegative = kSecAttrIsNegative as String
    /// A key with a value that’s a string that provides a sync view hint.
    static let SyncViewHint = kSecAttrSyncViewHint as String
    /// no
    static let PersistantReference = kSecAttrPersistantReference as String
    /// no
    static let PersistentReference = kSecAttrPersistentReference as String
    // /// A key with a value that indicates whether to store the data in a keychain available to anyone who uses the device.
    // @available(tvOS 16.0, *)
    // static let UseUserIndependentKeychain = kSecUseUserIndependentKeychain as String
}

/// values you use with the kSecClass key.
public enum KeychainClassValues: String, Sendable {
    ///The value that indicates a generic password item.
    case genericPassword
    ///The value that indicates an Internet password item.
    case internetPassword
    /// The value that indicates a certificate item.
    case certificate
    ///The value that indicates a cryptographic key item.
    case key
    ///The value that indicates an identity item.
    case identity

    public var rawValue: String {
        switch self {
        case .genericPassword:
            return kSecClassGenericPassword as String
        case .internetPassword:
            return kSecClassInternetPassword as String
        case .certificate:
            return kSecClassCertificate as String
        case .key:
            return kSecClassKey as String
        case .identity:
            return kSecClassIdentity as String
        }
    }
}

/// Item search matching keys
public struct KeychainSearchKeys: Sendable {
    /// A key whose value indicates a policy with which a matching certificate or identity must verify.
    static let MatchPolicy = kSecMatchPolicy as String
    /// A key whose value indicates a list of items to search.
    static let MatchItemList = kSecMatchItemList as String
    /// A key whose value indicates a list of items to search.
    static let MatchSearchList = kSecMatchSearchList as String
    /// A key whose value is a string to match against a certificate or identity’s issuers.
    static let MatchIssuers = kSecMatchIssuers as String
    /// A key whose value is a string to match against a certificate or identity’s email address.
    static let MatchEmailAddressIfPresent = kSecMatchEmailAddressIfPresent as String
    /// A key whose value is a string to look for in a certificate or identity’s subject.
    static let MatchSubjectContains = kSecMatchSubjectContains as String
    /// A key whose value is a string to match against the beginning of a certificate or identity’s subject.
    static let MatchSubjectStartsWith = kSecMatchSubjectStartsWith as String
    /// A key whose value is a string to match against the end of a certificate or identity’s subject.
    static let MatchSubjectEndsWith = kSecMatchSubjectEndsWith as String
    /// A key whose value is a string to exactly match a certificate or identity’s subject.
    static let MatchSubjectWholeString = kSecMatchSubjectWholeString as String
    /// A key whose value is a Boolean indicating whether case-insensitive matching is performed.
    static let MatchCaseInsensitive = kSecMatchCaseInsensitive as String
    /// A key whose value is a Boolean indicating whether diacritic-insensitive matching is performed.
    static let MatchDiacriticInsensitive = kSecMatchDiacriticInsensitive as String
    /// A key whose value is a Boolean indicating whether width-insensitive matching is performed.
    static let MatchWidthInsensitive = kSecMatchWidthInsensitive as String
    /// A key whose value is a Boolean indicating whether untrusted certificates should be returned.
    static let MatchTrustedOnly = kSecMatchTrustedOnly as String
    /// A key whose value indicates the validity date.
    static let MatchValidOnDate = kSecMatchValidOnDate as String
    /// A key whose value indicates the match limit.
    static let MatchLimit = kSecMatchLimit as String

    /// A key whose value is a keychain to operate on.
    static let UseKeychain = kSecUseKeychain as String
    /// A key whose value indicates whether the user is prompted for authentication.
    static let UseAuthenticationUI = kSecUseAuthenticationUI as String
    /// A key whose value indicates a local authentication context to use.
    static let UseAuthenticationContext = kSecUseAuthenticationContext as String
    /// A key whose value indicates whether to treat macOS keychain items like iOS keychain items.
    @available(macOS 10.15, *)
    static let UseDataProtectionKeychain = kSecUseDataProtectionKeychain as String
}

/// Keys used to limit the number of results returned.
public enum KeychainMatchLimitValues: String, Sendable {
    /// A key whose value indicates the match limit.
    case one
    /// A key whose value indicates the match limit.
    case all

    public var rawValue: String {
        switch self {
        case .one:
            return kSecMatchLimitOne as String
        case .all:
            return kSecMatchLimitAll as String
        }
    }
}

/// Values you use to indicate whether to allow UI authentication.
public enum KeychainUIAuthenticationValues: String, Sendable {
    /// A key whose value is a Boolean indicating whether to allow UI authentication.
    case skip

    public var rawValue: String {
        switch self {
        case .skip:
            return kSecUseAuthenticationUISkip as String
        }
    }
}

/// Keys you use to specify the type of results to return from a keychain item search or add operation.
public enum KeychainValueResultReturn: String, Sendable {
    /// A key whose value is a Boolean indicating whether to return item data.
    case data
    /// A key whose value is a Boolean indicating whether to return item attributes.
    case attributes
    /// A key whose value is a Boolean indicating whether to return an item reference.
    case ref
    /// A key whose value is a Boolean indicating whether to return a persistent item reference.
    case persistentRef

    public var rawValue: String {
        switch self {
        case .data:
            return kSecReturnData as String
        case .attributes:
            return kSecReturnAttributes as String
        case .ref:
            return kSecReturnRef as String
        case .persistentRef:
            return kSecReturnPersistentRef as String
        }
    }
}

/// Keys that appear in the result dictionary when you specify more than one search result key.
public struct KeychainValueTypeKeys: Sendable {
    ///A key whose value is the item’s data.
    static let Data = kSecValueData as String
    /// A key whose value is a reference to the item.
    static let Ref = kSecValueRef as String
    ///A key whose value is a persistent reference to the item.
    static let PersistentRef = kSecValuePersistentRef as String
}

public struct KeychainPasswordAttributeKeys: Sendable {
    /// A key whose value is a string indicating the item’s account name.
    static let Account = kSecAttrAccount as String
    /// A key whose value is a string indicating the item’s service.
    static let Service = kSecAttrService as String
    /// A key whose value indicates the item’s user-defined attributes.
    static let Generic = kSecAttrGeneric as String
    /// A key whose value is a string indicating the item’s security domain.
    static let SecurityDomain = kSecAttrSecurityDomain as String
    /// A key whose value is a string indicating the item’s server.
    static let Server = kSecAttrServer as String
    /// A key whose value indicates the item’s protocol.
    static let ItemProtocol = kSecAttrProtocol as String
    /// A key whose value indicates the item’s authentication scheme.
    static let AuthenticationType = kSecAttrAuthenticationType as String
    /// A key whose value indicates the item’s port.
    static let Port = kSecAttrPort as String
    /// A key whose value is a string indicating the item’s path attribute.
    static let Path = kSecAttrPath as String
}

public struct KeychainCertificateAttributeKeys: Sendable {
    /// A key whose value indicates the item’s subject name.
    static let Subject = kSecAttrSubject as String
    /// A key whose value indicates the item’s issuer.
    static let Issuer = kSecAttrIssuer as String
    /// A key whose value indicates the item’s serial number.
    static let SerialNumber = kSecAttrSerialNumber as String
    /// A key whose value indicates the item’s subject key ID.
    static let SubjectKeyID = kSecAttrSubjectKeyID as String
    /// A key whose value indicates the item’s public key hash.
    static let PublicKeyHash = kSecAttrPublicKeyHash as String
    /// A key whose value indicates the item’s certificate type.
    static let CertificateType = kSecAttrCertificateType as String
    /// A key whose value indicates the item’s certificate encoding.
    static let CertificateEncoding = kSecAttrCertificateEncoding as String
}

public struct KeychainCryptographicKeyAttributeKeys: Sendable {
    /// A key whose value indicates the item’s cryptographic key class.
    static let KeyClass = kSecAttrKeyClass as String
    /// A key whose value indicates the item’s application label.
    static let ApplicationLabel = kSecAttrApplicationLabel as String
    /// A key whose value indicates the item’s private tag.
    static let ApplicationTag = kSecAttrApplicationTag as String
    /// A key whose value indicates the item’s algorithm.
    static let KeyType = kSecAttrKeyType as String
    /// A key whose value indicates the item’s pseudorandom function.
    static let PRF = kSecAttrPRF as String
    /// A key whose value indicates the salt to use for this item.
    static let Salt = kSecAttrSalt as String
    /// A key whose value indicates the number of rounds to run the pseudorandom function.
    static let Rounds = kSecAttrRounds as String
    /// A key whose value indicates the number of bits in a cryptographic key.
    static let KeySizeInBits = kSecAttrKeySizeInBits as String
    /// A key whose value indicates the effective number of bits in a cryptographic key.
    static let EffectiveKeySize = kSecAttrEffectiveKeySize as String
    /// A key whose value indicates that a cryptographic key is in an external store.
    static let TokenID = kSecAttrTokenID as String
}

public struct KeychainCryptographicKeyUsageAttributeKeys: Sendable {
    /// A key whose value indicates the item’s permanence.
    static let IsPermanent = kSecAttrIsPermanent as String
    /// A key whose value indicates the item’s sensitivity.
    static let IsSensitive = kSecAttrIsSensitive as String
    /// A key whose value indicates the item’s extractability.
    static let IsExtractable = kSecAttrIsExtractable as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for encryption.
    static let CanEncrypt = kSecAttrCanEncrypt as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for decryption.
    static let CanDecrypt = kSecAttrCanDecrypt as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for derivation.
    static let CanDerive = kSecAttrCanDerive as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for digital signing.
    static let CanSign = kSecAttrCanSign as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for signature verification.
    static let CanVerify = kSecAttrCanVerify as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for wrapping.
    static let CanWrap = kSecAttrCanWrap as String
    /// A key whose value is a Boolean that indicates whether the cryptographic key can be used for unwrapping.
    static let CanUnwrap = kSecAttrCanUnwrap as String
}

/// Values you use with the kSecAttrProtocol attribute key.
public enum KeychainProtocolValues: String, Sendable {
    /// FTP protocol.
    case ftp
    /// A client side FTP account.
    case ftpAccount
    /// HTTP protocol.
    case http
    /// IRC protocol.
    case irc
    /// NNTP protocol.
    case nntp
    /// POP3 protocol.
    case pop3
    /// SMTP protocol.
    case smtp
    /// SOCKS protocol.
    case socks
    /// IMAP protocol.
    case imap
    /// LDAP protocol.
    case ldap
    /// AFP over AppleTalk.
    case appleTalk
    /// AFP over TCP.
    case afp
    /// Telnet protocol.
    case telnet
    /// SSH protocol.
    case ssh
    /// FTP over TLS/SSL.
    case ftps
    /// HTTP over TLS/SSL.
    case https
    /// HTTP proxy.
    case httpProxy
    /// HTTPS proxy.
    case httpsProxy
    /// FTP proxy.
    case ftpProxy
    /// SMB protocol.
    case smb
    /// RTSP protocol.
    case rtsp
    /// RTSP proxy.
    case rtspProxy
    /// DAAP protocol.
    case daap
    /// Remote Apple Events.
    case eppc
    /// IPP protocol.
    case ipp
    /// NNTP over TLS/SSL.
    case nntps
    /// LDAP over TLS/SSL.
    case ldaps
    /// Telnet over TLS/SSL.
    case telnetS
    /// IMAP over TLS/SSL.
    case imaps
    /// IRC over TLS/SSL.
    case ircs
    /// POP3 over TLS/SSL.
    case pop3s

    public var rawValue: String {
        switch self {
        case .ftp:
            return kSecAttrProtocolFTP as String
        case .ftpAccount:
            return kSecAttrProtocolFTPAccount as String
        case .http:
            return kSecAttrProtocolHTTP as String
        case .irc:
            return kSecAttrProtocolIRC as String
        case .nntp:
            return kSecAttrProtocolNNTP as String
        case .pop3:
            return kSecAttrProtocolPOP3 as String
        case .smtp:
            return kSecAttrProtocolSMTP as String
        case .socks:
            return kSecAttrProtocolSOCKS as String
        case .imap:
            return kSecAttrProtocolIMAP as String
        case .ldap:
            return kSecAttrProtocolLDAP as String
        case .appleTalk:
            return kSecAttrProtocolAppleTalk as String
        case .afp:
            return kSecAttrProtocolAFP as String
        case .telnet:
            return kSecAttrProtocolTelnet as String
        case .ssh:
            return kSecAttrProtocolSSH as String
        case .ftps:
            return kSecAttrProtocolFTPS as String
        case .https:
            return kSecAttrProtocolHTTPS as String
        case .httpProxy:
            return kSecAttrProtocolHTTPProxy as String
        case .httpsProxy:
            return kSecAttrProtocolHTTPSProxy as String
        case .ftpProxy:
            return kSecAttrProtocolFTPProxy as String
        case .smb:
            return kSecAttrProtocolSMB as String
        case .rtsp:
            return kSecAttrProtocolRTSP as String
        case .rtspProxy:
            return kSecAttrProtocolRTSPProxy as String
        case .daap:
            return kSecAttrProtocolDAAP as String
        case .eppc:
            return kSecAttrProtocolEPPC as String
        case .ipp:
            return kSecAttrProtocolIPP as String
        case .nntps:
            return kSecAttrProtocolNNTPS as String
        case .ldaps:
            return kSecAttrProtocolLDAPS as String
        case .telnetS:
            return kSecAttrProtocolTelnetS as String
        case .imaps:
            return kSecAttrProtocolIMAPS as String
        case .ircs:
            return kSecAttrProtocolIRCS as String
        case .pop3s:
            return kSecAttrProtocolPOP3S as String
        }
    }
}

/// Values you use with the kSecAttrAuthenticationType attribute key.
public enum KeychainAuthenticationTypeValues: String, Sendable {
    /// Windows NT LAN Manager authentication.
    case ntlm
    /// Microsoft Network default authentication.
    case msn
    /// Distributed Password Authentication.
    case dpa
    /// Remote Password Authentication.
    case rpa
    /// HTTP Basic authentication.
    case httpBasic
    /// HTTP Digest Access authentication.
    case httpDigest
    /// HTML form based authentication.
    case htmlForm
    /// The default authentication type.
    case `default`

    public var rawValue: String {
        switch self {
        case .ntlm:
            return kSecAttrAuthenticationTypeNTLM as String
        case .msn:
            return kSecAttrAuthenticationTypeMSN as String
        case .dpa:
            return kSecAttrAuthenticationTypeDPA as String
        case .rpa:
            return kSecAttrAuthenticationTypeRPA as String
        case .httpBasic:
            return kSecAttrAuthenticationTypeHTTPBasic as String
        case .httpDigest:
            return kSecAttrAuthenticationTypeHTTPDigest as String
        case .htmlForm:
            return kSecAttrAuthenticationTypeHTMLForm as String
        case .default:
            return kSecAttrAuthenticationTypeDefault as String
        }
    }
}

/// Values you use with the kSecAttrKeyClass attribute key.
public enum KeychainKeyClassValues: String, Sendable {
    /// A public key of a public-private pair.
    case `public`
    /// A private key of a public-private pair.
    case `private`
    /// A symmetric key.
    case symmetric

    public var rawValue: String {
        switch self {
        case .public:
            return kSecAttrKeyClassPublic as String
        case .private:
            return kSecAttrKeyClassPrivate as String
        case .symmetric:
            return kSecAttrKeyClassSymmetric as String
        }
    }
}

/// Values you use with the kSecAttrKeyType attribute key.
public enum KeychainKeyTypeValues: String, Sendable {
    /// RSA algorithm.
    case rsa
    /// DSA algorithm.
    case dsa
    /// AES algorithm.
    case aes
    /// DES algorithm.
    case des
    /// Triple DES algorithm.
    case tripleDes
    /// RC4 algorithm.
    case rc4
    /// RC2 algorithm.
    case rc2
    /// CAST algorithm.
    case cast
    /// Elliptic curve algorithm.
    case ecsecPrimeRandom

    public var rawValue: String {
        switch self {
        case .rsa:
            return kSecAttrKeyTypeRSA as String
        case .dsa:
            return kSecAttrKeyTypeDSA as String
        case .aes:
            return kSecAttrKeyTypeAES as String
        case .des:
            return kSecAttrKeyTypeDES as String
        case .tripleDes:
            return kSecAttrKeyType3DES as String
        case .rc4:
            return kSecAttrKeyTypeRC4 as String
        case .rc2:
            return kSecAttrKeyTypeRC2 as String
        case .cast:
            return kSecAttrKeyTypeCAST as String
        case .ecsecPrimeRandom:
            return kSecAttrKeyTypeECSECPrimeRandom as String
        }
    }
}

/// Values you use with the kSecAttrSynchronizable attribute key.
public enum KeychainSynchronizabilityValues: String, Sendable {
    /// A key whose value indicates whether the item synchronizes through iCloud.
    case synchronizableAny

    public var rawValue: String {
        switch self {
        case .synchronizableAny:
            return kSecAttrSynchronizableAny as String
        }
    }
}

/// Values you use with the kSecAttrTokenID attribute key.
public enum KeychainTokenIdValues: String, Sendable {
    /// A key whose value indicates whether the item synchronizes through iCloud.
    case secureEnclave

    public var rawValue: String {
        switch self {
        case .secureEnclave:
            return kSecAttrTokenIDSecureEnclave as String
        }
    }
}

/// Values you use with the kSecAttrAccessible attribute key, listed from most to least restrictive.
public enum KeychainAccessibilityValues: String, Sendable {
    /// The data in the keychain can only be accessed when the device is unlocked. Only available if a passcode is set on the device.
    case whenPasscodeSetThisDeviceOnly
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    case whenUnlockedThisDeviceOnly
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    case whenUnlocked
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    case afterFirstUnlockThisDeviceOnly
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    case afterFirstUnlock

    public var rawValue: String {
        switch self {
        case .whenPasscodeSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked as String
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock as String
        }
    }
}

///Values you use with the kSecAttrPRF attribute key to indicate the item's pseudorandom function.
public enum KeychainPseudorandomFunctionValues: String, Sendable {
    /// Use the SHA1 algorithm.
    case sha1
    /// Use the SHA224 algorithm.
    case sha224
    /// Use the SHA256 algorithm.
    case sha256
    /// Use the SHA384 algorithm.
    case sha384
    /// Use the SHA512 algorithm.
    case sha512

    public var rawValue: String {
        switch self {
        case .sha1:
            return kSecAttrPRFHmacAlgSHA1 as String
        case .sha224:
            return kSecAttrPRFHmacAlgSHA224 as String
        case .sha256:
            return kSecAttrPRFHmacAlgSHA256 as String
        case .sha384:
            return kSecAttrPRFHmacAlgSHA384 as String
        case .sha512:
            return kSecAttrPRFHmacAlgSHA512 as String
        }
    }
}

/// Values you use with the kSecAttrAccessGroup attribute key.
public enum KeychainAccessGroupValues: String, Sendable {
    /// no description
    case token

    public var rawValue: String {
        switch self {
        case .token:
            return kSecAttrAccessGroupToken as String
        }
    }
}
