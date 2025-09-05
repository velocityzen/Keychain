import Security

public struct KeychainItemAttributeKeys {
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
public struct KeychainClassValues {
    ///The value that indicates a generic password item.
    static let GenericPassword = kSecClassGenericPassword as String
    ///The value that indicates an Internet password item.
    static let InternetPassword = kSecClassInternetPassword as String
    /// The value that indicates a certificate item.
    static let Certificate = kSecClassCertificate as String
    ///The value that indicates a cryptographic key item.
    static let Key = kSecClassKey as String
    ///The value that indicates an identity item.
    static let Identity = kSecClassIdentity as String
}

/// Item search matching keys
public struct KeychainSearchKeys {
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
public struct KeychainMatchLimitValues {
    /// A key whose value indicates the match limit.
    static let One = kSecMatchLimitOne as String
    /// A key whose value indicates the match limit.
    static let All = kSecMatchLimitAll as String
}

/// Values you use to indicate whether to allow UI authentication.
public struct KeychainUIAuthenticationValues {
    ///A value that indicates items requiring user authentication should be skipped.
    static let Skip = kSecUseAuthenticationUISkip as String
}

/// Keys you use to specify the type of results to return from a keychain item search or add operation.
public struct KeychainValueResultReturn {
    /// A key whose value is a Boolean that indicates whether or not to return item data.
    static let Data = kSecReturnData as String
    ///A key whose value is a Boolean indicating whether or not to return item attributes.
    static let Attributes = kSecReturnAttributes as String
    ///A key whose value is a Boolean indicating whether or not to return a reference to an item.
    static let Ref = kSecReturnRef as String
    ///A key whose value is a Boolean indicating whether or not to return a persistent reference to an item.
    static let PersistentRef = kSecReturnPersistentRef as String
}

/// Keys that appear in the result dictionary when you specify more than one search result key.
public struct KeychainValueTypeKeys {
    ///A key whose value is the item’s data.
    static let Data = kSecValueData as String
    /// A key whose value is a reference to the item.
    static let Ref = kSecValueRef as String
    ///A key whose value is a persistent reference to the item.
    static let PersistentRef = kSecValuePersistentRef as String
}

public struct KeychainPasswordAttributeKeys {
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

public struct KeychainCertificateAttributeKeys {
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

public struct KeychainCryptographicKeyAttributeKeys {
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

public struct KeychainCryptographicKeyUsageAttributeKeys {
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
public struct KeychainProtocolValues {
    /// FTP protocol.
    static let FTP = kSecAttrProtocolFTP as String
    /// A client side FTP account.
    static let FTPAccount = kSecAttrProtocolFTPAccount as String
    /// HTTP protocol.
    static let HTTP = kSecAttrProtocolHTTP as String
    /// IRC protocol.
    static let IRC = kSecAttrProtocolIRC as String
    /// NNTP protocol.
    static let NNTP = kSecAttrProtocolNNTP as String
    /// POP3 protocol.
    static let POP3 = kSecAttrProtocolPOP3 as String
    /// SMTP protocol.
    static let SMTP = kSecAttrProtocolSMTP as String
    /// SOCKS protocol.
    static let SOCKS = kSecAttrProtocolSOCKS as String
    /// IMAP protocol.
    static let IMAP = kSecAttrProtocolIMAP as String
    /// LDAP protocol.
    static let LDAP = kSecAttrProtocolLDAP as String
    /// AFP over AppleTalk.
    static let AppleTalk = kSecAttrProtocolAppleTalk as String
    /// AFP over TCP.
    static let AFP = kSecAttrProtocolAFP as String
    /// Telnet protocol.
    static let Telnet = kSecAttrProtocolTelnet as String
    /// SSH protocol.
    static let SSH = kSecAttrProtocolSSH as String
    /// FTP over TLS/SSL.
    static let FTPS = kSecAttrProtocolFTPS as String
    /// HTTP over TLS/SSL.
    static let HTTPS = kSecAttrProtocolHTTPS as String
    /// HTTP proxy.
    static let HTTPProxy = kSecAttrProtocolHTTPProxy as String
    /// HTTPS proxy.
    static let HTTPSProxy = kSecAttrProtocolHTTPSProxy as String
    /// FTP proxy.
    static let FTPProxy = kSecAttrProtocolFTPProxy as String
    /// SMB protocol.
    static let SMB = kSecAttrProtocolSMB as String
    /// RTSP protocol.
    static let RTSP = kSecAttrProtocolRTSP as String
    /// RTSP proxy.
    static let RTSPProxy = kSecAttrProtocolRTSPProxy as String
    /// DAAP protocol.
    static let DAAP = kSecAttrProtocolDAAP as String
    /// Remote Apple Events.
    static let EPPC = kSecAttrProtocolEPPC as String
    /// IPP protocol.
    static let IPP = kSecAttrProtocolIPP as String
    /// NNTP over TLS/SSL.
    static let NNTPS = kSecAttrProtocolNNTPS as String
    /// LDAP over TLS/SSL.
    static let LDAPS = kSecAttrProtocolLDAPS as String
    /// Telnet over TLS/SSL.
    static let TelnetS = kSecAttrProtocolTelnetS as String
    /// IMAP over TLS/SSL.
    static let IMAPS = kSecAttrProtocolIMAPS as String
    /// IRC over TLS/SSL.
    static let IRCS = kSecAttrProtocolIRCS as String
    /// POP3 over TLS/SSL.
    static let POP3S = kSecAttrProtocolPOP3S as String
}

/// Values you use with the kSecAttrAuthenticationType attribute key.
public struct KeychainAuthenticationTypeValues {
    /// Windows NT LAN Manager authentication.
    static let NTLM = kSecAttrAuthenticationTypeNTLM as String
    /// Microsoft Network default authentication.
    static let MSN = kSecAttrAuthenticationTypeMSN as String
    /// Distributed Password authentication.
    static let DPA = kSecAttrAuthenticationTypeDPA as String
    /// Remote Password authentication.
    static let RPA = kSecAttrAuthenticationTypeRPA as String
    /// HTTP Basic authentication.
    static let HTTPBasic = kSecAttrAuthenticationTypeHTTPBasic as String
    /// HTTP Digest Access authentication.
    static let HTTPDigest = kSecAttrAuthenticationTypeHTTPDigest as String
    /// HTML form based authentication.
    static let HTMLForm = kSecAttrAuthenticationTypeHTMLForm as String
    /// The default authentication type.
    static let Default = kSecAttrAuthenticationTypeDefault as String
}

/// Values you use with the kSecAttrKeyClass attribute key.
public struct KeychainKeyClassValues {
    /// A public key of a public-private pair.
    static let Public = kSecAttrKeyClassPublic as String
    /// A private key of a public-private pair.
    static let Private = kSecAttrKeyClassPrivate as String
    /// A private key used for symmetric-key encryption and decryption.
    static let Symmetric = kSecAttrKeyClassSymmetric as String
}

/// Values you use with the kSecAttrKeyType attribute key.
public struct KeychainKeyTypeValues {
    /// RSA algorithm.
    static let RSA = kSecAttrKeyTypeRSA as String
    /// DSA algorithm.
    static let DSA = kSecAttrKeyTypeDSA as String
    /// AES algorithm.
    static let AES = kSecAttrKeyTypeAES as String
    /// DES algorithm.
    static let DES = kSecAttrKeyTypeDES as String
    /// 3DES algorithm.
    static let TripleDES = kSecAttrKeyType3DES as String
    /// RC4 algorithm.
    static let RC4 = kSecAttrKeyTypeRC4 as String
    /// RC2 algorithm.
    static let RC2 = kSecAttrKeyTypeRC2 as String
    /// CAST algorithm.
    static let CAST = kSecAttrKeyTypeCAST as String
    /// Elliptic curve algorithm.
    static let ECSECPrimeRandom = kSecAttrKeyTypeECSECPrimeRandom as String
}

/// Values you use with the kSecAttrSynchronizable attribute key.
public struct KeychainSynchronizabilityValues {
    /// Specifies that both synchronizable and non-synchronizable results should be returned from a query.
    static let SynchronizableAny = kSecAttrSynchronizableAny as String
}

/// Values you use with the kSecAttrTokenID attribute key.
public struct KeychainTokenIdValues {
    /// Specifies an item should be stored in the device’s Secure Enclave.
    static let SecureEnclave = kSecAttrTokenIDSecureEnclave as String
}

/// Values you use with the kSecAttrAccessible attribute key, listed from most to least restrictive.
public struct KeychainAccessibilityValues {
    /// The data in the keychain can only be accessed when the device is unlocked. Only available if a passcode is set on the device.
    static let WhenPasscodeSetThisDeviceOnly =
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    static let WhenUnlockedThisDeviceOnly =
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    static let WhenUnlocked = kSecAttrAccessibleWhenUnlocked as String
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    static let AfterFirstUnlockThisDeviceOnly =
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    static let AfterFirstUnlock = kSecAttrAccessibleAfterFirstUnlock as String
}

///Values you use with the kSecAttrPRF attribute key to indicate the item’s pseudorandom function.
public struct KeychainPseudorandomFunctionValues {
    /// Use the SHA1 algorithm.
    static let SHA1 = kSecAttrPRFHmacAlgSHA1 as String
    /// Use the SHA224 algorithm.
    static let SHA224 = kSecAttrPRFHmacAlgSHA224 as String
    /// Use the SHA256 algorithm.
    static let SHA256 = kSecAttrPRFHmacAlgSHA256 as String
    /// Use the SHA384 algorithm.
    static let SHA384 = kSecAttrPRFHmacAlgSHA384 as String
    /// Use the SHA512 algorithm.
    static let SHA512 = kSecAttrPRFHmacAlgSHA512 as String
}

/// Values you use with the kSecAttrAccessGroup attribute key.
public struct KeychainAccessGroupValues {
    /// The access group containing items provided by external tokens.
    static let Token = kSecAttrAccessGroupToken as String
}
