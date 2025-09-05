import Security

// Item class keys
let kSecClass: CFString  //A dictionary key whose value is the item’s class.

//Item class values Values you use with the kSecClass key.
let kSecClassGenericPassword: CFString  //The value that indicates a generic password item.
let kSecClassInternetPassword: CFString  //The value that indicates an Internet password item.
let kSecClassCertificate: CFString  // The value that indicates a certificate item.
let kSecClassKey: CFString  //The value that indicates a cryptographic key item.
let kSecClassIdentity: CFString  //The value that indicates an identity item.

let kSecValueData  //A key whose value is the item’s data.

//Item result keys
//Keys you use to specify the type of results to return from a keychain item search or add operation.
let kSecReturnData: CFString  // A key whose value is a Boolean that indicates whether or not to return item data.
let kSecReturnAttributes: CFString  //A key whose value is a Boolean indicating whether or not to return item attributes.
let kSecReturnRef: CFString  //A key whose value is a Boolean indicating whether or not to return a reference to an item.
let kSecReturnPersistentRef: CFString  //A key whose value is a Boolean indicating whether or not to return a persistent reference to an item.

// Item value type keys
// Keys that appear in the result dictionary when you specify more than one search result key.
let kSecValueData: CFString  //A key whose value is the item’s data.
let kSecValueRef: CFString  //A key whose value is a reference to the item.
let kSecValuePersistentRef: CFString  //A key whose value is a persistent reference to the item.

// return codes
// https://developer.apple.com/documentation/security/security-framework-result-codes
