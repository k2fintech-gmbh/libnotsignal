# LibNotSignal Usage Examples

## Setup and Key Generation

```swift
import LibNotSignal

// Generate identity key pair
let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()

// Generate registration ID (a unique identifier for this user's device)
let registrationId = try LibNotSignal.shared.generateRegistrationId()

// Generate pre-keys (one-time use keys for session establishment)
let preKeys = try LibNotSignal.shared.generatePreKeys(start: 1, count: 10)

// Generate a signed pre-key (a medium-term key signed by the identity key)
let signedPreKey = try LibNotSignal.shared.generateSignedPreKey(
    identityKeyPair: identityKeyPair,
    id: 1
)
```

## Creating a Key Store

For LibNotSignal to work, you need to implement the `SignalProtocolStore` protocol, which is a combination of:
- `IdentityKeyStore` - stores identity keys and handles trust decisions
- `PreKeyStore` - stores pre-keys
- `SessionStore` - stores active sessions
- `SignedPreKeyStore` - stores signed pre-keys

Here's a simple example of a persistent key store implementation using UserDefaults (for demo purposes only, in a real app you would use secure storage):

```swift
class SimpleKeyStore: SignalProtocolStore {
    private let defaults = UserDefaults.standard
    private let identityKeyPair: IdentityKeyPair
    private let registrationId: UInt32
    
    init() throws {
        // Load or create identity key pair
        if let identityKeyData = defaults.data(forKey: "identityKeyPair") {
            let decoder = JSONDecoder()
            self.identityKeyPair = try decoder.decode(IdentityKeyPair.self, from: identityKeyData)
        } else {
            self.identityKeyPair = try IdentityKeyPair.generate()
            let encoder = JSONDecoder()
            let data = try encoder.encode(identityKeyPair)
            defaults.set(data, forKey: "identityKeyPair")
        }
        
        // Load or create registration ID
        if let regId = defaults.object(forKey: "registrationId") as? UInt32 {
            self.registrationId = regId
        } else {
            self.registrationId = try SignalCrypto.shared.randomInt(min: 1, max: 16380)
            defaults.set(registrationId, forKey: "registrationId")
        }
    }
    
    // IdentityKeyStore implementation
    func getIdentityKeyPair() throws -> IdentityKeyPair {
        return identityKeyPair
    }
    
    func getLocalRegistrationId() throws -> UInt32 {
        return registrationId
    }
    
    func saveIdentity(_ identity: IdentityKey, for address: SignalAddress) throws -> Bool {
        let key = "identity_\(address.description)"
        let existingIdentityData = defaults.data(forKey: key)
        
        let encoder = JSONEncoder()
        let identityData = try encoder.encode(identity)
        
        defaults.set(identityData, forKey: key)
        
        return existingIdentityData != nil && existingIdentityData != identityData
    }
    
    func isTrustedIdentity(_ identity: IdentityKey, for address: SignalAddress, direction: Direction) throws -> Bool {
        let key = "identity_\(address.description)"
        
        // If we have no record, trust on first use
        if defaults.data(forKey: key) == nil {
            return true
        }
        
        // Compare with stored identity
        if let storedData = defaults.data(forKey: key) {
            let decoder = JSONDecoder()
            let storedIdentity = try decoder.decode(IdentityKey.self, from: storedData)
            return storedIdentity == identity
        }
        
        return false
    }
    
    func getIdentity(for address: SignalAddress) throws -> IdentityKey? {
        let key = "identity_\(address.description)"
        
        if let data = defaults.data(forKey: key) {
            let decoder = JSONDecoder()
            return try decoder.decode(IdentityKey.self, from: data)
        }
        
        return nil
    }
    
    // PreKeyStore implementation
    func loadPreKey(id: UInt32) throws -> PreKeyRecord? {
        let key = "prekey_\(id)"
        
        if let data = defaults.data(forKey: key) {
            let decoder = JSONDecoder()
            return try decoder.decode(PreKeyRecord.self, from: data)
        }
        
        return nil
    }
    
    func storePreKey(_ record: PreKeyRecord, id: UInt32) throws {
        let key = "prekey_\(id)"
        let encoder = JSONEncoder()
        let data = try encoder.encode(record)
        defaults.set(data, forKey: key)
    }
    
    func containsPreKey(id: UInt32) throws -> Bool {
        return defaults.data(forKey: "prekey_\(id)") != nil
    }
    
    func removePreKey(id: UInt32) throws {
        defaults.removeObject(forKey: "prekey_\(id)")
    }
    
    func getAllPreKeys() throws -> [PreKeyRecord] {
        var preKeys: [PreKeyRecord] = []
        
        for key in defaults.dictionaryRepresentation().keys {
            if key.starts(with: "prekey_"), let data = defaults.data(forKey: key) {
                let decoder = JSONDecoder()
                if let preKey = try? decoder.decode(PreKeyRecord.self, from: data) {
                    preKeys.append(preKey)
                }
            }
        }
        
        return preKeys
    }
    
    // SignedPreKeyStore implementation
    func loadSignedPreKey(id: UInt32) throws -> SignedPreKeyRecord? {
        let key = "signedprekey_\(id)"
        
        if let data = defaults.data(forKey: key) {
            let decoder = JSONDecoder()
            return try decoder.decode(SignedPreKeyRecord.self, from: data)
        }
        
        return nil
    }
    
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32) throws {
        let key = "signedprekey_\(id)"
        let encoder = JSONEncoder()
        let data = try encoder.encode(record)
        defaults.set(data, forKey: key)
    }
    
    func containsSignedPreKey(id: UInt32) throws -> Bool {
        return defaults.data(forKey: "signedprekey_\(id)") != nil
    }
    
    func removeSignedPreKey(id: UInt32) throws {
        defaults.removeObject(forKey: "signedprekey_\(id)")
    }
    
    func getAllSignedPreKeys() throws -> [SignedPreKeyRecord] {
        var signedPreKeys: [SignedPreKeyRecord] = []
        
        for key in defaults.dictionaryRepresentation().keys {
            if key.starts(with: "signedprekey_"), let data = defaults.data(forKey: key) {
                let decoder = JSONDecoder()
                if let signedPreKey = try? decoder.decode(SignedPreKeyRecord.self, from: data) {
                    signedPreKeys.append(signedPreKey)
                }
            }
        }
        
        return signedPreKeys
    }
    
    // SessionStore implementation
    func loadSession(for address: SignalAddress) throws -> SessionState? {
        let key = "session_\(address.description)"
        
        if let data = defaults.data(forKey: key) {
            let decoder = JSONDecoder()
            return try decoder.decode(SessionState.self, from: data)
        }
        
        return nil
    }
    
    func storeSession(_ session: SessionState, for address: SignalAddress) throws {
        let key = "session_\(address.description)"
        let encoder = JSONEncoder()
        let data = try encoder.encode(session)
        defaults.set(data, forKey: key)
    }
    
    func containsSession(for address: SignalAddress) throws -> Bool {
        return defaults.data(forKey: "session_\(address.description)") != nil
    }
    
    func deleteSession(for address: SignalAddress) throws {
        defaults.removeObject(forKey: "session_\(address.description)")
    }
    
    func deleteAllSessions(for name: String) throws {
        for key in defaults.dictionaryRepresentation().keys {
            if key.starts(with: "session_\(name)") {
                defaults.removeObject(forKey: key)
            }
        }
    }
    
    func getAllAddresses() throws -> [SignalAddress] {
        var addresses: [SignalAddress] = []
        
        for key in defaults.dictionaryRepresentation().keys {
            if key.starts(with: "session_") {
                let addressStr = key.replacingOccurrences(of: "session_", with: "")
                let components = addressStr.split(separator: ":")
                
                if components.count == 2, let deviceId = UInt32(components[1]) {
                    let address = SignalAddress(name: String(components[0]), deviceId: deviceId)
                    addresses.append(address)
                }
            }
        }
        
        return addresses
    }
}
```

## Session Establishment

### Alice's Side

```swift
// Initialize Alice's store
let aliceStore = SimpleKeyStore()

// Get a pre-key bundle from Bob (usually from a server)
let bobPreKeyBundle: PreKeyBundle = fetchBobsPreKeyBundleFromServer()

// Create a session with Bob
let bobAddress = SignalAddress(name: "bob", deviceId: 1)
let sessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
try sessionBuilder.process(preKeyBundle: bobPreKeyBundle)

// Now Alice can send encrypted messages to Bob
let sessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
let message = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try sessionCipher.encrypt(message)

// Send encryptedMessage.body to Bob
sendToServer(message: encryptedMessage.body, recipient: bobAddress)
```

### Bob's Side

```swift
// Initialize Bob's store
let bobStore = SimpleKeyStore()

// Receive a message from Alice (from a server)
let aliceAddress = SignalAddress(name: "alice", deviceId: 1)
let encryptedMessage: Data = receiveFromServer(sender: aliceAddress)

// Process the message
let sessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

// If this is the first message in the conversation, it will be a pre-key message
let decryptedMessage = try sessionCipher.decrypt(preKeyMessage: parsePreKeyMessage(encryptedMessage))

// For subsequent messages
// let decryptedMessage = try sessionCipher.decrypt(message: parseSignalMessage(encryptedMessage))

print("Received: \(String(data: decryptedMessage, encoding: .utf8)!)")
```

## Verifying Identities

```swift
// Get your identity key and the other user's identity key
let myIdentityKey = aliceStore.getIdentityKeyPair().publicKey
let theirIdentityKey = bobPreKeyBundle.identityKey

// Generate a fingerprint
let fingerprint = LibNotSignal.shared.generateFingerprint(
    localIdentity: myIdentityKey,
    remoteIdentity: theirIdentityKey,
    localAddress: aliceAddress,
    remoteAddress: bobAddress
)

// Display the fingerprint to both users to verify out-of-band
print("Verify this code with Bob: \(fingerprint)")
```

## Group Messaging

LibNotSignal doesn't include group messaging functionality yet, but you can build a simple group messaging system by:
1. Managing group membership on your server
2. Sending individual messages to each group member
3. Including group metadata in message payloads

In a full implementation, you would use SenderKey distribution to optimize group messaging. 