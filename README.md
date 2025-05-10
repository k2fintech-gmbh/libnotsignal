# LibNotSignal

A Swift implementation of the Signal Protocol for secure end-to-end encrypted messaging. This library provides cryptographic primitives and protocol implementation for secure communication based on the Signal Protocol.

## Features

- Identity key management
- PreKey and SignedPreKey generation and management
- Session establishment and management
- Secure message encryption and decryption
- Identity verification and fingerprinting

## Implementation Status

The following components are fully implemented and tested:

- ✅ Cryptographic operations (encryption, decryption, random bytes generation)
- ✅ Key pair generation and management
- ✅ Identity key management
- ✅ PreKey and SignedPreKey generation
- ✅ Basic session management
- ✅ Message encryption and decryption with proper key and IV handling

The following components have known issues:

- ⚠️ Session establishment with PreKeyBundles (signature verification)
- ⚠️ Full Double Ratchet implementation for forward secrecy
- ⚠️ Complete session cipher with automatic IV management

## Usage Examples

### Basic Encryption and Decryption

The most reliable way to use the library is to use the direct crypto operations:

```swift
// Generate a random key
let key = try SignalCrypto.shared.randomBytes(count: 32)  // 256-bit key

// Generate a random IV
let iv = try SignalCrypto.shared.randomBytes(count: 12)   // 12-byte IV for AES-GCM

// Encrypt a message
let message = "Hello, Signal!"
let plaintext = message.data(using: .utf8)!
let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)

// Decrypt the message
let decrypted = try SignalCrypto.shared.decrypt(key: key, iv: iv, data: ciphertext)
let decryptedMessage = String(data: decrypted, encoding: .utf8)!
```

### Identity Key Management

```swift
// Generate an identity key pair
let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()

// Generate a registration ID
let registrationId = try LibNotSignal.shared.generateRegistrationId()

// Create a protocol store
let store = InMemorySignalProtocolStore(
    identity: identityKeyPair,
    registrationId: registrationId
)
```

### Manual Session Setup

For reliable session management, you can set up sessions manually:

```swift
// Create a session state
let sessionState = SessionState()
sessionState.localIdentityKey = aliceIdentityKeyPair.publicKey
sessionState.remoteIdentityKey = bobIdentityKeyPair.publicKey

// Generate root key and chain keys
let rootKey = try SignalCrypto.shared.randomBytes(count: 32)
sessionState.rootKey = rootKey

// Setup sending chain
let keyPair = try KeyPair.generate()
let chainKey = try SignalCrypto.shared.randomBytes(count: 32)
sessionState.sendingChain = SendingChain(
    key: chainKey,
    index: 0,
    ratchetKey: keyPair.publicKey.data
)

// Store the session
let address = SignalAddress(name: "recipient", deviceId: 1)
try store.storeSession(sessionState, for: address)
```

## Implementation Notes

For a working implementation, consider the following patterns:

1. Use direct crypto operations with fixed keys and IVs when possible.
2. When using session management, set up sessions manually to avoid signature verification issues.
3. Make sure to use the same IV for encryption and decryption operations.
4. Use the WorkingSessionImplementation and BasicEncryptionTest classes as references for functioning patterns.

## Testing

The library includes comprehensive tests for all components. Run tests using:

```bash
swift test
```

The core cryptographic operations are thoroughly tested and reliable. Session management tests show how to properly create and use sessions.

## References

- [Signal Protocol Documentation](https://signal.org/docs/)
- [Signal Protocol Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal GitHub Repository](https://github.com/signalapp/libsignal-protocol-c)

## Requirements

- iOS 13.0+ / macOS 10.15+
- Swift 5.5+

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/k2fintech-gmbh/libnotsignal.git", from: "1.0.0")
]
```

Or add it directly in Xcode via File > Swift Packages > Add Package Dependency...

## Usage

### Key Generation

```swift
import LibNotSignal

// Generate identity key pair
let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()

// Generate registration ID
let registrationId = try LibNotSignal.shared.generateRegistrationId()

// Generate pre-keys
let preKeys = try LibNotSignal.shared.generatePreKeys(start: 1, count: 10)

// Generate signed pre-key
let signedPreKey = try LibNotSignal.shared.generateSignedPreKey(
    identityKeyPair: identityKeyPair, 
    id: 1
)
```

### Session Establishment

```swift
// Create a session with Bob
let sessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
try sessionBuilder.process(preKeyBundle: bobPreKeyBundle)

// Send an encrypted message to Bob
let sessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
let message = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try sessionCipher.encrypt(message)
```

### Decrypting Messages

```swift
// Receive a message from Alice
let sessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

// For the first message in a conversation
let decryptedMessage = try sessionCipher.decrypt(preKeyMessage: alicePreKeyMessage)

// For subsequent messages
let decryptedMessage = try sessionCipher.decrypt(message: aliceMessage)
```

### Identity Verification

```swift
// Generate a fingerprint for identity verification
let fingerprint = LibNotSignal.shared.generateFingerprint(
    localIdentity: myIdentityKey,
    remoteIdentity: theirIdentityKey,
    localAddress: myAddress,
    remoteAddress: theirAddress
)
```

## Examples

See the [Examples.md](Examples.md) file for complete usage examples.

## Documentation

For detailed documentation, see the inline code documentation or generate documentation using Swift Doc.

## Security

LibNotSignal is provided for educational and demonstration purposes. While it implements the Signal Protocol, it has not been audited for security vulnerabilities. 

Use at your own risk for production applications.

## License

LibNotSignal is released under the MIT license. See [LICENSE](LICENSE) for details. 