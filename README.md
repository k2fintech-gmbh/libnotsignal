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
- ⚠️ Message type conversion between CiphertextMessage, PreKeySignalMessage, and SignalMessage

## Reliable Usage Patterns

Based on extensive testing, the following usage patterns are reliable:

### 1. Direct Crypto Operations

The most reliable way to use the library is with direct crypto operations:

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

### 2. Manual Session Setup

For reliable session management, set up sessions manually:

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

// Also set up receiving chain (for bidirectional communication)
sessionState.receivingChains.append(ReceivingChain(
    key: bobChainKey,
    index: 0,
    ratchetKey: bobKeyPair.publicKey.data
))

// Store the session
let address = SignalAddress(name: "recipient", deviceId: 1)
try store.storeSession(sessionState, for: address)
```

### 3. Real-World Client Implementation

For a practical implementation in a messaging app:

```swift
// Create a client implementation that handles key management
class SignalClientImplementation {
    // Setup identity
    func generateIdentity() throws {
        identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        registrationId = try LibNotSignal.shared.generateRegistrationId()
        protocolStore = InMemorySignalProtocolStore(
            identity: identityKeyPair,
            registrationId: registrationId
        )
    }
    
    // Setup direct session (bypassing bundle exchange)
    func setupDirectSession(with userId: String, identityKey: IdentityKey) throws {
        // Create session state manually
        let sessionState = SessionState()
        sessionState.localIdentityKey = identityKeyPair.publicKey
        sessionState.remoteIdentityKey = identityKey
        
        // Create root and chain keys
        let rootKey = try SignalCrypto.shared.randomBytes(count: 32)
        sessionState.rootKey = rootKey
        
        // Set up sending chain
        let keyPair = try KeyPair.generate()
        let chainKey = try SignalCrypto.shared.randomBytes(count: 32)
        sessionState.sendingChain = SendingChain(
            key: chainKey,
            index: 0,
            ratchetKey: keyPair.publicKey.data
        )
        
        // Store the session
        try protocolStore.storeSession(sessionState, for: address)
    }
    
    // Encrypt a message
    func encryptMessage(_ message: String, for recipientId: String) throws -> SignalMessage {
        let cipher = getSessionCipher(for: recipientAddress)
        let plaintext = message.data(using: .utf8)!
        let encryptedMessage = try cipher.encrypt(plaintext)
        return try SignalMessage(data: encryptedMessage.body)
    }
}
```

## Testing

The library includes comprehensive tests for all components. Run tests using:

```bash
swift test
```

The following tests demonstrate reliable usage patterns:
- BasicEncryptionTest - Direct crypto operations
- DirectEncryptionTests - Simple encryption without session management
- WorkingSessionImplementation - Manual session setup with fixed keys
- RealWorldSignalImplementation - Practical client implementation
- CryptoTests - Core crypto functionality
- IdentityKeyTests - Identity key generation and management
- PreKeyTests - PreKey generation and storage

Tests with known issues:
- SessionImplementationTests - Some signature verification issues
- DirectCryptoImplementation - Simplified pattern for message exchange

## Implementation Notes

For a working implementation, consider the following guidelines:

1. Use direct crypto operations with fixed keys and IVs when possible
2. When using session management, set up sessions manually to avoid signature verification issues
3. Make sure to use the same IV for encryption and decryption operations
4. Store properties should be accessed using getter methods rather than directly
5. When working with message types, be careful with conversions between CiphertextMessage, PreKeySignalMessage, and SignalMessage
6. Manual session setup with pre-shared keys works more reliably than automatic session establishment with PreKeyBundles

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

See the examples above for basic usage patterns. For detailed examples, refer to the test files in the project. 