# LibNotSignal

LibNotSignal is a Swift implementation of the Signal Protocol for secure messaging. It provides end-to-end encryption for messages with forward secrecy and post-compromise security through key ratcheting.

## Features

- End-to-end encryption for messages
- Forward secrecy with the Double Ratchet algorithm
- Post-compromise security through ratcheting
- Secure session establishment using the X3DH protocol
- Support for both synchronous and asynchronous messaging
- Handles missing and out-of-order messages

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