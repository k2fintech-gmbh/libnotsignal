# Implementation Plan for LibNotSignal Missing Entities

Based on the error messages, we've implemented the following missing entities in the LibNotSignal library:

## 1. Key Types

### Added Types:
- `PrivateKey`: A strongly-typed wrapper for private key data with `ContiguousBytes` conformance
- `PublicKey`: A strongly-typed wrapper for public key data with `ContiguousBytes` conformance
- `ProtocolAddress`: A type that matches the Signal protocol's addressing scheme

### Extended Types:
- `IdentityKey`: Added ability to work with `PublicKey` and added serialization methods
- `IdentityKeyPair`: Added ability to work with `PrivateKey` and added serialization methods
- `PreKeyRecord`: Added serialization/deserialization and compatibility with `PublicKey`/`PrivateKey`
- `SignedPreKeyRecord`: Added serialization/deserialization and compatibility with `PublicKey`/`PrivateKey`

## 2. Protocol Conformance

- Added the `ContiguousBytes` protocol through a typealias to Swift's built-in protocol
- Ensured `Data` conforms to `ContiguousBytes`
- Added extensions to `Data` for cryptographic operations

## 3. Crypto Provider Extensions

- Extended the crypto provider system with `ExtendedCryptoProvider` protocol
- Added implementation in `DefaultCryptoProvider+Extended.swift`
- Added a method to `SignalCrypto` to generate key pairs from existing private keys

## 4. Serialization Support

- Added serialization methods to all key types
- Added deserialization static methods
- Added error handling for invalid serialized data

## Next Steps

1. Import the LibNotSignal module in your application code
2. Use the exported types in your application code:
   - Replace references to `SignalAddress` with `ProtocolAddress`
   - Use the `PrivateKey` and `PublicKey` types for strongly-typed key handling
   - Use the serialization/deserialization methods for storage and transmission
3. Test the implementation with your existing code 