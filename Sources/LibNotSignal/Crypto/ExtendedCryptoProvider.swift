import Foundation

public protocol ExtendedCryptoProvider: CryptoProvider {
    // Additional method to derive a public key from a private key
    func getPublicKeyFrom(privateKey: Data) throws -> Data
} 