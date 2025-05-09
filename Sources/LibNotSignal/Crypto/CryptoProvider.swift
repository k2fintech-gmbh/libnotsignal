import Foundation
import Crypto

public protocol CryptoProvider {
    // Random number generation
    func randomBytes(count: Int) throws -> Data
    
    // Hash functions
    func sha256(_ data: Data) -> Data
    func hmacSHA256(key: Data, data: Data) -> Data
    
    // HKDF - Extract and expand to derive keys
    func hkdfDeriveSecrets(inputKeyMaterial: Data, info: Data, outputLength: Int, salt: Data) throws -> Data
    
    // AES-CBC encryption/decryption
    func encrypt(key: Data, iv: Data, data: Data) throws -> Data
    func decrypt(key: Data, iv: Data, data: Data) throws -> Data
    
    // Elliptic curve operations
    func generateKeyPair() throws -> (privateKey: Data, publicKey: Data)
    func calculateAgreement(privateKey: Data, publicKey: Data) throws -> Data
    func sign(privateKey: Data, message: Data) throws -> Data
    func verify(publicKey: Data, message: Data, signature: Data) throws -> Bool
} 