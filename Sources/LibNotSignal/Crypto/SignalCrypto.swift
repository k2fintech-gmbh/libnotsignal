import Foundation

public class SignalCrypto {
    
    // Singleton instance with default provider
    public static let shared = SignalCrypto()
    
    // Customizable crypto provider
    public var provider: CryptoProvider
    
    public init(provider: CryptoProvider = DefaultCryptoProvider()) {
        self.provider = provider
    }
    
    // Random number generation
    public func randomBytes(count: Int) throws -> Data {
        return try provider.randomBytes(count: count)
    }
    
    // Generate a random integer in a specific range
    public func randomInt(min: UInt32, max: UInt32) throws -> UInt32 {
        precondition(max > min)
        let range = max - min + 1
        let bytesNeeded = 4
        
        let randomData = try randomBytes(count: bytesNeeded)
        let randomValue = randomData.withUnsafeBytes { pointer in
            return pointer.load(as: UInt32.self)
        }
        
        return (randomValue % range) + min
    }
    
    // Hash functions
    public func sha256(_ data: Data) -> Data {
        return provider.sha256(data)
    }
    
    public func hmacSHA256(key: Data, data: Data) -> Data {
        return provider.hmacSHA256(key: key, data: data)
    }
    
    // HKDF
    public func hkdfDeriveSecrets(inputKeyMaterial: Data, info: Data, outputLength: Int, salt: Data = Data()) throws -> Data {
        return try provider.hkdfDeriveSecrets(inputKeyMaterial: inputKeyMaterial, info: info, outputLength: outputLength, salt: salt)
    }
    
    // AES encryption/decryption
    public func encrypt(key: Data, iv: Data, data: Data) throws -> Data {
        return try provider.encrypt(key: key, iv: iv, data: data)
    }
    
    public func decrypt(key: Data, iv: Data, data: Data) throws -> Data {
        return try provider.decrypt(key: key, iv: iv, data: data)
    }
    
    // Curve25519 operations
    public func generateKeyPair() throws -> (privateKey: Data, publicKey: Data) {
        return try provider.generateKeyPair()
    }
    
    // Generate a key pair using a given private key
    public func generateKeyPair(privateKey: Data) throws -> (privateKey: Data, publicKey: Data) {
        // Use the provider to derive the public key from the private key
        if let extendedProvider = provider as? ExtendedCryptoProvider {
            let publicKey = try extendedProvider.getPublicKeyFrom(privateKey: privateKey)
            return (privateKey: privateKey, publicKey: publicKey)
        } else {
            throw LibNotSignalError.unsupportedOperation
        }
    }
    
    public func calculateAgreement(privateKey: Data, publicKey: Data) throws -> Data {
        return try provider.calculateAgreement(privateKey: privateKey, publicKey: publicKey)
    }
    
    public func sign(privateKey: Data, message: Data) throws -> Data {
        return try provider.sign(privateKey: privateKey, message: message)
    }
    
    public func verify(publicKey: Data, message: Data, signature: Data) throws -> Bool {
        return try provider.verify(publicKey: publicKey, message: message, signature: signature)
    }
} 