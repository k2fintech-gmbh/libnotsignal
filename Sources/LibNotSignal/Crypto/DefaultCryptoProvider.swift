import Foundation
import Crypto

public class DefaultCryptoProvider: CryptoProvider {
    
    public init() {}
    
    // Random number generation
    public func randomBytes(count: Int) throws -> Data {
        return Data(SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { buffer in
            return [UInt8](buffer)
        })
    }
    
    // Hash functions
    public func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }
    
    public func hmacSHA256(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let authenticationCode = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(authenticationCode)
    }
    
    // HKDF - Extract and expand to derive keys
    public func hkdfDeriveSecrets(inputKeyMaterial: Data, info: Data, outputLength: Int, salt: Data) throws -> Data {
        let saltKey = SymmetricKey(data: salt)
        
        // HKDF extract
        let prk = HMAC<SHA256>.authenticationCode(for: inputKeyMaterial, using: saltKey)
        
        // HKDF expand
        let blockSize = SHA256.Digest.byteCount
        let numBlocks = (outputLength + blockSize - 1) / blockSize
        
        var output = Data()
        var previousT = Data()
        
        for i in 1...numBlocks {
            var input = previousT
            input.append(info)
            input.append(UInt8(i))
            
            let hmacKey = SymmetricKey(data: prk)
            let t = HMAC<SHA256>.authenticationCode(for: input, using: hmacKey)
            previousT = Data(t)
            output.append(previousT)
        }
        
        return output.prefix(outputLength)
    }
    
    // AES-GCM implementation compatible with Signal Protocol
    public func encrypt(key: Data, iv: Data, data: Data) throws -> Data {
        // Ensure we have the correct key size
        guard key.count == 16 || key.count == 32 else {
            throw LibNotSignalError.invalidKey
        }
        
        // Process IV to ensure correct size (12 bytes for AES-GCM)
        let processedIV = processIV(iv)
        
        // Create symmetric key and nonce
        let symmetricKey = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: processedIV)
        
        // Encrypt with AES-GCM
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce)
        
        // Signal Protocol format: ciphertext followed by authentication tag
        // The IV is passed separately and not included in the result
        var result = Data()
        result.append(sealedBox.ciphertext)
        result.append(sealedBox.tag)
        
        return result
    }
    
    public func decrypt(key: Data, iv: Data, data: Data) throws -> Data {
        // Ensure we have the correct key size
        guard key.count == 16 || key.count == 32 else {
            throw LibNotSignalError.invalidKey
        }
        
        // Ensure we have enough data for at least the authentication tag
        guard data.count >= 16 else {
            throw LibNotSignalError.invalidCiphertext
        }
        
        // Process IV to ensure correct size
        let processedIV = processIV(iv)
        
        // Split the data into ciphertext and tag components
        let ciphertextLength = data.count - 16
        let ciphertext = data.prefix(ciphertextLength)
        let tag = data.suffix(16)
        
        do {
            // Create symmetric key and nonce
            let symmetricKey = SymmetricKey(data: key)
            let nonce = try AES.GCM.Nonce(data: processedIV)
            
            // Create sealed box with separated components
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            
            // Decrypt
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            // Convert all errors to the expected Signal Protocol error type
            throw LibNotSignalError.invalidCiphertext
        }
    }
    
    // Helper to process IV into 12-byte format needed for AES.GCM
    private func processIV(_ iv: Data) -> Data {
        if iv.count == 12 {
            return iv
        } else if iv.count < 12 {
            // Pad with zeros
            return iv + Data(repeating: 0, count: 12 - iv.count)
        } else {
            // Hash and take first 12 bytes
            return sha256(iv).prefix(12)
        }
    }
    
    // Elliptic curve operations (using Curve25519)
    public func generateKeyPair() throws -> (privateKey: Data, publicKey: Data) {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        return (privateKey.rawRepresentation, publicKey.rawRepresentation)
    }
    
    public func calculateAgreement(privateKey: Data, publicKey: Data) throws -> Data {
        let privateKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let publicKeyObj = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        
        let sharedSecret = try privateKeyObj.sharedSecretFromKeyAgreement(with: publicKeyObj)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }
    
    public func sign(privateKey: Data, message: Data) throws -> Data {
        // Note: Curve25519 is not suitable for signing. 
        // For real implementation, use Ed25519 for signatures
        throw LibNotSignalError.unsupportedOperation
    }
    
    public func verify(publicKey: Data, message: Data, signature: Data) throws -> Bool {
        // Note: Curve25519 is not suitable for verifying. 
        // For real implementation, use Ed25519 for verification
        throw LibNotSignalError.unsupportedOperation
    }
} 