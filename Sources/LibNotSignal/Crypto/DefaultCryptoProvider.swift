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
    
    // AES-CBC encryption/decryption
    public func encrypt(key: Data, iv: Data, data: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: AES.GCM.Nonce(data: iv))
        return sealedBox.ciphertext + sealedBox.tag
    }
    
    public func decrypt(key: Data, iv: Data, data: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        
        // Split the data into ciphertext and tag (assuming tag is at the end, 16 bytes for AES-GCM)
        let tagSize = 16
        let ciphertextSize = data.count - tagSize
        
        guard ciphertextSize > 0 else {
            throw LibNotSignalError.invalidCiphertext
        }
        
        let ciphertext = data.prefix(ciphertextSize)
        let tag = data.suffix(tagSize)
        
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: iv),
            ciphertext: ciphertext,
            tag: tag
        )
        
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
    
    // Elliptic curve operations (using Curve25519)
    public func generateKeyPair() throws -> (privateKey: Data, publicKey: Data) {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        return (privateKey.rawRepresentation, publicKey.rawRepresentation)
    }
    
    public func calculateAgreement(privateKey: Data, publicKey: Data) throws -> Data {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }
    
    public func sign(privateKey: Data, message: Data) throws -> Data {
        // Use the private key for signing
        // Note: In some protocols you would use separate signing and agreement keys
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        let signature = try signingKey.signature(for: message)
        return Data(signature)
    }
    
    public func verify(publicKey: Data, message: Data, signature: Data) throws -> Bool {
        // Verify using the appropriate signing public key
        let signingPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        return signingPublicKey.isValidSignature(signature, for: message)
    }
} 