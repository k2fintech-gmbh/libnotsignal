import Foundation
import Crypto
import os.log

public class DefaultCryptoProvider: CryptoProvider {
    
    // Logger for debugging
    private let logger: OSLog
    private let isDebugLoggingEnabled: Bool
    
    public init(isDebugLoggingEnabled: Bool = false) {
        self.isDebugLoggingEnabled = isDebugLoggingEnabled
        self.logger = OSLog(subsystem: "LibNotSignal", category: "Crypto")
    }
    
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
    
    // AES-GCM implementation compliant with Signal Protocol
    public func encrypt(key: Data, iv: Data, data: Data) throws -> Data {
        if isDebugLoggingEnabled {
            os_log("Encrypt: key length: %d, IV length: %d, data length: %d", log: logger, type: .debug, 
                   key.count, iv.count, data.count)
            os_log("Encrypt: IV: %{public}@", log: logger, type: .debug, iv.hexEncodedString())
        }
        
        // Validate key size: AES requires 16 or 32 bytes (128 or 256 bit) keys
        guard key.count == 16 || key.count == 32 else {
            os_log("Invalid key size: %d", log: logger, type: .error, key.count)
            throw LibNotSignalError.invalidKey
        }
        
        // Normalize IV to 12 bytes for AES-GCM
        let normalizedIV = normalizeIV(iv)
        
        // Create symmetric key and nonce
        let symmetricKey = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: normalizedIV)
        
        // Encrypt with AES-GCM
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce)
        
        // Signal Protocol format: ciphertext + authentication tag
        // The IV is not included in the output, as it's provided separately
        var result = Data()
        result.append(sealedBox.ciphertext)
        result.append(sealedBox.tag)
        
        if isDebugLoggingEnabled {
            os_log("Encrypt result: length: %d", log: logger, type: .debug, result.count)
            if result.count <= 64 {
                os_log("Encrypt result: %{public}@", log: logger, type: .debug, result.hexEncodedString())
            }
        }
        
        return result
    }
    
    public func decrypt(key: Data, iv: Data, data: Data) throws -> Data {
        if isDebugLoggingEnabled {
            os_log("Decrypt: key length: %d, IV length: %d, data length: %d", log: logger, type: .debug, 
                   key.count, iv.count, data.count)
            os_log("Decrypt: IV: %{public}@", log: logger, type: .debug, iv.hexEncodedString())
        }
        
        // Validate key size
        guard key.count == 16 || key.count == 32 else {
            os_log("Invalid key size: %d", log: logger, type: .error, key.count)
            throw LibNotSignalError.invalidKey
        }
        
        // Ensure the data is long enough to have an authentication tag
        guard data.count >= 16 else {
            os_log("Data too short to contain authentication tag", log: logger, type: .error)
            throw LibNotSignalError.invalidCiphertext
        }
        
        // Normalize IV to 12 bytes
        let normalizedIV = normalizeIV(iv)
        
        // Split data into ciphertext and authentication tag
        let tagLength = 16 // GCM authentication tag is 16 bytes
        let ciphertextLength = data.count - tagLength
        let ciphertext = data.prefix(ciphertextLength)
        let tag = data.suffix(tagLength)
        
        if isDebugLoggingEnabled {
            os_log("Decrypt: ciphertext length: %d", log: logger, type: .debug, ciphertextLength)
            os_log("Decrypt: auth tag: %{public}@", log: logger, type: .debug, tag.hexEncodedString())
        }
        
        do {
            // Create symmetric key and nonce
            let symmetricKey = SymmetricKey(data: key)
            let nonce = try AES.GCM.Nonce(data: normalizedIV)
            
            // Create a sealed box from components
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            
            // Decrypt with AES-GCM and verify authentication
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
            
            if isDebugLoggingEnabled {
                os_log("Decrypt success: plaintext length: %d", log: logger, type: .debug, plaintext.count)
            }
            
            return plaintext
        } catch {
            os_log("Decrypt failed: %{public}@", log: logger, type: .error, error as CVarArg)
            throw LibNotSignalError.invalidCiphertext
        }
    }
    
    // Helper to normalize IV to the 12 bytes required by AES-GCM
    private func normalizeIV(_ iv: Data) -> Data {
        if iv.count == 12 {
            // IV is already the correct size
            return iv
        } else if iv.count < 12 {
            // Pad with zeros if too short
            return iv + Data(repeating: 0, count: 12 - iv.count)
        } else {
            // Truncate to first 12 bytes if too long
            return iv.prefix(12)
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
        if isDebugLoggingEnabled {
            os_log("Signing message of length %d with private key of length %d", log: logger, type: .debug,
                   message.count, privateKey.count)
        }
        
        do {
            // Create an Ed25519 signing key from the provided private key
            // Note: If you're given a Curve25519 key, you might need to convert it to Ed25519 format
            // The CryptoKit Ed25519 API expects a specific format for its private keys
            
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
            
            // Sign the message
            let signature = try signingKey.signature(for: message)
            
            if isDebugLoggingEnabled {
                os_log("Successfully generated signature of length %d", log: logger, type: .debug, signature.count)
            }
            
            return Data(signature)
        } catch {
            os_log("Signing failed: %{public}@", log: logger, type: .error, error as CVarArg)
            throw LibNotSignalError.signatureError
        }
    }
    
    public func verify(publicKey: Data, message: Data, signature: Data) throws -> Bool {
        if isDebugLoggingEnabled {
            os_log("Verifying signature of length %d for message of length %d with public key of length %d", 
                   log: logger, type: .debug, signature.count, message.count, publicKey.count)
        }
        
        do {
            // Create an Ed25519 verification key from the provided public key
            let verificationKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            
            // Verify the signature
            let isValid = verificationKey.isValidSignature(Data(signature), for: message)
            
            if isDebugLoggingEnabled {
                os_log("Signature verification result: %{public}@", log: logger, type: .debug, isValid ? "valid" : "invalid")
            }
            
            return isValid
        } catch {
            os_log("Verification failed: %{public}@", log: logger, type: .error, error as CVarArg)
            throw LibNotSignalError.signatureError
        }
    }
}

// Extension for Data to provide hex encoding
extension Data {
    func hexEncodedString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
} 