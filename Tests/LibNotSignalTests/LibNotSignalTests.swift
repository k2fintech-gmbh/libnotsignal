import XCTest
@testable import LibNotSignal

class LibNotSignalTests: XCTestCase {
    
    func testKeyGeneration() throws {
        // Test identity key pair generation
        let identityKeyPair = try IdentityKeyPair.generate()
        XCTAssertFalse(identityKeyPair.publicKey.publicKey.isEmpty)
        XCTAssertFalse(identityKeyPair.privateKey.isEmpty)
        
        // Test pre key generation
        let preKey = try PreKeyRecord.generate(id: 1)
        XCTAssertEqual(preKey.id, 1)
        XCTAssertFalse(preKey.publicKey.isEmpty)
        XCTAssertFalse(preKey.privateKey.isEmpty)
        
        // Test signed pre key generation
        let signedPreKey = try SignedPreKeyRecord.generate(id: 2, identityKeyPair: identityKeyPair)
        XCTAssertEqual(signedPreKey.id, 2)
        XCTAssertFalse(signedPreKey.publicKey.isEmpty)
        XCTAssertFalse(signedPreKey.privateKey.isEmpty)
        XCTAssertFalse(signedPreKey.signature.isEmpty)
        
        // Test signature generation and verification
        let message = "Test message".data(using: .utf8)!
        let signature = try identityKeyPair.sign(message)
        XCTAssertFalse(signature.isEmpty)
        
        // Verify the signature
        let validSignature = try identityKeyPair.publicKey.verifySignature(
            for: message,
            signature: signature
        )
        XCTAssertTrue(validSignature)
    }
    
    func testCryptoOperations() throws {
        // Test random bytes generation
        let randomData = try SignalCrypto.shared.randomBytes(count: 32)
        XCTAssertEqual(randomData.count, 32)
        
        // Test SHA256
        let testData = "test".data(using: .utf8)!
        let hash = SignalCrypto.shared.sha256(testData)
        XCTAssertEqual(hash.count, 32)
        
        // Test HMAC
        let hmacKey = "key".data(using: .utf8)!
        let hmac = SignalCrypto.shared.hmacSHA256(key: hmacKey, data: testData)
        XCTAssertEqual(hmac.count, 32)
        
        // Test encryption and decryption
        let (privateKey, publicKey) = try SignalCrypto.shared.generateKeyPair()
        XCTAssertFalse(privateKey.isEmpty)
        XCTAssertFalse(publicKey.isEmpty)
        
        // Test key agreement
        let sharedSecret = try SignalCrypto.shared.calculateAgreement(privateKey: privateKey, publicKey: publicKey)
        XCTAssertFalse(sharedSecret.isEmpty)
        
        // Test encryption with derived key
        let key = try SignalCrypto.shared.hkdfDeriveSecrets(
            inputKeyMaterial: sharedSecret,
            info: "Test".data(using: .utf8)!,
            outputLength: 32
        )
        let iv = try SignalCrypto.shared.randomBytes(count: 16)
        let plaintext = "Hello, world!".data(using: .utf8)!
        
        let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)
        XCTAssertFalse(ciphertext.isEmpty)
        
        // Test decryption
        let decrypted = try SignalCrypto.shared.decrypt(key: key, iv: iv, data: ciphertext)
        XCTAssertEqual(decrypted, plaintext)
    }
} 