import XCTest
@testable import LibNotSignal

final class CryptoTests: XCTestCase {
    
    func testGenerateKeyPair() throws {
        // Generate a key pair
        let keyPair = try SignalCrypto.shared.generateKeyPair()
        
        // Verify key pair properties
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertFalse(keyPair.publicKey.isEmpty)
        XCTAssertFalse(keyPair.privateKey.isEmpty)
        
        // Generate a second key pair to check uniqueness
        let keyPair2 = try SignalCrypto.shared.generateKeyPair()
        XCTAssertNotEqual(keyPair.publicKey, keyPair2.publicKey)
        XCTAssertNotEqual(keyPair.privateKey, keyPair2.privateKey)
    }
    
    func testRandomBytes() throws {
        // Test random data generation
        let randomData1 = try SignalCrypto.shared.randomBytes(count: 32)
        let randomData2 = try SignalCrypto.shared.randomBytes(count: 32)
        
        // Verify the length
        XCTAssertEqual(randomData1.count, 32)
        XCTAssertEqual(randomData2.count, 32)
        
        // Verify that two random generations produce different data
        XCTAssertNotEqual(randomData1, randomData2)
    }
    
    func testEncryptDecrypt() throws {
        // Generate a random key and IV for testing
        let key = try SignalCrypto.shared.randomBytes(count: 32)  // 256-bit key
        let iv = try SignalCrypto.shared.randomBytes(count: 16)   // 128-bit IV
        
        // Test data to encrypt
        let plaintext = "Secret message".data(using: .utf8)!
        
        // Encrypt data
        let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)
        
        // Verify ciphertext is not the same as plaintext
        XCTAssertNotEqual(ciphertext, plaintext)
        
        // Decrypt data
        let decrypted = try SignalCrypto.shared.decrypt(key: key, iv: iv, data: ciphertext)
        
        // Verify decrypted matches the original
        XCTAssertEqual(decrypted, plaintext)
    }
    
    func testEncryptDecryptSpecificMessage() throws {
        // Generate a random key and IV for encryption
        let key = try SignalCrypto.shared.randomBytes(count: 32)  // 256-bit key
        let iv = try SignalCrypto.shared.randomBytes(count: 16)   // 128-bit IV
        
        // Specific message to encrypt
        let message = "Hi BOB"
        let plaintext = message.data(using: .utf8)!
        
        // Encrypt the message
        let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)
        
        // Verify the message was encrypted (ciphertext should be different from plaintext)
        XCTAssertNotEqual(ciphertext, plaintext)
        
        // Decrypt the message
        let decryptedData = try SignalCrypto.shared.decrypt(key: key, iv: iv, data: ciphertext)
        
        // Convert back to string
        let decryptedMessage = String(data: decryptedData, encoding: .utf8)
        
        // Verify decrypted message matches the original
        XCTAssertEqual(decryptedMessage, message)
        XCTAssertEqual(decryptedMessage, "Hi BOB")
    }
    
    // Note: Signing and verification functionality is not yet implemented
} 