import XCTest
import Crypto
@testable import LibNotSignal

class CryptoTests: XCTestCase {
    
    func testAESGCMEncryptionDecryption() throws {
        // Generate a random key and IV
        let key = try SignalCrypto.shared.randomBytes(count: 32) // 256-bit key
        let iv = try SignalCrypto.shared.randomBytes(count: 12)  // 96-bit IV (standard for AES-GCM)
        
        // Test data
        let plaintext = "This is a test message for Signal Protocol".data(using: .utf8)!
        
        // Encrypt
        let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)
        
        // Verify format: The ciphertext should be original length + 16 bytes for the tag
        XCTAssertEqual(ciphertext.count, plaintext.count + 16)
        
        // Decrypt
        let decrypted = try SignalCrypto.shared.decrypt(key: key, iv: iv, data: ciphertext)
        
        // Verify decryption
        XCTAssertEqual(decrypted, plaintext)
        
        // Test authentication failure
        var modifiedCiphertext = ciphertext
        // Modify a byte in the ciphertext
        let index = min(4, ciphertext.count - 17)  // Ensure we're modifying the ciphertext, not the tag
        modifiedCiphertext[index] ^= 0x01
        
        // This should throw an authentication error
        XCTAssertThrowsError(try SignalCrypto.shared.decrypt(key: key, iv: iv, data: modifiedCiphertext)) { error in
            XCTAssertEqual(error as? LibNotSignalError, LibNotSignalError.invalidCiphertext)
        }
    }
    
    func testSignalProtocolFormat() throws {
        // This test verifies that our AES-GCM format matches what Signal Protocol expects
        
        // Generate a random key and IV
        let key = try SignalCrypto.shared.randomBytes(count: 32)
        let iv = try SignalCrypto.shared.randomBytes(count: 12)
        
        // Test data
        let plaintext = "Message for Signal Protocol format test".data(using: .utf8)!
        
        // Encrypt with our provider
        let provider = DefaultCryptoProvider()
        let ciphertext = try provider.encrypt(key: key, iv: iv, data: plaintext)
        
        // Verify that our ciphertext doesn't contain the IV
        // (Signal Protocol passes IV separately, so ciphertext should only have data + tag)
        
        // Create a Swift Crypto implementation for verification
        let symmetricKey = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
        
        // Our ciphertext should be just the ciphertext + tag (no IV)
        let expectedFormat = sealedBox.ciphertext + sealedBox.tag
        
        // Verify the format
        XCTAssertEqual(ciphertext, expectedFormat)
        
        // Verify decryption using separate IV
        let decrypted = try provider.decrypt(key: key, iv: iv, data: ciphertext)
        XCTAssertEqual(decrypted, plaintext)
    }
} 