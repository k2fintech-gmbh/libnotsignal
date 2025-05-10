import XCTest
@testable import LibNotSignal

final class DirectEncryptionTests: XCTestCase {
    
    func testSimpleEncryptDecrypt() throws {
        // Generate a random key and IV
        let key = try SignalCrypto.shared.randomBytes(count: 32)  // 256-bit key
        let iv = try SignalCrypto.shared.randomBytes(count: 16)   // 128-bit IV
        
        // Test data to encrypt
        let message = "Hi BOB, this is a test message"
        let plaintext = message.data(using: .utf8)!
        
        // Encrypt the data
        let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)
        XCTAssertNotEqual(ciphertext, plaintext, "Ciphertext should differ from plaintext")
        
        // Decrypt the data
        let decrypted = try SignalCrypto.shared.decrypt(key: key, iv: iv, data: ciphertext)
        let decryptedMessage = String(data: decrypted, encoding: .utf8)
        
        // Verify that the decrypted message matches the original
        XCTAssertEqual(decryptedMessage, message)
    }
    
    func testSessionMessageFormat() throws {
        // First, let's encrypt a message using a specific format similar to what the session cipher would produce
        
        // Generate the keys
        let key = try SignalCrypto.shared.randomBytes(count: 32)
        let iv = try SignalCrypto.shared.randomBytes(count: 16)
        
        // The message
        let message = "Test message for simulated session cipher"
        let plaintext = message.data(using: .utf8)!
        
        // Encrypt the message
        let ciphertext = try SignalCrypto.shared.encrypt(key: key, iv: iv, data: plaintext)
        
        // Create a fake signal message (with just the ciphertext)
        let fakeSignalMessage = SignalMessage(
            version: 3,
            senderRatchetKey: Data(repeating: 0, count: 32),
            counter: 0,
            previousCounter: 0,
            ciphertext: ciphertext,
            serialized: Data()
        )
        
        // Pretend to decrypt a signal message (mimicking what happens in SessionCipher)
        let iv2 = iv // In a real use case, this would be derived from the message keys
        let decrypted = try SignalCrypto.shared.decrypt(
            key: key,
            iv: iv2,
            data: fakeSignalMessage.ciphertext
        )
        
        let decryptedMessage = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual(decryptedMessage, message)
    }
    
    func testMultipleMessages() throws {
        // Create a crypto provider with debug logging enabled
        let debugProvider = DefaultCryptoProvider(isDebugLoggingEnabled: true)
        let crypto = SignalCrypto(provider: debugProvider)
        
        // Generate a key pair
        let key = try crypto.randomBytes(count: 32)
        let iv = try crypto.randomBytes(count: 12) // Use 12 bytes for AES-GCM
        
        // Test multiple messages with the same key and different IVs
        let messages = [
            "Message 1",
            "Message 2",
            "Message 3"
        ]
        
        for (i, message) in messages.enumerated() {
            // Create a unique IV for each message (in real use, this would be derived from chain keys)
            var uniqueIV = iv
            if i > 0 {
                // Modify the last byte for uniqueness
                var ivBytes = [UInt8](iv)
                ivBytes[ivBytes.count - 1] = UInt8(i)
                uniqueIV = Data(ivBytes)
            }
            
            let plaintext = message.data(using: .utf8)!
            
            // Encrypt
            let ciphertext = try crypto.encrypt(key: key, iv: uniqueIV, data: plaintext)
            
            // Decrypt
            let decrypted = try crypto.decrypt(key: key, iv: uniqueIV, data: ciphertext)
            let decryptedMessage = String(data: decrypted, encoding: .utf8)
            
            XCTAssertEqual(decryptedMessage, message, "Message \(i+1) should decrypt correctly")
        }
    }
} 