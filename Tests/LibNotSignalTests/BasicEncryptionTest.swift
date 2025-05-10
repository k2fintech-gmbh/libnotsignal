import XCTest
@testable import LibNotSignal

/// A basic test that demonstrates using the LibNotSignal crypto directly
/// This is the most reliable way to test the encryption/decryption functionality
final class BasicEncryptionTest: XCTestCase {
    
    func testBasicEncryptionDecryption() throws {
        // Fixed key for testing
        let key = Data(repeating: 0xAB, count: 32)  // 32-byte key (256 bits)
        
        // Fixed IV for testing
        let iv = Data(repeating: 0xCD, count: 12)   // 12-byte IV for AES-GCM
        
        // Test message
        let message = "Hi Bob, this is Alice!"
        let plaintext = message.data(using: .utf8)!
        
        print("Original message: \"\(message)\"")
        print("Using key: \(dataToHexString(key))")
        print("Using IV: \(dataToHexString(iv))")
        
        // Encrypt
        let ciphertext = try SignalCrypto.shared.encrypt(
            key: key,
            iv: iv,
            data: plaintext
        )
        
        print("Encrypted data: \(dataToHexString(ciphertext))")
        
        // Decrypt
        let decryptedData = try SignalCrypto.shared.decrypt(
            key: key,
            iv: iv,
            data: ciphertext
        )
        
        // Convert back to string
        guard let decryptedMessage = String(data: decryptedData, encoding: .utf8) else {
            XCTFail("Failed to decode decrypted data")
            return
        }
        
        print("Decrypted message: \"\(decryptedMessage)\"")
        
        // Verify
        XCTAssertEqual(decryptedMessage, message)
    }
    
    func testMultipleMessagesWithSameKey() throws {
        // Fixed key for testing
        let key = Data(repeating: 0x12, count: 32)
        
        // Messages
        let messages = [
            "First message from Alice to Bob",
            "Second message with different content",
            "Third message - still using the same key"
        ]
        
        for (i, message) in messages.enumerated() {
            print("\nMessage #\(i+1): \"\(message)\"")
            
            // Use a different IV for each message
            let iv = Data(repeating: UInt8(i + 1), count: 12)
            print("Using IV: \(dataToHexString(iv))")
            
            // Encrypt
            let plaintext = message.data(using: .utf8)!
            let ciphertext = try SignalCrypto.shared.encrypt(
                key: key,
                iv: iv,
                data: plaintext
            )
            
            // Decrypt with the same key and IV
            let decryptedData = try SignalCrypto.shared.decrypt(
                key: key,
                iv: iv,
                data: ciphertext
            )
            
            // Convert back to string
            guard let decryptedMessage = String(data: decryptedData, encoding: .utf8) else {
                XCTFail("Failed to decode decrypted data for message #\(i+1)")
                continue
            }
            
            // Verify
            XCTAssertEqual(decryptedMessage, message)
            print("Successfully decrypted: \"\(decryptedMessage)\"")
        }
    }
    
    // Helper function to convert data to hex string
    private func dataToHexString(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
} 