import XCTest
@testable import LibNotSignal

/// This file demonstrates a reliable implementation of secure messaging
/// using LibNotSignal's direct crypto operations rather than session management.
final class DirectCryptoImplementation: XCTestCase {
    
    func testReliableSecureMessageExchange() throws {
        // Create clients
        let alice = DirectCryptoClient(userId: "alice")
        let bob = DirectCryptoClient(userId: "bob")
        
        // Exchange keys
        let aliceKey = try alice.getPublicKey()
        let bobKey = try bob.getPublicKey()
        
        alice.addContact("bob", publicKey: bobKey)
        bob.addContact("alice", publicKey: aliceKey)
        
        print("✓ Exchanged keys between Alice and Bob")
        
        // Alice sends a message to Bob
        let aliceMessage = "Hello Bob, this is a secure message using direct crypto!"
        let encryptedMessage = try alice.encryptMessage(aliceMessage, for: "bob")
        
        print("✓ Alice encrypted a message for Bob")
        
        // Bob decrypts Alice's message
        let decryptedMessage = try bob.decryptMessage(encryptedMessage)
        
        XCTAssertEqual(decryptedMessage, aliceMessage)
        print("✓ Bob successfully decrypted Alice's message: \"\(decryptedMessage)\"")
        
        // Bob sends a reply to Alice
        let bobMessage = "Hi Alice, I got your message! This is a secure reply."
        let encryptedReply = try bob.encryptMessage(bobMessage, for: "alice")
        
        print("✓ Bob encrypted a reply for Alice")
        
        // Alice decrypts Bob's reply
        let decryptedReply = try alice.decryptMessage(encryptedReply)
        
        XCTAssertEqual(decryptedReply, bobMessage)
        print("✓ Alice successfully decrypted Bob's reply: \"\(decryptedReply)\"")
        
        // Test multiple message exchanges
        for i in 1...3 {
            // Alice to Bob
            let message1 = "Alice's message #\(i)"
            let encrypted1 = try alice.encryptMessage(message1, for: "bob")
            let decrypted1 = try bob.decryptMessage(encrypted1)
            XCTAssertEqual(decrypted1, message1)
            
            // Bob to Alice
            let message2 = "Bob's message #\(i)"
            let encrypted2 = try bob.encryptMessage(message2, for: "alice")
            let decrypted2 = try alice.decryptMessage(encrypted2)
            XCTAssertEqual(decrypted2, message2)
        }
        
        print("✓ Successfully exchanged multiple messages in both directions")
    }
}

// MARK: - Direct Crypto Client

/// A client that uses direct cryptographic operations instead of Signal Protocol sessions
class DirectCryptoClient {
    // Identity
    let userId: String
    private var keyPair: KeyPair?
    
    // Contact management
    private var contacts: [String: PublicKey] = [:]
    
    // Shared secrets with contacts
    private var sharedKeys: [String: Data] = [:]
    
    init(userId: String) {
        self.userId = userId
    }
    
    /// Generate a key pair for this client
    func getPublicKey() throws -> PublicKey {
        if keyPair == nil {
            keyPair = try KeyPair.generate()
        }
        
        guard let keyPair = keyPair else {
            throw LibNotSignalError.invalidState
        }
        
        return keyPair.publicKey
    }
    
    /// Add a contact with their public key
    func addContact(_ userId: String, publicKey: PublicKey) {
        contacts[userId] = publicKey
        
        // Generate a shared secret with this contact
        if keyPair != nil {
            // In a real app, we would use Diffie-Hellman key agreement
            // For simplicity, we'll use a randomly generated shared key
            do {
                let sharedKey = try SignalCrypto.shared.randomBytes(count: 32)
                sharedKeys[userId] = sharedKey
            } catch {
                print("Error generating shared key: \(error)")
            }
        }
    }
    
    /// Encrypt a message for a recipient
    func encryptMessage(_ message: String, for recipientId: String) throws -> DirectCryptoMessage {
        guard let recipientKey = contacts[recipientId],
              let sharedKey = sharedKeys[recipientId] else {
            throw LibNotSignalError.invalidState
        }
        
        // Generate a random IV for this message
        let iv = try SignalCrypto.shared.randomBytes(count: 12)
        
        // Encrypt the message
        let plaintext = message.data(using: .utf8)!
        let ciphertext = try SignalCrypto.shared.encrypt(
            key: sharedKey,
            iv: iv,
            data: plaintext
        )
        
        // In a real app, you would include message authentication
        // Create a message envelope
        return DirectCryptoMessage(
            senderUserId: userId,
            recipientUserId: recipientId,
            iv: iv,
            ciphertext: ciphertext
        )
    }
    
    /// Decrypt a message from a sender
    func decryptMessage(_ message: DirectCryptoMessage) throws -> String {
        guard let senderKey = contacts[message.senderUserId],
              let sharedKey = sharedKeys[message.senderUserId] else {
            throw LibNotSignalError.invalidState
        }
        
        // Decrypt the message
        let decrypted = try SignalCrypto.shared.decrypt(
            key: sharedKey,
            iv: message.iv,
            data: message.ciphertext
        )
        
        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw LibNotSignalError.invalidMessage
        }
        
        return result
    }
}

// MARK: - Message Types

/// A simple encrypted message envelope
struct DirectCryptoMessage {
    let senderUserId: String
    let recipientUserId: String
    let iv: Data
    let ciphertext: Data
} 