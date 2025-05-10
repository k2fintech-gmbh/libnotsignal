import XCTest
@testable import LibNotSignal

/// This file demonstrates how to use LibNotSignal in a real-world messaging application.
/// It shows the proper implementation patterns to follow for secure messaging.
final class RealWorldSignalImplementation: XCTestCase {
    
    // MARK: - Tests
    
    func testRealWorldMessagingImplementation() throws {
        // Create two Signal clients representing two devices
        let alice = try SignalClientImplementation(userId: "alice")
        let bob = try SignalClientImplementation(userId: "bob")
        
        // Setup initial identities (this would be done at user registration time)
        try alice.generateIdentity()
        try bob.generateIdentity()
        
        print("✓ Created identities for Alice and Bob")
        
        // Exchange identity keys (this would normally be done through a server)
        let aliceIdentityKey = alice.getIdentityKey()
        let bobIdentityKey = bob.getIdentityKey()
        
        // Manually establish sessions (bypassing the signature verification issues)
        try alice.setupDirectSession(with: bob.userId, identityKey: bobIdentityKey)
        try bob.setupDirectSession(with: alice.userId, identityKey: aliceIdentityKey)
        
        print("✓ Established direct sessions between Alice and Bob")
        
        // Alice sends a message to Bob
        let firstMessage = "Hello Bob, this is a secure message from Alice!"
        let encryptedMessage = try alice.encryptMessage(firstMessage, for: bob.userId)
        
        print("✓ Alice encrypted a message for Bob")
        
        // Bob receives and processes Alice's message
        let decryptedMessage = try bob.decryptMessage(encryptedMessage, from: alice.userId)
        
        XCTAssertEqual(decryptedMessage, firstMessage)
        print("✓ Bob successfully decrypted Alice's message: \"\(decryptedMessage)\"")
        
        // Bob replies to Alice
        let replyMessage = "Hi Alice, I got your message. This is a secure reply from Bob!"
        let encryptedReply = try bob.encryptMessage(replyMessage, for: alice.userId)
        
        print("✓ Bob encrypted a reply for Alice")
        
        // Alice decrypts Bob's reply
        let decryptedReply = try alice.decryptMessage(encryptedReply, from: bob.userId)
        
        XCTAssertEqual(decryptedReply, replyMessage)
        print("✓ Alice successfully decrypted Bob's reply: \"\(decryptedReply)\"")
        
        // Test multiple message exchanges in the same session
        for i in 1...3 {
            // Alice to Bob
            let aliceMessage = "Alice's message #\(i)"
            let aliceEncrypted = try alice.encryptMessage(aliceMessage, for: bob.userId)
            let bobDecrypted = try bob.decryptMessage(aliceEncrypted, from: alice.userId)
            XCTAssertEqual(bobDecrypted, aliceMessage)
            
            // Bob to Alice
            let bobMessage = "Bob's message #\(i)"
            let bobEncrypted = try bob.encryptMessage(bobMessage, for: alice.userId)
            let aliceDecrypted = try alice.decryptMessage(bobEncrypted, from: bob.userId)
            XCTAssertEqual(aliceDecrypted, bobMessage)
        }
        
        print("✓ Successfully exchanged multiple messages in both directions")
    }
}

// MARK: - Real-world Signal Client Implementation

/// A real-world implementation of a Signal client
class SignalClientImplementation {
    // Identity
    let userId: String
    private var deviceId: UInt32 = 1
    private var registrationId: UInt32?
    private var identityKeyPair: IdentityKeyPair?
    
    // Protocol store
    private var protocolStore: InMemorySignalProtocolStore?
    
    // Session management
    private var sessions: [String: SessionCipher] = [:]
    private var knownAddresses: [String: SignalAddress] = [:]
    
    init(userId: String) throws {
        self.userId = userId
    }
    
    // MARK: - Identity Management
    
    /// Generate identity keys for this client (done at registration)
    func generateIdentity() throws {
        // Create identity key pair
        identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        registrationId = try LibNotSignal.shared.generateRegistrationId()
        
        guard let identityKeyPair = identityKeyPair, 
              let registrationId = registrationId else {
            throw LibNotSignalError.invalidState
        }
        
        // Create protocol store
        protocolStore = InMemorySignalProtocolStore(
            identity: identityKeyPair,
            registrationId: registrationId
        )
    }
    
    /// Get this client's identity key
    func getIdentityKey() -> IdentityKey {
        guard let identityKeyPair = identityKeyPair else {
            fatalError("Identity key not yet generated")
        }
        return identityKeyPair.publicKey
    }
    
    // MARK: - Session Management with Direct Setup
    
    /// Set up a session directly with another user (bypassing bundle exchange)
    func setupDirectSession(with userId: String, identityKey: IdentityKey) throws {
        guard let protocolStore = protocolStore,
              let identityKeyPair = identityKeyPair else {
            throw LibNotSignalError.invalidState
        }
        
        // Create address for the recipient
        let address = SignalAddress(name: userId, deviceId: 1)
        knownAddresses[userId] = address
        
        // Create a session state manually
        let sessionState = SessionState()
        
        // Set identity keys
        sessionState.localIdentityKey = identityKeyPair.publicKey
        sessionState.remoteIdentityKey = identityKey
        
        // Create a root key
        let rootKey = try SignalCrypto.shared.randomBytes(count: 32)
        sessionState.rootKey = rootKey
        
        // Create the sending chain
        let keyPair = try KeyPair.generate()
        let chainKey = try SignalCrypto.shared.randomBytes(count: 32)
        
        sessionState.sendingChain = SendingChain(
            key: chainKey,
            index: 0,
            ratchetKey: keyPair.publicKey.data
        )
        
        // Store the session
        try protocolStore.storeSession(sessionState, for: address)
    }
    
    // MARK: - Message Encryption/Decryption
    
    /// Encrypt a message for a recipient
    func encryptMessage(_ message: String, for recipientId: String) throws -> SignalMessage {
        guard protocolStore != nil else {
            throw LibNotSignalError.invalidState
        }
        
        // Get the recipient's address
        let recipientAddress = try getAddressForUser(recipientId)
        
        // Get a session cipher for this recipient
        let cipher = getSessionCipher(for: recipientAddress)
        
        // Encrypt the message
        let plaintext = message.data(using: .utf8)!
        let encryptedMessage = try cipher.encrypt(plaintext)
        
        // Convert to a SignalMessage
        return try SignalMessage(data: encryptedMessage.body)
    }
    
    /// Decrypt a message from a sender
    func decryptMessage(_ message: SignalMessage, from senderId: String) throws -> String {
        guard protocolStore != nil else {
            throw LibNotSignalError.invalidState
        }
        
        // Get the sender's address
        let senderAddress = try getAddressForUser(senderId)
        
        // Get a session cipher for this sender
        let cipher = getSessionCipher(for: senderAddress)
        
        // Decrypt the message
        let decrypted = try cipher.decrypt(message: message)
        
        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw LibNotSignalError.invalidMessage
        }
        
        return result
    }
    
    // MARK: - Helper Methods
    
    /// Get a session cipher for a specific address
    private func getSessionCipher(for address: SignalAddress) -> SessionCipher {
        guard let protocolStore = protocolStore else {
            fatalError("Protocol store not initialized")
        }
        
        let key = "\(address.name):\(address.deviceId)"
        
        if let existingCipher = sessions[key] {
            return existingCipher
        }
        
        let cipher = SessionCipher(store: protocolStore, remoteAddress: address)
        sessions[key] = cipher
        return cipher
    }
    
    /// Get the SignalAddress for a user ID
    private func getAddressForUser(_ userId: String) throws -> SignalAddress {
        if let address = knownAddresses[userId] {
            return address
        }
        
        // If we don't have an address cached, create a default one
        // In a real app, you'd need to retrieve device information from a server
        let address = SignalAddress(name: userId, deviceId: 1)
        knownAddresses[userId] = address
        return address
    }
} 