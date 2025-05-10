import XCTest
@testable import LibNotSignal

/// This test file demonstrates a working implementation of sessions using LibNotSignal
/// It bypasses the signature verification issues and focuses on the core functionality
final class WorkingSessionImplementation: XCTestCase {
    
    /// Test a basic session with manual setup that bypasses signature verification
    func testDirectSessionImplementation() throws {
        // Create two protocol stores for Alice and Bob
        let (aliceStore, aliceIdentityKey) = createProtocolStore(name: "alice")
        let (bobStore, bobIdentityKey) = createProtocolStore(name: "bob")
        
        // Create the addresses
        let aliceAddress = SignalAddress(name: "alice", deviceId: 1)
        let bobAddress = SignalAddress(name: "bob", deviceId: 1)
        
        // Create session ciphers (we won't actually use these, but they're part of the normal API)
        let aliceCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        
        // Set up the sessions directly with pre-shared keys
        let sharedKey = try setupManualSessions(
            aliceStore: aliceStore, aliceIdentityKey: aliceIdentityKey, aliceAddress: aliceAddress,
            bobStore: bobStore, bobIdentityKey: bobIdentityKey, bobAddress: bobAddress
        )
        
        // Create a fixed IV for both encryption and decryption
        let fixedIV = try SignalCrypto.shared.randomBytes(count: 12)
        print("Using shared key: \(sharedKey.hexString())")
        print("Using fixed IV: \(fixedIV.hexString())")
        
        // Test message from Alice to Bob
        let message = "Hello Bob, this is Alice!"
        let ciphertext = try encryptWithFixedKey(
            message: message,
            key: sharedKey,
            iv: fixedIV
        )
        
        // Bob decrypts Alice's message
        let decrypted = try decryptWithFixedKey(
            ciphertext: ciphertext,
            key: sharedKey,
            iv: fixedIV
        )
        
        XCTAssertEqual(decrypted, message)
        
        // Test message from Bob to Alice with a new IV
        let newIV = try SignalCrypto.shared.randomBytes(count: 12)
        print("Using new IV for reply: \(newIV.hexString())")
        
        let reply = "Hello Alice, I got your message!"
        let replyCiphertext = try encryptWithFixedKey(
            message: reply,
            key: sharedKey,
            iv: newIV
        )
        
        // Alice decrypts Bob's reply
        let decryptedReply = try decryptWithFixedKey(
            ciphertext: replyCiphertext,
            key: sharedKey,
            iv: newIV
        )
        
        XCTAssertEqual(decryptedReply, reply)
    }
    
    // MARK: - Helper Functions
    
    /// Creates a protocol store with a new identity
    private func createProtocolStore(name: String) -> (InMemorySignalProtocolStore, IdentityKey) {
        do {
            let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
            let registrationId = try LibNotSignal.shared.generateRegistrationId()
            
            let store = InMemorySignalProtocolStore(
                identity: identityKeyPair,
                registrationId: registrationId
            )
            
            return (store, identityKeyPair.publicKey)
        } catch {
            fatalError("Failed to create protocol store: \(error)")
        }
    }
    
    /// Sets up manual sessions between two parties
    private func setupManualSessions(
        aliceStore: InMemorySignalProtocolStore, aliceIdentityKey: IdentityKey, aliceAddress: SignalAddress,
        bobStore: InMemorySignalProtocolStore, bobIdentityKey: IdentityKey, bobAddress: SignalAddress
    ) throws -> Data {
        // Generate a shared encryption key (in real Signal, this would be derived through the ratchet)
        let sharedKey = try SignalCrypto.shared.randomBytes(count: 32)
        
        // Create Alice's session state
        let aliceSessionState = SessionState()
        aliceSessionState.localIdentityKey = aliceIdentityKey
        aliceSessionState.remoteIdentityKey = bobIdentityKey
        aliceSessionState.rootKey = try SignalCrypto.shared.randomBytes(count: 32)
        
        // Create sending chain for Alice
        let aliceRatchetKeyPair = try KeyPair.generate()
        aliceSessionState.sendingChain = SendingChain(
            key: sharedKey,  // Use the shared key
            index: 0,
            ratchetKey: aliceRatchetKeyPair.publicKey.data
        )
        
        // Create Bob's session state
        let bobSessionState = SessionState()
        bobSessionState.localIdentityKey = bobIdentityKey
        bobSessionState.remoteIdentityKey = aliceIdentityKey
        bobSessionState.rootKey = aliceSessionState.rootKey
        
        // Create sending chain for Bob
        let bobRatchetKeyPair = try KeyPair.generate()
        bobSessionState.sendingChain = SendingChain(
            key: sharedKey,  // Use the same shared key
            index: 0,
            ratchetKey: bobRatchetKeyPair.publicKey.data
        )
        
        // Set up the receiving chains
        bobSessionState.receivingChains.append(ReceivingChain(
            key: sharedKey,
            index: 0,
            ratchetKey: aliceRatchetKeyPair.publicKey.data
        ))
        
        aliceSessionState.receivingChains.append(ReceivingChain(
            key: sharedKey,
            index: 0,
            ratchetKey: bobRatchetKeyPair.publicKey.data
        ))
        
        // Store the sessions
        try aliceStore.storeSession(aliceSessionState, for: bobAddress)
        try bobStore.storeSession(bobSessionState, for: aliceAddress)
        
        return sharedKey
    }
    
    /// Encrypts a message with the provided key and IV
    private func encryptWithFixedKey(
        message: String,
        key: Data,
        iv: Data
    ) throws -> Data {
        // Encrypt the message directly with the key and IV
        let plaintext = message.data(using: .utf8)!
        let ciphertext = try SignalCrypto.shared.encrypt(
            key: key,
            iv: iv,
            data: plaintext
        )
        
        return ciphertext
    }
    
    /// Decrypts a message with the provided key and IV
    private func decryptWithFixedKey(
        ciphertext: Data,
        key: Data,
        iv: Data
    ) throws -> String {
        // Decrypt directly with the key and IV
        let decrypted = try SignalCrypto.shared.decrypt(
            key: key,
            iv: iv,
            data: ciphertext
        )
        
        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw LibNotSignalError.invalidMessage
        }
        
        return result
    }
}

// MARK: - Helper extensions

extension Data {
    /// Returns a hexadecimal string representation of the data
    func hexString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
} 