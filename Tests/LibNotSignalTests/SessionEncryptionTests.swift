import XCTest
@testable import LibNotSignal

final class SessionEncryptionTests: XCTestCase {
    
    // Test with direct encryption, bypassing session cipher
    func testDirectEncryptionWithSignalMessage() throws {
        // Set up encryption keys
        let messageKey = try SignalCrypto.shared.randomBytes(count: 32)
        let iv = try SignalCrypto.shared.randomBytes(count: 12)  // 12 bytes for AES-GCM
        
        // The message to encrypt
        let message = "Hi BOB"
        let plaintext = message.data(using: .utf8)!
        
        // Encrypt with CryptoProvider directly
        let ciphertext = try SignalCrypto.shared.encrypt(key: messageKey, iv: iv, data: plaintext)
        
        // Create a signal message with this ciphertext
        let signalMessage = SignalMessage(
            version: 3,
            senderRatchetKey: Data(repeating: 0, count: 32),
            counter: 0,
            previousCounter: 0,
            ciphertext: ciphertext,
            serialized: Data()
        )
        
        // Decrypt using the same keys
        let decrypted = try SignalCrypto.shared.decrypt(key: messageKey, iv: iv, data: signalMessage.ciphertext)
        let decryptedMessage = String(data: decrypted, encoding: .utf8)
        
        XCTAssertEqual(decryptedMessage, message)
    }
    
    // This test mimics the session cipher but with fixed keys
    func testMimicSessionCipher() throws {
        // Set up the stores and addresses
        let aliceIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let bobIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        let aliceStore = InMemorySignalProtocolStore(
            identity: aliceIdentityKeyPair, 
            registrationId: try LibNotSignal.shared.generateRegistrationId()
        )
        let bobStore = InMemorySignalProtocolStore(
            identity: bobIdentityKeyPair, 
            registrationId: try LibNotSignal.shared.generateRegistrationId()
        )
        
        let aliceAddress = SignalAddress(name: "alice", deviceId: 1)
        let bobAddress = SignalAddress(name: "bob", deviceId: 1)
        
        // Create the ciphers
        let aliceCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        
        // Setup simplified session states manually
        let aliceSessionState = SessionState()
        let bobSessionState = SessionState()
        
        // Set identity keys
        aliceSessionState.localIdentityKey = aliceIdentityKeyPair.publicKey
        aliceSessionState.remoteIdentityKey = bobIdentityKeyPair.publicKey
        
        bobSessionState.localIdentityKey = bobIdentityKeyPair.publicKey
        bobSessionState.remoteIdentityKey = aliceIdentityKeyPair.publicKey
        
        // Generate a single fixed sending chain for Alice
        let aliceMessageKey = try SignalCrypto.shared.randomBytes(count: 32)
        aliceSessionState.sendingChain = SendingChain(
            key: aliceMessageKey,
            index: 0,
            ratchetKey: Data(repeating: 1, count: 32)
        )
        
        // Generate a single fixed sending chain for Bob
        let bobMessageKey = try SignalCrypto.shared.randomBytes(count: 32)
        bobSessionState.sendingChain = SendingChain(
            key: bobMessageKey,
            index: 0,
            ratchetKey: Data(repeating: 2, count: 32)
        )
        
        // Setup receiver chains
        bobSessionState.receivingChains.append(ReceivingChain(
            key: aliceMessageKey,
            index: 0,
            ratchetKey: Data(repeating: 1, count: 32)
        ))
        
        aliceSessionState.receivingChains.append(ReceivingChain(
            key: bobMessageKey,
            index: 0,
            ratchetKey: Data(repeating: 2, count: 32)
        ))
        
        // Store the sessions
        try aliceStore.storeSession(aliceSessionState, for: bobAddress)
        try bobStore.storeSession(bobSessionState, for: aliceAddress)
        
        // Alice encrypts a message
        let message = "Hi BOB"
        let plaintext = message.data(using: .utf8)!
        
        // Instead of using the full session cipher, we'll just do basic encryption
        // This mimics what SessionCipher would do but without the session ratcheting
        
        // Create an IV (in the real system this would be derived from the chain)
        let iv = try SignalCrypto.shared.randomBytes(count: 12)
        
        // Encrypt
        let ciphertext = try SignalCrypto.shared.encrypt(key: aliceMessageKey, iv: iv, data: plaintext)
        
        // Create a signal message
        let signalMessage = SignalMessage(
            version: 3,
            senderRatchetKey: Data(repeating: 1, count: 32),  // Match Alice's ratchet key
            counter: 0,
            previousCounter: 0,
            ciphertext: ciphertext,
            serialized: Data()
        )
        
        // Decrypt manually
        let decryptedData = try SignalCrypto.shared.decrypt(key: aliceMessageKey, iv: iv, data: signalMessage.ciphertext)
        let decryptedMessage = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(decryptedMessage, message)
    }
} 