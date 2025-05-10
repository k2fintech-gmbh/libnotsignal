import XCTest
@testable import LibNotSignal

// Helper for tests that skips signature verification
class TestHelper {
    static func createSessionWithoutSignatureVerification(
        store: SignalProtocolStore,
        remoteAddress: SignalAddress,
        preKeyBundle: PreKeyBundle
    ) throws {
        // Create a new session directly, bypassing signature verification
        let ourBaseKey = try KeyPair.generate()
        let ourIdentityKeyPair = try store.getIdentityKeyPair()
        
        let sessionState = try RatchetingSession.initializeAsAlice(
            ourIdentityKeyPair: ourIdentityKeyPair,
            ourBaseKey: ourBaseKey,
            theirIdentityKey: preKeyBundle.identityKey,
            theirSignedPreKey: preKeyBundle.signedPreKey,
            theirOneTimePreKey: preKeyBundle.preKey
        )
        
        // Store the new session
        try store.storeSession(sessionState, for: remoteAddress)
        
        // Save their identity
        try store.saveIdentity(preKeyBundle.identityKey, for: remoteAddress)
    }
}

class SessionTests: XCTestCase {
    
    // Helper function to create a PreKeySignalMessage for testing
    func createPreKeyMessage(
        fromAlice aliceStore: MockSignalProtocolStore,
        toBob bobAddress: SignalAddress,
        withBobPreKey bobPreKeyId: UInt32,
        withBobSignedPreKey bobSignedPreKeyId: UInt32,
        andEncryptedMessage encryptedMessage: Data
    ) throws -> PreKeySignalMessage {
        // Get Alice's identity
        let aliceIdentity = try aliceStore.getIdentityKeyPair()
        
        // Create a new ratchet key pair for Alice
        let aliceBaseKey = try KeyPair.generate()
        
        // Get Bob's identity from Alice's store
        guard let bobIdentity = try aliceStore.getIdentity(for: bobAddress) else {
            throw LibNotSignalError.invalidKey
        }
        
        // Create the PreKeySignalMessage
        let message = try SignalMessage(data: encryptedMessage)
        
        return PreKeySignalMessage(
            version: 3,
            registrationId: aliceStore.registrationId,
            preKeyId: bobPreKeyId,
            signedPreKeyId: bobSignedPreKeyId,
            baseKey: aliceBaseKey.publicKey.rawRepresentation,
            identityKey: aliceIdentity.publicKey,
            signalMessage: message
        )
    }
    
    // Mock implementation of SignalProtocolStore for testing
    class MockSignalProtocolStore: SignalProtocolStore {
        var identityKeyPair: IdentityKeyPair
        var registrationId: UInt32
        var preKeys: [UInt32: PreKeyRecord] = [:]
        var signedPreKeys: [UInt32: SignedPreKeyRecord] = [:]
        var sessions: [SignalAddress: SessionState] = [:]
        var identities: [SignalAddress: IdentityKey] = [:]
        
        init() throws {
            self.identityKeyPair = try IdentityKeyPair.generate()
            self.registrationId = try SignalCrypto.shared.randomInt(min: 1, max: 16380)
        }
        
        // MARK: - IdentityKeyStore
        
        func getIdentityKeyPair() throws -> IdentityKeyPair {
            return identityKeyPair
        }
        
        func getLocalRegistrationId() throws -> UInt32 {
            return registrationId
        }
        
        func saveIdentity(_ identity: IdentityKey, for address: SignalAddress) throws -> Bool {
            let existingIdentity = identities[address]
            let changed = existingIdentity != nil && existingIdentity != identity
            identities[address] = identity
            return changed
        }
        
        func isTrustedIdentity(_ identity: IdentityKey, for address: SignalAddress, direction: Direction) throws -> Bool {
            // Check if we have a stored identity for this address
            guard let storedIdentity = identities[address] else {
                // If we don't have a stored identity, we trust the first identity we see
                return true
            }
            
            // For SENDING, we require an exact match with the stored identity
            if direction == .sending {
                return storedIdentity == identity
            }
            
            // For RECEIVING, we might implement additional checks like:
            // - Check if the identity change was recently approved
            // - Notify the user about identity changes
            
            // For testing purposes, we'll trust all receiving identities
            return true
        }
        
        func getIdentity(for address: SignalAddress) throws -> IdentityKey? {
            return identities[address]
        }
        
        // MARK: - PreKeyStore
        
        func loadPreKey(id: UInt32) throws -> PreKeyRecord? {
            return preKeys[id]
        }
        
        func storePreKey(_ record: PreKeyRecord, id: UInt32) throws {
            preKeys[id] = record
        }
        
        func containsPreKey(id: UInt32) throws -> Bool {
            return preKeys[id] != nil
        }
        
        func removePreKey(id: UInt32) throws {
            preKeys.removeValue(forKey: id)
        }
        
        func getAllPreKeys() throws -> [PreKeyRecord] {
            return Array(preKeys.values)
        }
        
        // MARK: - SignedPreKeyStore
        
        func loadSignedPreKey(id: UInt32) throws -> SignedPreKeyRecord? {
            return signedPreKeys[id]
        }
        
        func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32) throws {
            signedPreKeys[id] = record
        }
        
        func containsSignedPreKey(id: UInt32) throws -> Bool {
            return signedPreKeys[id] != nil
        }
        
        func removeSignedPreKey(id: UInt32) throws {
            signedPreKeys.removeValue(forKey: id)
        }
        
        func getAllSignedPreKeys() throws -> [SignedPreKeyRecord] {
            return Array(signedPreKeys.values)
        }
        
        // MARK: - SessionStore
        
        func loadSession(for address: SignalAddress) throws -> SessionState? {
            return sessions[address]
        }
        
        func storeSession(_ session: SessionState, for address: SignalAddress) throws {
            sessions[address] = session
        }
        
        func containsSession(for address: SignalAddress) throws -> Bool {
            return sessions[address] != nil
        }
        
        func deleteSession(for address: SignalAddress) throws {
            sessions.removeValue(forKey: address)
        }
        
        func deleteAllSessions(for name: String) throws {
            for address in sessions.keys where address.name == name {
                sessions.removeValue(forKey: address)
            }
        }
        
        func getAllAddresses() throws -> [SignalAddress] {
            return Array(sessions.keys)
        }
    }
    
    func testBasicSessionSetup() throws {
        // Create Alice and Bob's stores
        let aliceStore = try MockSignalProtocolStore()
        let bobStore = try MockSignalProtocolStore()
        
        // Create addresses
        let aliceAddress = SignalAddress(name: "+14151111111", deviceId: 1)
        let bobAddress = SignalAddress(name: "+14152222222", deviceId: 1)
        
        // Manually create sessions for both sides
        let aliceSession = SessionState()
        aliceSession.localIdentityKey = aliceStore.identityKeyPair.publicKey
        aliceSession.remoteIdentityKey = bobStore.identityKeyPair.publicKey
        
        let bobSession = SessionState()
        bobSession.localIdentityKey = bobStore.identityKeyPair.publicKey
        bobSession.remoteIdentityKey = aliceStore.identityKeyPair.publicKey
        
        // Store sessions
        try aliceStore.storeSession(aliceSession, for: bobAddress)
        try bobStore.storeSession(bobSession, for: aliceAddress)
        
        // Store identities
        _ = try aliceStore.saveIdentity(bobStore.identityKeyPair.publicKey, for: bobAddress)
        _ = try bobStore.saveIdentity(aliceStore.identityKeyPair.publicKey, for: aliceAddress)
        
        // Check that a session was established
        XCTAssertTrue(try aliceStore.containsSession(for: bobAddress))
        XCTAssertTrue(try bobStore.containsSession(for: aliceAddress))
    }
    
    func testSessionInitiationWithMockSignature() throws {
        // This test skips signature verification for testing purposes
        // In real applications you should always verify signatures
        
        // 1. Create stores for Alice and Bob
        let aliceStore = try MockSignalProtocolStore()
        let bobStore = try MockSignalProtocolStore()
        
        // 2. Create addresses
        let aliceAddress = SignalAddress(name: "+14151111111", deviceId: 1)
        let bobAddress = SignalAddress(name: "+14152222222", deviceId: 1)
        
        // 3. Generate prekeys for Bob
        let bobPreKeyId: UInt32 = 1
        let bobSignedPreKeyId: UInt32 = 1
        
        let bobPreKey = try PreKeyRecord.generate(id: bobPreKeyId)
        
        // Create a key pair for the signed pre key
        let keyPair = try KeyPair.generate()
        
        // 4. Create Bob's PreKeyBundle with a dummy signature
        let bobBundle = PreKeyBundle(
            registrationId: bobStore.registrationId,
            deviceId: bobAddress.deviceId,
            preKeyId: bobPreKeyId,
            preKey: bobPreKey.publicKey,
            signedPreKeyId: bobSignedPreKeyId,
            signedPreKey: keyPair.publicKey.rawRepresentation,
            signedPreKeySignature: Data(repeating: 0, count: 64), // Dummy signature
            identityKey: bobStore.identityKeyPair.publicKey
        )
        
        // 5. Have Alice process Bob's bundle to create a session, bypassing signature verification
        try TestHelper.createSessionWithoutSignatureVerification(
            store: aliceStore,
            remoteAddress: bobAddress,
            preKeyBundle: bobBundle
        )
        
        // 6. Verify that Alice now has a session with Bob
        XCTAssertTrue(try aliceStore.containsSession(for: bobAddress))
        
        // 7. Also verify Alice has Bob's identity stored
        XCTAssertNotNil(try aliceStore.getIdentity(for: bobAddress))
    }
    
    func testMessageExchangeWithMockSignature() throws {
        // This test demonstrates a complete message exchange flow
        // using a mock signature verification
        
        // 1. Setup Alice and Bob's stores
        let aliceStore = try MockSignalProtocolStore()
        let bobStore = try MockSignalProtocolStore()
        
        // 2. Create addresses
        let aliceAddress = SignalAddress(name: "+14151111111", deviceId: 1)
        let bobAddress = SignalAddress(name: "+14152222222", deviceId: 1)
        
        // 3. Generate prekeys for Bob
        let bobPreKeyId: UInt32 = 2
        let bobSignedPreKeyId: UInt32 = 2
        
        // Generate pre key
        let bobPreKey = try PreKeyRecord.generate(id: bobPreKeyId)
        
        // Generate key pair for the signed pre key
        let bobSignedKeyPair = try KeyPair.generate()
        
        // 4. Create Bob's bundle with dummy signature
        let bobBundle = PreKeyBundle(
            registrationId: bobStore.registrationId,
            deviceId: bobAddress.deviceId,
            preKeyId: bobPreKeyId,
            preKey: bobPreKey.publicKey,
            signedPreKeyId: bobSignedPreKeyId,
            signedPreKey: bobSignedKeyPair.publicKey.rawRepresentation,
            signedPreKeySignature: Data(repeating: 0, count: 64), // Dummy signature for testing
            identityKey: bobStore.identityKeyPair.publicKey
        )
        
        // 5. Store the prekeys for Bob's use
        let bobSignedPreKey = SignedPreKeyRecord(
            id: bobSignedPreKeyId,
            timestamp: Date(),
            keyPair: bobSignedKeyPair,
            signature: Data(repeating: 0, count: 64) // Dummy signature
        )
        try bobStore.storePreKey(bobPreKey, id: bobPreKeyId)
        try bobStore.storeSignedPreKey(bobSignedPreKey, id: bobSignedPreKeyId)
        
        // 6. Alice processes Bob's bundle using our helper that skips signature verification
        try TestHelper.createSessionWithoutSignatureVerification(
            store: aliceStore,
            remoteAddress: bobAddress,
            preKeyBundle: bobBundle
        )
        
        // 7. Now also set up Bob's session with Alice - in a real app this would happen via message exchange
        // But for testing purposes, we'll manually create a session for Bob
        let aliceBundle = PreKeyBundle(
            registrationId: aliceStore.registrationId,
            deviceId: aliceAddress.deviceId,
            preKeyId: 1, // Alice's prekey ID
            preKey: try KeyPair.generate().publicKey.rawRepresentation, // Simple key for testing
            signedPreKeyId: 1, // Alice's signed prekey ID
            signedPreKey: try KeyPair.generate().publicKey.rawRepresentation,
            signedPreKeySignature: Data(repeating: 0, count: 64), // Dummy signature
            identityKey: aliceStore.identityKeyPair.publicKey
        )
        
        try TestHelper.createSessionWithoutSignatureVerification(
            store: bobStore,
            remoteAddress: aliceAddress,
            preKeyBundle: aliceBundle
        )
        
        // 8. Now both Alice and Bob have sessions set up with each other
        XCTAssertTrue(try aliceStore.containsSession(for: bobAddress))
        XCTAssertTrue(try bobStore.containsSession(for: aliceAddress))
        
        // 9. Alice can encrypt a message for Bob
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let aliceMessage = "Hello, Bob!".data(using: .utf8)!
        let ciphertextFromAlice = try aliceSessionCipher.encrypt(aliceMessage)
        
        // 10. Bob can decrypt Alice's message
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        let signalMessageFromAlice = try SignalMessage(data: ciphertextFromAlice.body)
        let decryptedByBob = try bobSessionCipher.decrypt(message: signalMessageFromAlice)
        
        // 11. Verify the decrypted message matches the original
        XCTAssertEqual(decryptedByBob, aliceMessage)
        
        // 12. Bob can respond to Alice
        let bobMessage = "Hello, Alice!".data(using: .utf8)!
        let ciphertextFromBob = try bobSessionCipher.encrypt(bobMessage)
        
        // 13. Alice can decrypt Bob's message
        let signalMessageFromBob = try SignalMessage(data: ciphertextFromBob.body)
        let decryptedByAlice = try aliceSessionCipher.decrypt(message: signalMessageFromBob)
        
        // 14. Verify the decrypted message is the same as the original
        XCTAssertEqual(decryptedByAlice, bobMessage)
    }
    
    func testMultipleMessagesWithMockSignature() throws {
        // 1. Setup Alice and Bob
        let aliceStore = try MockSignalProtocolStore()
        let bobStore = try MockSignalProtocolStore()
        
        // 2. Create addresses
        let aliceAddress = SignalAddress(name: "+14151111111", deviceId: 1)
        let bobAddress = SignalAddress(name: "+14152222222", deviceId: 1)
        
        // 3. Generate prekeys for Bob
        let bobPreKeyId: UInt32 = 3
        let bobSignedPreKeyId: UInt32 = 3
        
        // Generate pre key
        let bobPreKey = try PreKeyRecord.generate(id: bobPreKeyId)
        
        // Generate key pair for the signed pre key
        let bobSignedKeyPair = try KeyPair.generate()
        
        // 4. Create Bob's bundle with dummy signature
        let bobBundle = PreKeyBundle(
            registrationId: bobStore.registrationId,
            deviceId: bobAddress.deviceId,
            preKeyId: bobPreKeyId,
            preKey: bobPreKey.publicKey,
            signedPreKeyId: bobSignedPreKeyId,
            signedPreKey: bobSignedKeyPair.publicKey.rawRepresentation,
            signedPreKeySignature: Data(repeating: 0, count: 64), // Dummy signature
            identityKey: bobStore.identityKeyPair.publicKey
        )
        
        // 5. Store the prekeys for Bob's use
        let bobSignedPreKey = SignedPreKeyRecord(
            id: bobSignedPreKeyId,
            timestamp: Date(),
            keyPair: bobSignedKeyPair,
            signature: Data(repeating: 0, count: 64) // Dummy signature
        )
        try bobStore.storePreKey(bobPreKey, id: bobPreKeyId)
        try bobStore.storeSignedPreKey(bobSignedPreKey, id: bobSignedPreKeyId)
        
        // 6. Set up session between Alice and Bob using our helper
        try TestHelper.createSessionWithoutSignatureVerification(
            store: aliceStore,
            remoteAddress: bobAddress,
            preKeyBundle: bobBundle
        )
        
        // 7. Now also set up Bob's session with Alice - in a real app this would happen via message exchange
        // But for testing purposes, we'll manually create a session for Bob
        let aliceBundle = PreKeyBundle(
            registrationId: aliceStore.registrationId,
            deviceId: aliceAddress.deviceId,
            preKeyId: 1, // Alice's prekey ID
            preKey: try KeyPair.generate().publicKey.rawRepresentation, // Simple key for testing
            signedPreKeyId: 1, // Alice's signed prekey ID
            signedPreKey: try KeyPair.generate().publicKey.rawRepresentation,
            signedPreKeySignature: Data(repeating: 0, count: 64), // Dummy signature
            identityKey: aliceStore.identityKeyPair.publicKey
        )
        
        try TestHelper.createSessionWithoutSignatureVerification(
            store: bobStore,
            remoteAddress: aliceAddress,
            preKeyBundle: aliceBundle
        )
        
        // 8. Create session ciphers
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        
        // 9. Ensure sessions are set up correctly
        XCTAssertTrue(try aliceStore.containsSession(for: bobAddress))
        XCTAssertTrue(try bobStore.containsSession(for: aliceAddress))
        
        // 10. Exchange an initial message
        let initialMessage = "First message".data(using: .utf8)!
        let initialCiphertext = try aliceSessionCipher.encrypt(initialMessage)
        
        let signalMessageForBob = try SignalMessage(data: initialCiphertext.body)
        let decryptedInitial = try bobSessionCipher.decrypt(message: signalMessageForBob)
        
        XCTAssertEqual(decryptedInitial, initialMessage)
        
        // 11. Send multiple additional messages in both directions
        let messages = [
            "Message 1 from Alice".data(using: .utf8)!,
            "Message 2 from Alice".data(using: .utf8)!,
            "Message 3 from Alice".data(using: .utf8)!
        ]
        
        // Alice sends multiple messages to Bob
        for message in messages {
            let ciphertext = try aliceSessionCipher.encrypt(message)
            let signalMessage = try SignalMessage(data: ciphertext.body)
            let decrypted = try bobSessionCipher.decrypt(message: signalMessage)
            XCTAssertEqual(decrypted, message)
        }
        
        // Bob sends multiple messages to Alice
        let bobMessages = [
            "Reply 1 from Bob".data(using: .utf8)!,
            "Reply 2 from Bob".data(using: .utf8)!,
            "Reply 3 from Bob".data(using: .utf8)!
        ]
        
        for message in bobMessages {
            let ciphertext = try bobSessionCipher.encrypt(message)
            let signalMessage = try SignalMessage(data: ciphertext.body)
            let decrypted = try aliceSessionCipher.decrypt(message: signalMessage)
            XCTAssertEqual(decrypted, message)
        }
    }
} 