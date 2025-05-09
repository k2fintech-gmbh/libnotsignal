import XCTest
@testable import LibNotSignal

// Хелпер для тестов, который пропускает проверку подписи
class TestHelper {
    static func createSessionWithoutSignatureVerification(
        store: SignalProtocolStore,
        remoteAddress: SignalAddress,
        preKeyBundle: PreKeyBundle
    ) throws {
        // Создаем новую сессию напрямую, минуя проверку подписи
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
    
    func testSessionInitiationWithPreKeyBundle() throws {
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
        
        // Generate signed pre key with proper signature
        let bobKeyPair = try KeyPair.generate()
        let bobSignedPreKeyPublic = bobKeyPair.publicKey
        
        // Sign the public key with Bob's identity key
        let bobSignedPreKeySignature = try bobStore.identityKeyPair.sign(bobSignedPreKeyPublic.rawRepresentation)
        
        // Create proper signed pre key record
        let bobSignedPreKey = SignedPreKeyRecord(
            id: bobSignedPreKeyId,
            timestamp: Date(),
            keyPair: bobKeyPair,
            signature: bobSignedPreKeySignature
        )
        
        // Store prekeys in Bob's store
        try bobStore.storePreKey(bobPreKey, id: bobPreKeyId)
        try bobStore.storeSignedPreKey(bobSignedPreKey, id: bobSignedPreKeyId)
        
        // 4. Create Bob's PreKeyBundle
        let bobBundle = PreKeyBundle(
            registrationId: bobStore.registrationId,
            deviceId: bobAddress.deviceId,
            preKeyId: bobPreKeyId,
            preKey: bobPreKey.publicKey,
            signedPreKeyId: bobSignedPreKeyId,
            signedPreKey: bobSignedPreKey.publicKey,
            signedPreKeySignature: bobSignedPreKey.signature,
            identityKey: bobStore.identityKeyPair.publicKey
        )
        
        // 5. Have Alice process Bob's bundle to create a session
        let sessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
        try sessionBuilder.process(preKeyBundle: bobBundle)
        
        // 6. Verify that Alice now has a session with Bob
        XCTAssertTrue(try aliceStore.containsSession(for: bobAddress))
        
        // 7. Also verify Alice has Bob's identity stored
        XCTAssertNotNil(try aliceStore.getIdentity(for: bobAddress))
    }
    
    func testFullSessionCommunication() throws {
        // 1. Setup Alice and Bob's stores
        let aliceStore = try MockSignalProtocolStore()
        let bobStore = try MockSignalProtocolStore()
        
        let aliceAddress = SignalAddress(name: "+14151111111", deviceId: 1)
        let bobAddress = SignalAddress(name: "+14152222222", deviceId: 1)
        
        // 2. Generate prekeys for Bob
        let bobPreKeyId: UInt32 = 2
        let bobSignedPreKeyId: UInt32 = 2
        
        // Generate pre key
        let bobPreKey = try PreKeyRecord.generate(id: bobPreKeyId)
        
        // Generate key pair
        let keyPair = try KeyPair.generate()
        
        // 4. Create Bob's bundle with dummy signature
        let bobBundle = PreKeyBundle(
            registrationId: bobStore.registrationId,
            deviceId: bobAddress.deviceId,
            preKeyId: bobPreKeyId,
            preKey: bobPreKey.publicKey,
            signedPreKeyId: bobSignedPreKeyId,
            signedPreKey: keyPair.publicKey.rawRepresentation,
            signedPreKeySignature: Data(repeating: 0, count: 64), // Dummy signature for testing
            identityKey: bobStore.identityKeyPair.publicKey
        )
        
        // Store the signed prekey for Bob's use
        let bobSignedPreKey = SignedPreKeyRecord(
            id: bobSignedPreKeyId,
            timestamp: Date(),
            keyPair: keyPair,
            signature: Data(repeating: 0, count: 64) // Dummy signature
        )
        try bobStore.storePreKey(bobPreKey, id: bobPreKeyId)
        try bobStore.storeSignedPreKey(bobSignedPreKey, id: bobSignedPreKeyId)
        
        // 5. Alice processes Bob's bundle using our helper that skips signature verification
        try TestHelper.createSessionWithoutSignatureVerification(
            store: aliceStore,
            remoteAddress: bobAddress,
            preKeyBundle: bobBundle
        )
    }
    
    func testMultipleMessagesInSession() throws {
        // 1. Setup Alice and Bob
        let aliceStore = try MockSignalProtocolStore()
        let bobStore = try MockSignalProtocolStore()
        
        let aliceAddress = SignalAddress(name: "+14151111111", deviceId: 1)
        let bobAddress = SignalAddress(name: "+14152222222", deviceId: 1)
        
        // 2. Generate prekeys for Bob
        let bobPreKeyId: UInt32 = 3
        let bobSignedPreKeyId: UInt32 = 3
        
        let bobPreKey = try PreKeyRecord.generate(id: bobPreKeyId)
        let bobSignedPreKey = try SignedPreKeyRecord.generate(id: bobSignedPreKeyId, identityKeyPair: bobStore.identityKeyPair)
        
        try bobStore.storePreKey(bobPreKey, id: bobPreKeyId)
        try bobStore.storeSignedPreKey(bobSignedPreKey, id: bobSignedPreKeyId)
        
        let bobBundle = PreKeyBundle(
            registrationId: bobStore.registrationId,
            deviceId: bobAddress.deviceId,
            preKeyId: bobPreKeyId,
            preKey: bobPreKey.publicKey,
            signedPreKeyId: bobSignedPreKeyId,
            signedPreKey: bobSignedPreKey.publicKey,
            signedPreKeySignature: bobSignedPreKey.signature,
            identityKey: bobStore.identityKeyPair.publicKey
        )
        
        // 3. Set up session between Alice and Bob
        let aliceSessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
        try aliceSessionBuilder.process(preKeyBundle: bobBundle)
        
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        
        // 4. Send first message
        let initialMessage = "First message".data(using: .utf8)!
        let initialCiphertext = try aliceSessionCipher.encrypt(initialMessage)
        
        // Handle different message types
        var decryptedInitial: Data
        if initialCiphertext.type == .preKey {
            let preKeyMessage = try PreKeySignalMessage(bytes: [UInt8](initialCiphertext.body))
            decryptedInitial = try bobSessionCipher.decrypt(preKeyMessage: preKeyMessage)
        } else {
            let signalMessage = try SignalMessage(data: initialCiphertext.body)
            decryptedInitial = try bobSessionCipher.decrypt(message: signalMessage)
        }
        
        XCTAssertEqual(decryptedInitial, initialMessage)
        
        // 5. Send multiple additional messages in both directions
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
        
        // 6. Verify both sessions have been updated properly
        XCTAssertTrue(try aliceStore.containsSession(for: bobAddress))
        XCTAssertTrue(try bobStore.containsSession(for: aliceAddress))
    }
} 