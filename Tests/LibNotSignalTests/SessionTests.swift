import XCTest
@testable import LibNotSignal

final class SessionTests: XCTestCase {
    var aliceStore: InMemorySignalProtocolStore!
    var bobStore: InMemorySignalProtocolStore!
    var aliceAddress: SignalAddress!
    var bobAddress: SignalAddress!
    
    override func setUp() {
        super.setUp()
        
        // Generate identity keys for Alice and Bob
        let aliceIdentityKeyPair = try! LibNotSignal.shared.generateIdentityKeyPair()
        let bobIdentityKeyPair = try! LibNotSignal.shared.generateIdentityKeyPair()
        
        // Create protocol stores
        aliceStore = InMemorySignalProtocolStore(
            identity: aliceIdentityKeyPair,
            registrationId: try! LibNotSignal.shared.generateRegistrationId()
        )
        
        bobStore = InMemorySignalProtocolStore(
            identity: bobIdentityKeyPair,
            registrationId: try! LibNotSignal.shared.generateRegistrationId()
        )
        
        // Create addresses
        aliceAddress = SignalAddress(name: "alice", deviceId: 1)
        bobAddress = SignalAddress(name: "bob", deviceId: 1)
    }
    
    func testBasicPreKeySession() throws {
        // Generate pre-keys for Bob
        let preKeys = try LibNotSignal.shared.generatePreKeys(start: 1, count: 10)
        let signedPreKey = try LibNotSignal.shared.generateSignedPreKey(
            identityKeyPair: try bobStore.getIdentityKeyPair(),
            id: 1
        )
        
        // Store Bob's pre-keys
        for preKey in preKeys {
            try bobStore.storePreKey(preKey, id: preKey.id)
        }
        try bobStore.storeSignedPreKey(signedPreKey, id: signedPreKey.id)
        
        // Create Bob's pre-key bundle
        let bobPreKeyBundle = PreKeyBundle(
            registrationId: try bobStore.getLocalRegistrationId(),
            deviceId: bobAddress.deviceId,
            preKeyId: preKeys[0].id,
            preKey: preKeys[0].publicKey,
            signedPreKeyId: signedPreKey.id,
            signedPreKey: signedPreKey.publicKey,
            signedPreKeySignature: signedPreKey.signature,
            identityKey: try bobStore.getIdentityKeyPair().publicKey
        )
        
        // Alice processes Bob's pre-key bundle
        let sessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
        try sessionBuilder.process(preKeyBundle: bobPreKeyBundle)
        
        // Verify Alice has a session with Bob
        XCTAssertNotNil(try aliceStore.loadSession(for: bobAddress))
        
        // Alice sends a message to Bob
        let originalMessage = "Hello, Bob!"
        let sessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let encryptedMessage = try sessionCipher.encrypt(originalMessage.data(using: .utf8)!)
        
        // Verify it's a pre-key message
        XCTAssertEqual(encryptedMessage.type, .preKey)
        
        // Convert to PreKeySignalMessage for Bob to decrypt
        let preKeyMessage = try PreKeySignalMessage(bytes: [UInt8](encryptedMessage.body))
        
        // Bob decrypts the message
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        let decryptedMessage = try bobSessionCipher.decrypt(preKeyMessage: preKeyMessage)
        let decryptedText = String(data: decryptedMessage, encoding: .utf8)!
        
        XCTAssertEqual(decryptedText, originalMessage)
        
        // Bob sends a response
        let responseMessage = "Hello, Alice!"
        let encryptedResponse = try bobSessionCipher.encrypt(responseMessage.data(using: .utf8)!)
        
        // Verify it's a regular message
        XCTAssertEqual(encryptedResponse.type, .whisper)
        
        // Convert to SignalMessage for Alice to decrypt
        let signalMessage = try SignalMessage(data: encryptedResponse.body)
        
        // Alice decrypts the response
        let decryptedResponse = try sessionCipher.decrypt(message: signalMessage)
        let decryptedResponseText = String(data: decryptedResponse, encoding: .utf8)!
        
        XCTAssertEqual(decryptedResponseText, responseMessage)
    }
    
    func testSessionPersistence() throws {
        // Set up initial session using pre-keys
        try setupInitialSession()
        
        // Create new stores to simulate app restart
        let newAliceStore = InMemorySignalProtocolStore(
            identity: try aliceStore.getIdentityKeyPair(),
            registrationId: try aliceStore.getLocalRegistrationId()
        )
        let newBobStore = InMemorySignalProtocolStore(
            identity: try bobStore.getIdentityKeyPair(),
            registrationId: try bobStore.getLocalRegistrationId()
        )
        
        // Copy session data to new stores
        if let aliceSession = try aliceStore.loadSession(for: bobAddress) {
            try newAliceStore.storeSession(aliceSession, for: bobAddress)
        }
        if let bobSession = try bobStore.loadSession(for: aliceAddress) {
            try newBobStore.storeSession(bobSession, for: aliceAddress)
        }
        
        // Test message exchange with new stores
        let message = "Message after restart"
        let sessionCipher = SessionCipher(store: newAliceStore, remoteAddress: bobAddress)
        let encryptedMessage = try sessionCipher.encrypt(message.data(using: .utf8)!)
        
        // Convert to SignalMessage for decryption
        let signalMessage = try SignalMessage(data: encryptedMessage.body)
        
        let decryptedMessage = try sessionCipher.decrypt(message: signalMessage)
        let decryptedText = String(data: decryptedMessage, encoding: .utf8)!
        
        XCTAssertEqual(decryptedText, message)
    }
    
    func testSessionReestablishment() throws {
        // Set up initial session
        try setupInitialSession()
        
        // Generate new pre-keys for Bob
        let newPreKeys = try LibNotSignal.shared.generatePreKeys(start: 11, count: 10)
        let newSignedPreKey = try LibNotSignal.shared.generateSignedPreKey(
            identityKeyPair: try bobStore.getIdentityKeyPair(),
            id: 2
        )
        
        // Store new pre-keys
        for preKey in newPreKeys {
            try bobStore.storePreKey(preKey, id: preKey.id)
        }
        try bobStore.storeSignedPreKey(newSignedPreKey, id: newSignedPreKey.id)
        
        // Create new pre-key bundle
        let newPreKeyBundle = PreKeyBundle(
            registrationId: try bobStore.getLocalRegistrationId(),
            deviceId: bobAddress.deviceId,
            preKeyId: newPreKeys[0].id,
            preKey: newPreKeys[0].publicKey,
            signedPreKeyId: newSignedPreKey.id,
            signedPreKey: newSignedPreKey.publicKey,
            signedPreKeySignature: newSignedPreKey.signature,
            identityKey: try bobStore.getIdentityKeyPair().publicKey
        )
        
        // Alice processes new pre-key bundle
        let sessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
        try sessionBuilder.process(preKeyBundle: newPreKeyBundle)
        
        // Test message exchange after reestablishment
        let message = "Message after reestablishment"
        let sessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let encryptedMessage = try sessionCipher.encrypt(message.data(using: .utf8)!)
        
        // Convert to SignalMessage for decryption
        let signalMessage = try SignalMessage(data: encryptedMessage.body)
        
        let decryptedMessage = try sessionCipher.decrypt(message: signalMessage)
        let decryptedText = String(data: decryptedMessage, encoding: .utf8)!
        
        XCTAssertEqual(decryptedText, message)
    }
    
    // Helper method to set up initial session
    private func setupInitialSession() throws {
        let preKeys = try LibNotSignal.shared.generatePreKeys(start: 1, count: 10)
        let signedPreKey = try LibNotSignal.shared.generateSignedPreKey(
            identityKeyPair: try bobStore.getIdentityKeyPair(),
            id: 1
        )
        
        for preKey in preKeys {
            try bobStore.storePreKey(preKey, id: preKey.id)
        }
        try bobStore.storeSignedPreKey(signedPreKey, id: signedPreKey.id)
        
        let preKeyBundle = PreKeyBundle(
            registrationId: try bobStore.getLocalRegistrationId(),
            deviceId: bobAddress.deviceId,
            preKeyId: preKeys[0].id,
            preKey: preKeys[0].publicKey,
            signedPreKeyId: signedPreKey.id,
            signedPreKey: signedPreKey.publicKey,
            signedPreKeySignature: signedPreKey.signature,
            identityKey: try bobStore.getIdentityKeyPair().publicKey
        )
        
        let sessionBuilder = SessionBuilder(store: aliceStore, remoteAddress: bobAddress)
        try sessionBuilder.process(preKeyBundle: preKeyBundle)
    }
} 