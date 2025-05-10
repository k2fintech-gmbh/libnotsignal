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
    
    // Test using session cipher with manually generated IV for MessageKeys
    func testSessionCipherWithDerivedIV() throws {
        // Create a custom crypto provider that always returns a fixed IV
        class FixedIVCryptoProvider: DefaultCryptoProvider {
            let fixedIV: Data
            
            init(fixedIV: Data) {
                self.fixedIV = fixedIV
                super.init(isDebugLoggingEnabled: true)
            }
            
            override public func randomBytes(count: Int) throws -> Data {
                if count == 12 || count == 16 {
                    // This will be used for IV generation
                    return fixedIV
                }
                return try super.randomBytes(count: count)
            }
        }
        
        // Generate a fixed IV
        let fixedIV = Data(repeating: 5, count: 12)
        
        // Set up the crypto provider
        let fixedIVProvider = FixedIVCryptoProvider(fixedIV: fixedIV)
        
        // Replace the default provider with our custom one
        let originalProvider = SignalCrypto.shared.provider
        SignalCrypto.shared.provider = fixedIVProvider
        
        // Clean up after test
        defer {
            // Restore the original provider
            SignalCrypto.shared.provider = originalProvider
        }
        
        // Set up Alice and Bob
        let aliceIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let bobIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        let aliceRegistrationId = try LibNotSignal.shared.generateRegistrationId()
        let bobRegistrationId = try LibNotSignal.shared.generateRegistrationId()
        
        let aliceAddress = SignalAddress(name: "alice", deviceId: 1)
        let bobAddress = SignalAddress(name: "bob", deviceId: 1)
        
        // Create stores
        let aliceStore = InMemorySignalProtocolStore(identity: aliceIdentityKeyPair, registrationId: aliceRegistrationId)
        let bobStore = InMemorySignalProtocolStore(identity: bobIdentityKeyPair, registrationId: bobRegistrationId)
        
        // Create session states
        let aliceSessionState = SessionState()
        let bobSessionState = SessionState()
        
        // Set identity keys
        aliceSessionState.localIdentityKey = aliceIdentityKeyPair.publicKey
        aliceSessionState.remoteIdentityKey = bobIdentityKeyPair.publicKey
        
        bobSessionState.localIdentityKey = bobIdentityKeyPair.publicKey
        bobSessionState.remoteIdentityKey = aliceIdentityKeyPair.publicKey
        
        // Create some fixed keys for testing
        let rootKey = try SignalCrypto.shared.randomBytes(count: 32)
        aliceSessionState.rootKey = rootKey
        bobSessionState.rootKey = rootKey
        
        // Setup Alice's sending chain
        let aliceKeyPair = try KeyPair.generate()
        let aliceChainKey = try SignalCrypto.shared.randomBytes(count: 32)
        aliceSessionState.sendingChain = SendingChain(
            key: aliceChainKey, 
            index: 0, 
            ratchetKey: aliceKeyPair.publicKey.data
        )
        
        // Setup Bob's receiving chain to match Alice's sending chain
        bobSessionState.receivingChains.append(ReceivingChain(
            key: aliceChainKey,
            index: 0,
            ratchetKey: aliceKeyPair.publicKey.data
        ))
        
        // Setup Bob's sending chain
        let bobKeyPair = try KeyPair.generate()
        let bobChainKey = try SignalCrypto.shared.randomBytes(count: 32)
        bobSessionState.sendingChain = SendingChain(
            key: bobChainKey,
            index: 0,
            ratchetKey: bobKeyPair.publicKey.data
        )
        
        // Setup Alice's receiving chain to match Bob's sending chain
        aliceSessionState.receivingChains.append(ReceivingChain(
            key: bobChainKey,
            index: 0,
            ratchetKey: bobKeyPair.publicKey.data
        ))
        
        // Store the sessions
        try aliceStore.storeSession(aliceSessionState, for: bobAddress)
        try bobStore.storeSession(bobSessionState, for: aliceAddress)
        
        // Create ciphers
        let aliceCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)
        
        // Test message
        let message = "Hi BOB"
        let plaintext = message.data(using: .utf8)!
        
        // Alice encrypts a message to Bob
        let ciphertextMessage = try aliceCipher.encrypt(plaintext)
        
        // Bob decrypts the message
        let signalMessage = try SignalMessage(data: ciphertextMessage.body)
        let decrypted = try bobCipher.decrypt(message: signalMessage)
        
        // Verify decryption
        let decryptedText = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual(decryptedText, message)
    }
} 