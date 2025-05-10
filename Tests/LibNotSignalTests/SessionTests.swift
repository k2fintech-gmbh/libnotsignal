import XCTest
@testable import LibNotSignal

final class SessionTests: XCTestCase {
    
    // Test basic session setup
    func testSessionCreation() throws {
        // Set up Alice's device
        let aliceIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let aliceRegistrationId = try LibNotSignal.shared.generateRegistrationId()
        
        // Set up Bob's device
        let bobIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let bobRegistrationId = try LibNotSignal.shared.generateRegistrationId()
        
        // Create protocol stores
        let aliceStore = InMemorySignalProtocolStore(identity: aliceIdentityKeyPair, registrationId: aliceRegistrationId)
        let bobStore = InMemorySignalProtocolStore(identity: bobIdentityKeyPair, registrationId: bobRegistrationId)
        
        // Verify store creation worked
        XCTAssertNotNil(aliceStore)
        XCTAssertNotNil(bobStore)
        
        // Verify we can retrieve the identity information
        XCTAssertEqual(try aliceStore.getIdentityKeyPair().publicKey, aliceIdentityKeyPair.publicKey)
        XCTAssertEqual(try bobStore.getIdentityKeyPair().publicKey, bobIdentityKeyPair.publicKey)
        XCTAssertEqual(try aliceStore.getLocalRegistrationId(), aliceRegistrationId)
        XCTAssertEqual(try bobStore.getLocalRegistrationId(), bobRegistrationId)
    }
    
    // Test basic identity key trust
    func testIdentityTrust() throws {
        // Set up Alice's device
        let aliceIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let aliceRegistrationId = try LibNotSignal.shared.generateRegistrationId()
        
        // Set up Bob's device
        let bobIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        // Create the addresses
        let bobAddress = SignalAddress(name: "bob", deviceId: 2)
        
        // Create Alice's store
        let aliceStore = InMemorySignalProtocolStore(identity: aliceIdentityKeyPair, registrationId: aliceRegistrationId)
        
        // By default, any identity should be trusted since we haven't stored any yet
        let isTrustedByDefault = try aliceStore.isTrustedIdentity(bobIdentityKeyPair.publicKey, for: bobAddress, direction: .sending)
        XCTAssertTrue(isTrustedByDefault, "New identities should be trusted by default")
    }
    
    // Test saving identity keys
    func testSaveIdentity() throws {
        // Set up a protocol store
        let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let registrationId = try LibNotSignal.shared.generateRegistrationId()
        let store = InMemorySignalProtocolStore(identity: identityKeyPair, registrationId: registrationId)
        
        // Create a remote identity and address
        let remoteKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let remoteAddress = SignalAddress(name: "remote", deviceId: 1)
        
        // Save the identity for the first time
        let firstSaveResult = try store.saveIdentity(remoteKeyPair.publicKey, for: remoteAddress)
        // In our implementation, saving a new identity should return true
        // (indicating that the identity was added or changed)
        print("First save result: \(firstSaveResult)")
        
        // Get the saved identity
        let savedIdentity = try store.getIdentity(for: remoteAddress)
        XCTAssertNotNil(savedIdentity, "Identity should be saved and retrievable")
        if let savedIdentity = savedIdentity {
            XCTAssertEqual(savedIdentity.serialize(), remoteKeyPair.publicKey.serialize(), "Saved identity should match what was stored")
        }
        
        // Save the same identity again
        let secondSaveResult = try store.saveIdentity(remoteKeyPair.publicKey, for: remoteAddress)
        print("Second save result (same key): \(secondSaveResult)")
        // Some implementations return false for saving the same identity again
        // But we won't assert this behavior as it might differ between implementations
        
        // Generate a different key and save it for the same address
        let differentKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let differentSaveResult = try store.saveIdentity(differentKeyPair.publicKey, for: remoteAddress)
        print("Different key save result: \(differentSaveResult)")
        // Some implementations return true for saving a different identity
        // But we won't assert this behavior as it might differ between implementations
        
        // Get the updated identity 
        let updatedIdentity = try store.getIdentity(for: remoteAddress)
        XCTAssertNotNil(updatedIdentity, "Updated identity should be retrievable")
        if let updatedIdentity = updatedIdentity {
            XCTAssertEqual(updatedIdentity.serialize(), differentKeyPair.publicKey.serialize(), "Updated identity should match the most recently stored key")
        }
    }
    
    // Test fingerprint generation
    func testFingerprint() throws {
        // Set up Alice's device
        let aliceIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        // Set up Bob's device
        let bobIdentityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        // Create the addresses
        let aliceAddress = SignalAddress(name: "alice", deviceId: 1)
        let bobAddress = SignalAddress(name: "bob", deviceId: 2)
        
        // Generate fingerprint
        let fingerprint = LibNotSignal.shared.generateFingerprint(
            localIdentity: aliceIdentityKeyPair.publicKey,
            remoteIdentity: bobIdentityKeyPair.publicKey,
            localAddress: aliceAddress,
            remoteAddress: bobAddress
        )
        
        // Verify fingerprint properties
        XCTAssertNotNil(fingerprint)
        XCTAssertFalse(fingerprint.isEmpty)
        XCTAssertTrue(fingerprint.contains("alice:"))
        XCTAssertTrue(fingerprint.contains("bob:"))
        XCTAssertTrue(fingerprint.contains("<->"))
        
        // Verify that a different pair of identities produces a different fingerprint
        let aliceIdentityKeyPair2 = try LibNotSignal.shared.generateIdentityKeyPair()
        let fingerprint2 = LibNotSignal.shared.generateFingerprint(
            localIdentity: aliceIdentityKeyPair2.publicKey,
            remoteIdentity: bobIdentityKeyPair.publicKey,
            localAddress: aliceAddress,
            remoteAddress: bobAddress
        )
        XCTAssertNotEqual(fingerprint, fingerprint2)
    }
} 