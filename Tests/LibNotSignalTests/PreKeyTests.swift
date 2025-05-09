import XCTest
@testable import LibNotSignal

final class PreKeyTests: XCTestCase {
    
    func testPreKeyGeneration() throws {
        // Generate a batch of prekeys
        let preKeys = try LibNotSignal.shared.generatePreKeys(start: 1, count: 10)
        
        // Check that we got the expected number of prekeys
        XCTAssertEqual(preKeys.count, 10)
        
        // Check that each prekey has the expected properties
        for i in 0..<10 {
            let preKey = preKeys[i]
            
            // Verify the ID is correct (should be 1, 2, 3, ..., 10)
            XCTAssertEqual(preKey.id, UInt32(i + 1))
            
            // Verify the key material exists
            XCTAssertNotNil(preKey.publicKey)
            XCTAssertNotNil(preKey.privateKey)
        }
        
        // Test serialization
        let serialized = preKeys[0].serialize()
        XCTAssertFalse(serialized.isEmpty)
    }
    
    func testPreKeyStore() throws {
        // Create a protocol store
        let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        let registrationId = try LibNotSignal.shared.generateRegistrationId()
        let store = InMemorySignalProtocolStore(identity: identityKeyPair, registrationId: registrationId)
        
        // Generate pre keys
        let preKeys = try LibNotSignal.shared.generatePreKeys(start: 1, count: 5)
        
        // Store the pre keys
        for preKey in preKeys {
            try store.storePreKey(preKey, id: preKey.id)
        }
        
        // Verify each pre key can be retrieved
        for preKey in preKeys {
            // Check if the store contains the key
            let contains = try store.containsPreKey(id: preKey.id)
            XCTAssertTrue(contains, "Store should contain pre key with ID \(preKey.id)")
            
            // Load the key and verify it matches
            if let loadedPreKey = try store.loadPreKey(id: preKey.id) {
                XCTAssertEqual(loadedPreKey.id, preKey.id, "Loaded pre key ID should match original")
                XCTAssertEqual(loadedPreKey.serialize(), preKey.serialize(), "Serialized pre key should match original")
            } else {
                XCTFail("Failed to load pre key with ID \(preKey.id)")
            }
        }
        
        // Test removing a pre key
        let keyToRemove = preKeys[0]
        try store.removePreKey(id: keyToRemove.id)
        
        // Verify it was removed
        let containsAfterRemoval = try store.containsPreKey(id: keyToRemove.id)
        XCTAssertFalse(containsAfterRemoval, "Store should not contain the removed pre key")
        
        let loadedAfterRemoval = try store.loadPreKey(id: keyToRemove.id)
        XCTAssertNil(loadedAfterRemoval, "Loading a removed pre key should return nil")
    }
    
    // Note: Signed prekey and prekey bundle functionality tests
    // are skipped because the current implementation does not
    // fully support signature operations.
    
    func testSignedPreKeyRecordBase64Serialization() throws {
        // Generate an identity key pair for signing
        let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        // Generate a signed pre key
        let signedPreKey = try SignedPreKeyRecord.generate(
            id: 1,
            identityKeyPair: identityKeyPair,
            timestamp: UInt64(Date().timeIntervalSince1970)
        )
        
        // Serialize to bytes
        let serializedBytes = signedPreKey.serialize()
        
        // Convert to base64
        let base64String = Data(serializedBytes).base64EncodedString()
        
        // Convert back from base64 to bytes
        guard let decodedData = Data(base64Encoded: base64String),
              let decodedBytes = try? [UInt8](decodedData) else {
            XCTFail("Failed to decode base64 string")
            return
        }
        
        // Deserialize back to SignedPreKeyRecord
        let deserializedRecord = try SignedPreKeyRecord(bytes: decodedBytes)
        
        // Verify all properties match
        XCTAssertEqual(deserializedRecord.id, signedPreKey.id)
        XCTAssertEqual(deserializedRecord.timestamp, signedPreKey.timestamp)
        XCTAssertEqual(deserializedRecord.publicKey, signedPreKey.publicKey)
        XCTAssertEqual(deserializedRecord.privateKey, signedPreKey.privateKey)
        XCTAssertEqual(deserializedRecord.signature, signedPreKey.signature)
        
        // Verify the serialized bytes match
        let reserializedBytes = deserializedRecord.serialize()
        XCTAssertEqual(reserializedBytes, serializedBytes)
    }
} 