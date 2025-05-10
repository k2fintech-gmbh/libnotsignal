import XCTest
@testable import LibNotSignal

final class IdentityKeyTests: XCTestCase {
    
    func testIdentityKeyGeneration() throws {
        // Test that we can generate identity keys
        let identityKeyPair = try LibNotSignal.shared.generateIdentityKeyPair()
        
        // Verify that the identity key pair has the expected properties
        XCTAssertNotNil(identityKeyPair.publicKey)
        XCTAssertNotNil(identityKeyPair.privateKey)
        
        // Verify that the public key data is available and not empty
        let publicKeyData = identityKeyPair.publicKey
        XCTAssertNotNil(publicKeyData)
        
        // Verify serialization
        let serialized = identityKeyPair.serialize()
        XCTAssertFalse(serialized.isEmpty)
        
        // Verify that we can deserialize (assuming a method might exist)
        // This test would need to be expanded once we know how deserialization works
    }
    
    func testRegistrationIdGeneration() throws {
        // Test registration ID generation
        let registrationId = try LibNotSignal.shared.generateRegistrationId()
        
        // Verify that the registration ID is within the expected range
        XCTAssertGreaterThanOrEqual(registrationId, 1)
        XCTAssertLessThanOrEqual(registrationId, 16380)
    }
    
    func testIdentityKeyComparison() throws {
        // Generate two different identity key pairs
        let identityKeyPair1 = try LibNotSignal.shared.generateIdentityKeyPair()
        let identityKeyPair2 = try LibNotSignal.shared.generateIdentityKeyPair()
        
        // Check that public keys are different
        XCTAssertNotEqual(identityKeyPair1.publicKey.serialize(), identityKeyPair2.publicKey.serialize())
        
        // Different key pairs should generate different public keys
        XCTAssertNotEqual(identityKeyPair1.publicKey.serialize(), identityKeyPair2.publicKey.serialize())
    }
} 