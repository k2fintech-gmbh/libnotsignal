import Foundation
import LibNotSignal

// This program tests the InMemorySignalProtocolStore implementation

// Generate identity key pair and registration ID
let identityKeyPair = try IdentityKeyPair.generate()
let registrationId: UInt32 = 1234

// Create the protocol store
let store = InMemorySignalProtocolStore(identity: identityKeyPair, registrationId: registrationId)

// Test IdentityKeyStore functions
do {
    let retrievedKeyPair = try store.getIdentityKeyPair()
    let retrievedRegId = try store.getLocalRegistrationId()
    
    print("Identity Key Store Test:")
    print("Identity Key Pair matches: \(retrievedKeyPair == identityKeyPair)")
    print("Registration ID matches: \(retrievedRegId == registrationId)")
} catch {
    print("IdentityKeyStore test failed: \(error)")
}

// Test PreKeyStore functions
do {
    let preKeyId: UInt32 = 1
    // Generate a PreKeyRecord directly
    let preKeyRecord = try PreKeyRecord.generate(id: preKeyId)
    
    try store.storePreKey(preKeyRecord, id: preKeyId)
    let containsPreKey = try store.containsPreKey(id: preKeyId)
    let retrievedPreKey = try store.loadPreKey(id: preKeyId)
    
    print("\nPreKey Store Test:")
    print("Contains PreKey: \(containsPreKey)")
    print("Retrieved PreKey matches: \(retrievedPreKey?.id == preKeyId)")
    
    try store.removePreKey(id: preKeyId)
    let containsPreKeyAfterRemoval = try store.containsPreKey(id: preKeyId)
    print("Contains PreKey after removal: \(containsPreKeyAfterRemoval)")
} catch {
    print("PreKeyStore test failed: \(error)")
}

// Test SignedPreKeyStore functions
do {
    let signedPreKeyId: UInt32 = 1
    // Generate a SignedPreKeyRecord directly
    let signedPreKeyRecord = try SignedPreKeyRecord.generate(id: signedPreKeyId, identityKeyPair: identityKeyPair)
    
    try store.storeSignedPreKey(signedPreKeyRecord, id: signedPreKeyId)
    let containsSignedPreKey = try store.containsSignedPreKey(id: signedPreKeyId)
    let retrievedSignedPreKey = try store.loadSignedPreKey(id: signedPreKeyId)
    
    print("\nSigned PreKey Store Test:")
    print("Contains Signed PreKey: \(containsSignedPreKey)")
    print("Retrieved Signed PreKey matches: \(retrievedSignedPreKey?.id == signedPreKeyId)")
    
    try store.removeSignedPreKey(id: signedPreKeyId)
    let containsSignedPreKeyAfterRemoval = try store.containsSignedPreKey(id: signedPreKeyId)
    print("Contains Signed PreKey after removal: \(containsSignedPreKeyAfterRemoval)")
} catch {
    print("SignedPreKeyStore test failed: \(error)")
}

// Test SessionStore functions
do {
    let address = SignalAddress(name: "test", deviceId: 1)
    let sessionState = SessionState()
    sessionState.rootKey = "test-root-key".data(using: .utf8)!
    
    try store.storeSession(sessionState, for: address)
    let containsSession = try store.containsSession(for: address)
    let retrievedSession = try store.loadSession(for: address)
    
    print("\nSession Store Test:")
    print("Contains Session: \(containsSession)")
    print("Retrieved Session matches: \(retrievedSession?.rootKey == sessionState.rootKey)")
    
    try store.deleteSession(for: address)
    let containsSessionAfterRemoval = try store.containsSession(for: address)
    print("Contains Session after removal: \(containsSessionAfterRemoval)")
    
    try store.deleteAllSessions(for: "test")
} catch {
    print("SessionStore test failed: \(error)")
}

print("\nAll tests completed successfully!") 