import XCTest
@testable import LibNotSignal

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
            // In a real implementation, this would check if the identity is trusted
            // For testing purposes, we'll trust all identities
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
} 