import Foundation

public class InMemorySignalProtocolStore: SignalProtocolStore, IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore {
    private var preKeyStore: InMemoryPreKeyStore
    private var signedPreKeyStore: InMemorySignedPreKeyStore
    private var sessionStore: InMemorySessionStore
    private var identityStore: InMemoryIdentityKeyStore
    
    public init(identity: IdentityKeyPair, registrationId: UInt32) {
        self.preKeyStore = InMemoryPreKeyStore()
        self.signedPreKeyStore = InMemorySignedPreKeyStore()
        self.sessionStore = InMemorySessionStore()
        self.identityStore = InMemoryIdentityKeyStore(identityKeyPair: identity, registrationId: registrationId)
    }
    
    // MARK: - PreKeyStore Protocol Implementation
    
    public func loadPreKey(id: UInt32) throws -> PreKeyRecord? {
        return try preKeyStore.loadPreKey(id: id, context: nil)
    }
    
    public func storePreKey(_ record: PreKeyRecord, id: UInt32) throws {
        try preKeyStore.storePreKey(record, id: id, context: nil)
    }
    
    public func containsPreKey(id: UInt32) throws -> Bool {
        return try preKeyStore.containsPreKey(id: id, context: nil)
    }
    
    public func removePreKey(id: UInt32) throws {
        try preKeyStore.removePreKey(id: id, context: nil)
    }
    
    public func getAllPreKeys() throws -> [PreKeyRecord] {
        // Implementation needed
        return []
    }
    
    // MARK: - SignedPreKeyStore Protocol Implementation
    
    public func loadSignedPreKey(id: UInt32) throws -> SignedPreKeyRecord? {
        return try signedPreKeyStore.loadSignedPreKey(id: id, context: nil)
    }
    
    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32) throws {
        try signedPreKeyStore.storeSignedPreKey(record, id: id, context: nil)
    }
    
    public func containsSignedPreKey(id: UInt32) throws -> Bool {
        return try signedPreKeyStore.containsSignedPreKey(id: id, context: nil)
    }
    
    public func removeSignedPreKey(id: UInt32) throws {
        try signedPreKeyStore.removeSignedPreKey(id: id, context: nil)
    }
    
    public func getAllSignedPreKeys() throws -> [SignedPreKeyRecord] {
        // Implementation needed
        return []
    }
    
    // MARK: - SessionStore Protocol Implementation
    
    public func loadSession(for address: SignalAddress) throws -> SessionState? {
        let protocolAddress = ProtocolAddress(from: address)
        if let sessionRecord = try sessionStore.loadSession(for: protocolAddress, context: nil) {
            // Return the session state from the session record
            return sessionRecord.sessionState
        }
        return nil
    }
    
    public func storeSession(_ session: SessionState, for address: SignalAddress) throws {
        let protocolAddress = ProtocolAddress(from: address)
        // Create a new SessionRecord with the provided SessionState
        let sessionRecord = SessionRecord(sessionState: session)
        try sessionStore.storeSession(sessionRecord, for: protocolAddress, context: nil)
    }
    
    public func containsSession(for address: SignalAddress) throws -> Bool {
        let protocolAddress = ProtocolAddress(from: address)
        return try sessionStore.containsSession(for: protocolAddress, context: nil)
    }
    
    public func deleteSession(for address: SignalAddress) throws {
        let protocolAddress = ProtocolAddress(from: address)
        try sessionStore.deleteSession(for: protocolAddress, context: nil)
    }
    
    public func deleteAllSessions(for name: String) throws {
        try sessionStore.deleteAllSessions(for: name, context: nil)
    }
    
    public func getAllAddresses() throws -> [SignalAddress] {
        // Implementation needed
        // This would typically convert from ProtocolAddress to SignalAddress
        return []
    }
    
    // MARK: - IdentityKeyStore Protocol Implementation
    
    public func getIdentityKeyPair() throws -> IdentityKeyPair {
        return try identityStore.getIdentityKeyPair(context: nil)
    }
    
    public func getLocalRegistrationId() throws -> UInt32 {
        return try identityStore.getLocalRegistrationId(context: nil)
    }
    
    public func saveIdentity(_ identity: IdentityKey, for address: SignalAddress) throws -> Bool {
        let protocolAddress = ProtocolAddress(from: address)
        return try identityStore.saveIdentity(identity, for: protocolAddress, context: nil)
    }
    
    public func isTrustedIdentity(_ identity: IdentityKey, for address: SignalAddress, direction: Direction) throws -> Bool {
        let protocolAddress = ProtocolAddress(from: address)
        return try identityStore.isTrustedIdentity(identity, for: protocolAddress, direction: direction, context: nil)
    }
    
    public func getIdentity(for address: SignalAddress) throws -> IdentityKey? {
        let protocolAddress = ProtocolAddress(from: address)
        return try identityStore.identity(for: protocolAddress, context: nil)
    }
    
    // MARK: - Original implementation with context parameter (for compatibility with SignalProtocolStore)
    
    public func loadPreKey(id: UInt32, context: Any?) throws -> PreKeyRecord? {
        return try preKeyStore.loadPreKey(id: id, context: context)
    }
    
    public func storePreKey(_ record: PreKeyRecord, id: UInt32, context: Any?) throws {
        try preKeyStore.storePreKey(record, id: id, context: context)
    }
    
    public func containsPreKey(id: UInt32, context: Any?) throws -> Bool {
        return try preKeyStore.containsPreKey(id: id, context: context)
    }
    
    public func removePreKey(id: UInt32, context: Any?) throws {
        try preKeyStore.removePreKey(id: id, context: context)
    }
    
    public func loadSignedPreKey(id: UInt32, context: Any?) throws -> SignedPreKeyRecord? {
        return try signedPreKeyStore.loadSignedPreKey(id: id, context: context)
    }
    
    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: Any?) throws {
        try signedPreKeyStore.storeSignedPreKey(record, id: id, context: context)
    }
    
    public func containsSignedPreKey(id: UInt32, context: Any?) throws -> Bool {
        return try signedPreKeyStore.containsSignedPreKey(id: id, context: context)
    }
    
    public func removeSignedPreKey(id: UInt32, context: Any?) throws {
        try signedPreKeyStore.removeSignedPreKey(id: id, context: context)
    }
    
    public func loadSession(for address: ProtocolAddress, context: Any?) throws -> SessionRecord? {
        return try sessionStore.loadSession(for: address, context: context)
    }
    
    public func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: Any?) throws {
        try sessionStore.storeSession(record, for: address, context: context)
    }
    
    public func containsSession(for address: ProtocolAddress, context: Any?) throws -> Bool {
        return try sessionStore.containsSession(for: address, context: context)
    }
    
    public func deleteSession(for address: ProtocolAddress, context: Any?) throws {
        try sessionStore.deleteSession(for: address, context: context)
    }
    
    public func deleteAllSessions(for name: String, context: Any?) throws {
        try sessionStore.deleteAllSessions(for: name, context: context)
    }
    
    public func getIdentityKeyPair(context: Any?) throws -> IdentityKeyPair {
        return try identityStore.getIdentityKeyPair(context: context)
    }
    
    public func getLocalRegistrationId(context: Any?) throws -> UInt32 {
        return try identityStore.getLocalRegistrationId(context: context)
    }
    
    public func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: Any?) throws -> Bool {
        return try identityStore.saveIdentity(identity, for: address, context: context)
    }
    
    public func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: Any?) throws -> Bool {
        return try identityStore.isTrustedIdentity(identity, for: address, direction: direction, context: context)
    }
    
    public func identity(for address: ProtocolAddress, context: Any?) throws -> IdentityKey? {
        return try identityStore.identity(for: address, context: context)
    }
    
    // MARK: - KyberPreKeyStore (empty implementation for compatibility)
    
    public func loadKyberPreKey(id: UInt32, context: Any?) throws -> Any? {
        return nil
    }
    
    public func storeKyberPreKey(_ record: Any, id: UInt32, context: Any?) throws {
        // No implementation needed
    }
    
    public func containsKyberPreKey(id: UInt32, context: Any?) throws -> Bool {
        return false
    }
    
    public func removeKyberPreKey(id: UInt32, context: Any?) throws {
        // No implementation needed
    }
    
    public func markKyberPreKeyUsed(id: UInt32, context: Any?) throws {
        // No implementation needed
    }
} 