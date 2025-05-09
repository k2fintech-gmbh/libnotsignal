import Foundation

public class InMemorySignedPreKeyStore: SignedPreKeyStore {
    private var store: [UInt32: SignedPreKeyRecord] = [:]
    
    public init() {}
    
    public func loadSignedPreKey(id: UInt32) throws -> SignedPreKeyRecord? {
        return store[id]
    }
    
    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32) throws {
        store[id] = record
    }
    
    public func containsSignedPreKey(id: UInt32) throws -> Bool {
        return store[id] != nil
    }
    
    public func removeSignedPreKey(id: UInt32) throws {
        store.removeValue(forKey: id)
    }
    
    public func getAllSignedPreKeys() throws -> [SignedPreKeyRecord] {
        return Array(store.values)
    }
    
    // Legacy methods with context parameter
    public func loadSignedPreKey(id: UInt32, context: Any?) throws -> SignedPreKeyRecord? {
        return try loadSignedPreKey(id: id)
    }
    
    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: Any?) throws {
        try storeSignedPreKey(record, id: id)
    }
    
    public func containsSignedPreKey(id: UInt32, context: Any?) throws -> Bool {
        return try containsSignedPreKey(id: id)
    }
    
    public func removeSignedPreKey(id: UInt32, context: Any?) throws {
        try removeSignedPreKey(id: id)
    }
} 