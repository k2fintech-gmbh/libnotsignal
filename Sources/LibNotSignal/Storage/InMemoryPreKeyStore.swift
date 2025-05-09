import Foundation

public class InMemoryPreKeyStore: PreKeyStore {
    private var store: [UInt32: PreKeyRecord] = [:]
    
    public init() {}
    
    public func loadPreKey(id: UInt32) throws -> PreKeyRecord? {
        return store[id]
    }
    
    public func storePreKey(_ record: PreKeyRecord, id: UInt32) throws {
        store[id] = record
    }
    
    public func containsPreKey(id: UInt32) throws -> Bool {
        return store[id] != nil
    }
    
    public func removePreKey(id: UInt32) throws {
        store.removeValue(forKey: id)
    }
    
    public func getAllPreKeys() throws -> [PreKeyRecord] {
        return Array(store.values)
    }
    
    // Legacy methods with context parameter
    public func loadPreKey(id: UInt32, context: Any?) throws -> PreKeyRecord? {
        return try loadPreKey(id: id)
    }
    
    public func storePreKey(_ record: PreKeyRecord, id: UInt32, context: Any?) throws {
        try storePreKey(record, id: id)
    }
    
    public func containsPreKey(id: UInt32, context: Any?) throws -> Bool {
        return try containsPreKey(id: id)
    }
    
    public func removePreKey(id: UInt32, context: Any?) throws {
        try removePreKey(id: id)
    }
} 