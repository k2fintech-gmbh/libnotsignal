import Foundation

public protocol PreKeyStore {
    func loadPreKey(id: UInt32) throws -> PreKeyRecord?
    func storePreKey(_ record: PreKeyRecord, id: UInt32) throws
    func containsPreKey(id: UInt32) throws -> Bool
    func removePreKey(id: UInt32) throws
    func getAllPreKeys() throws -> [PreKeyRecord]
} 