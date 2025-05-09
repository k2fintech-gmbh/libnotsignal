import Foundation

public protocol SignedPreKeyStore {
    func loadSignedPreKey(id: UInt32) throws -> SignedPreKeyRecord?
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32) throws
    func containsSignedPreKey(id: UInt32) throws -> Bool
    func removeSignedPreKey(id: UInt32) throws
    func getAllSignedPreKeys() throws -> [SignedPreKeyRecord]
} 