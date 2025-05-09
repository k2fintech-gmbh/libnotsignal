import Foundation

public struct PreKeyRecord: Codable, Equatable {
    public let id: UInt32
    public let publicKey: Data
    public let privateKey: Data
    
    public init(id: UInt32, publicKey: Data, privateKey: Data) {
        self.id = id
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    public static func generate(id: UInt32) throws -> PreKeyRecord {
        let (privateKey, publicKey) = try SignalCrypto.shared.generateKeyPair()
        return PreKeyRecord(id: id, publicKey: publicKey, privateKey: privateKey)
    }
    
    public static func generatePreKeys(startId: UInt32, count: UInt32) throws -> [PreKeyRecord] {
        var preKeys = [PreKeyRecord]()
        
        for i in 0..<count {
            let preKey = try PreKeyRecord.generate(id: startId + i)
            preKeys.append(preKey)
        }
        
        return preKeys
    }
} 