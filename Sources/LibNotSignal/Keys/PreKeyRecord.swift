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
    
    public init(id: UInt32, publicKey: PublicKey, privateKey: PrivateKey) {
        self.id = id
        
        var publicKeyData = Data()
        publicKey.withUnsafeBytes { buffer in
            publicKeyData.append(contentsOf: buffer)
        }
        self.publicKey = publicKeyData
        
        var privateKeyData = Data()
        privateKey.withUnsafeBytes { buffer in
            privateKeyData.append(contentsOf: buffer)
        }
        self.privateKey = privateKeyData
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
    
    public func serialize() -> Data {
        var result = Data()
        
        var idValue = id
        result.append(contentsOf: withUnsafeBytes(of: &idValue) { Array($0) })
        
        var publicKeyLength = UInt16(publicKey.count)
        result.append(contentsOf: withUnsafeBytes(of: &publicKeyLength) { Array($0) })
        result.append(publicKey)
        
        var privateKeyLength = UInt16(privateKey.count)
        result.append(contentsOf: withUnsafeBytes(of: &privateKeyLength) { Array($0) })
        result.append(privateKey)
        
        return result
    }
    
    public static func deserialize(from bytes: [UInt8]) throws -> PreKeyRecord {
        var offset = 0
        
        guard bytes.count >= offset + 4 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let id = UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
        offset += 4
        
        guard bytes.count >= offset + 2 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let publicKeyLength = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        
        guard bytes.count >= offset + Int(publicKeyLength) else {
            throw LibNotSignalError.invalidSerializedData
        }
        let publicKey = Data(bytes[offset..<offset + Int(publicKeyLength)])
        offset += Int(publicKeyLength)
        
        guard bytes.count >= offset + 2 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let privateKeyLength = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        
        guard bytes.count >= offset + Int(privateKeyLength) else {
            throw LibNotSignalError.invalidSerializedData
        }
        let privateKey = Data(bytes[offset..<offset + Int(privateKeyLength)])
        
        return PreKeyRecord(id: id, publicKey: publicKey, privateKey: privateKey)
    }
    
    // Backward compatibility with Codable - deserialize from Decoder
    public static func deserialize(from decoder: Decoder) throws -> PreKeyRecord {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        return try deserialize(from: [UInt8](data))
    }
    
    public func getPrivateKey() -> PrivateKey {
        return PrivateKey(rawKey: privateKey)
    }
    
    public func getPublicKey() -> PublicKey {
        return PublicKey(rawKey: publicKey)
    }
} 