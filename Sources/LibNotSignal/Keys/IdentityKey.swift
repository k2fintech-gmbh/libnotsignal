import Foundation

public struct IdentityKey: Codable, Equatable {
    public let publicKey: Data
    
    public init(publicKey: Data) {
        self.publicKey = publicKey
    }
    
    public init(publicKey: PublicKey) {
        var publicKeyData = Data()
        publicKey.withUnsafeBytes { buffer in
            publicKeyData.append(contentsOf: buffer)
        }
        self.publicKey = publicKeyData
    }
    
    public init(bytes: [UInt8]) throws {
        let deserialized = try Self.deserialize(bytes: bytes)
        self.init(publicKey: deserialized.publicKey)
    }
    
    public func verifySignature(for message: Data, signature: Data) throws -> Bool {
        return try SignalCrypto.shared.verify(publicKey: publicKey, message: message, signature: signature)
    }
    
    public func serialize() -> Data {
        return publicKey
    }
    
    public static func deserialize(bytes: [UInt8]) throws -> IdentityKey {
        return IdentityKey(publicKey: Data(bytes))
    }
    
    // Backward compatibility with Codable - deserialize from Decoder
    public static func deserialize(from decoder: Decoder) throws -> IdentityKey {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        return try deserialize(bytes: [UInt8](data))
    }
    
    public func getPublicKey() -> PublicKey {
        return PublicKey(rawKey: publicKey)
    }
} 