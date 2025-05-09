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
    
    public func verifySignature(for message: Data, signature: Data) throws -> Bool {
        return try SignalCrypto.shared.verify(publicKey: publicKey, message: message, signature: signature)
    }
    
    public func serialize() -> Data {
        return publicKey
    }
    
    public static func deserialize(bytes: [UInt8]) throws -> IdentityKey {
        return IdentityKey(publicKey: Data(bytes))
    }
    
    public func getPublicKey() -> PublicKey {
        return PublicKey(rawKey: publicKey)
    }
} 