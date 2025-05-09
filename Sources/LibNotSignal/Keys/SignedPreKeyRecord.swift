import Foundation

public struct SignedPreKeyRecord: Codable, Equatable {
    public let id: UInt32
    public let timestamp: UInt64
    public let publicKey: Data
    public let privateKey: Data
    public let signature: Data
    
    public init(id: UInt32, timestamp: UInt64, publicKey: Data, privateKey: Data, signature: Data) {
        self.id = id
        self.timestamp = timestamp
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.signature = signature
    }
    
    public static func generate(id: UInt32, identityKeyPair: IdentityKeyPair, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) throws -> SignedPreKeyRecord {
        let (privateKey, publicKey) = try SignalCrypto.shared.generateKeyPair()
        
        // Sign the public key with the identity key
        let signature = try identityKeyPair.sign(publicKey)
        
        return SignedPreKeyRecord(
            id: id,
            timestamp: timestamp,
            publicKey: publicKey,
            privateKey: privateKey,
            signature: signature
        )
    }
} 