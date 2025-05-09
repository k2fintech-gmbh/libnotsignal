import Foundation

public struct IdentityKey: Codable, Equatable {
    public let publicKey: Data
    
    public init(publicKey: Data) {
        self.publicKey = publicKey
    }
    
    public func verifySignature(for message: Data, signature: Data) throws -> Bool {
        return try SignalCrypto.shared.verify(publicKey: publicKey, message: message, signature: signature)
    }
} 