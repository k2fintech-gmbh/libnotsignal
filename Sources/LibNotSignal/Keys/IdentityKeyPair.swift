import Foundation

public struct IdentityKeyPair: Codable, Equatable {
    public let publicKey: IdentityKey
    public let privateKey: Data
    
    public init(publicKey: IdentityKey, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    public static func generate() throws -> IdentityKeyPair {
        let (privateKey, publicKey) = try SignalCrypto.shared.generateKeyPair()
        let identityKey = IdentityKey(publicKey: publicKey)
        return IdentityKeyPair(publicKey: identityKey, privateKey: privateKey)
    }
    
    public func sign(_ message: Data) throws -> Data {
        return try SignalCrypto.shared.sign(privateKey: privateKey, message: message)
    }
} 