import Foundation

public struct KeyPair: Codable, Equatable {
    public let publicKey: Data
    public let privateKey: Data
    
    public init(publicKey: Data, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    public static func generate() throws -> KeyPair {
        let (privateKey, publicKey) = try SignalCrypto.shared.generateKeyPair()
        return KeyPair(publicKey: publicKey, privateKey: privateKey)
    }
} 