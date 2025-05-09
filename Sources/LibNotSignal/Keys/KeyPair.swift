import Foundation

public class KeyPair {
    public let privateKey: PrivateKey
    public let publicKey: PublicKey
    
    public init(privateKey: PrivateKey, publicKey: PublicKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
    
    public static func generate() throws -> KeyPair {
        let privateKey = PrivateKey.generate()
        let publicKey = privateKey.publicKey
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }
} 