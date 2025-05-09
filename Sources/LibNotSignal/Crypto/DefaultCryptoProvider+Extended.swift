import Foundation
import Crypto

extension DefaultCryptoProvider: ExtendedCryptoProvider {
    public func getPublicKeyFrom(privateKey: Data) throws -> Data {
        // Create a private key from the raw representation
        let privateKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        
        // Get the public key
        let publicKey = privateKeyObj.publicKey
        
        // Return the raw representation of the public key
        return publicKey.rawRepresentation
    }
} 