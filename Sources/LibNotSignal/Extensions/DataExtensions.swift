import Foundation
import Crypto

extension Data {
    public func toBase64() -> String {
        return self.base64EncodedString()
    }
    
    public func sha256() -> Data {
        let digest = SHA256.hash(data: self)
        return Data(digest)
    }
    
    // For compatibility with code expecting a serialize method on Data
    public func serialize() -> Data {
        return self
    }
}

// Helper extension to convert anything to Data for compatibility
public extension NSObject {
    func toData() -> Data {
        if let data = self as? Data {
            return data
        } else if let privateKey = self as? PrivateKey {
            return privateKey.asData
        } else if let publicKey = self as? PublicKey {
            return publicKey.asData
        } else {
            fatalError("Cannot convert \(type(of: self)) to Data")
        }
    }
}

// Check if bytes property already exists before adding it
#if !swift(>=5.0)
extension Data {
    public var bytes: [UInt8] {
        return [UInt8](self)
    }
}
#endif 