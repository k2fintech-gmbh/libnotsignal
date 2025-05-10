import Foundation

public struct IdentityKeyPair: Codable, Equatable {
    public let publicKey: IdentityKey
    public let privateKey: Data
    
    // Add identityKey property to make it compatible with AsyncEncryptedService
    public var identityKey: IdentityKey {
        return publicKey
    }
    
    public init(publicKey: IdentityKey, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    // New constructor to support PrivateKey
    public init(publicKey: IdentityKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        
        var privateKeyData = Data()
        privateKey.withUnsafeBytes { buffer in
            privateKeyData.append(contentsOf: buffer)
        }
        self.privateKey = privateKeyData
    }
    
    // Direct initialization from bytes array
    public init(bytes: [UInt8]) throws {
        self = try IdentityKeyPair.deserialize(bytes: bytes)
    }
    
    public static func generate() throws -> IdentityKeyPair {
        let (privateKey, publicKey) = try SignalCrypto.shared.generateKeyPair()
        let identityKey = IdentityKey(publicKey: publicKey)
        return IdentityKeyPair(publicKey: identityKey, privateKey: privateKey)
    }
    
    // Add a sign method to make it compatible with AsyncEncryptedService
    public func sign(_ message: Data) throws -> Data {
        return try SignalCrypto.shared.sign(privateKey: privateKey, message: message)
    }
    
    // Serialize the key pair
    public func serialize() -> [UInt8] {
        let encodedPublicKey = publicKey.serialize()
        
        var result = [UInt8]()
        
        // Add private key length and data (big-endian)
        var privateKeyLength = UInt16(privateKey.count).bigEndian
        result.append(contentsOf: withUnsafeBytes(of: &privateKeyLength) { Array($0) })
        result.append(contentsOf: privateKey)
        
        // Add public key length and data (big-endian)
        var publicKeyLength = UInt16(encodedPublicKey.count).bigEndian
        result.append(contentsOf: withUnsafeBytes(of: &publicKeyLength) { Array($0) })
        result.append(contentsOf: encodedPublicKey)
        
        return result
    }
    
    // Create from serialized data
    public static func deserialize(bytes: [UInt8]) throws -> IdentityKeyPair {
        var offset = 0
        
        // Read private key length
        guard bytes.count >= offset + 2 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let privateKeyLength = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        
        // Read private key
        guard bytes.count >= offset + Int(privateKeyLength) else {
            throw LibNotSignalError.invalidSerializedData
        }
        let privateKey = Data(bytes[offset..<offset + Int(privateKeyLength)])
        offset += Int(privateKeyLength)
        
        // Read public key length
        guard bytes.count >= offset + 2 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let publicKeyLength = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        
        // Read public key
        guard bytes.count >= offset + Int(publicKeyLength) else {
            throw LibNotSignalError.invalidSerializedData
        }
        let publicKeyBytes = Array(bytes[offset..<offset + Int(publicKeyLength)])
        
        let identityKey = try IdentityKey.deserialize(bytes: publicKeyBytes)
        
        return IdentityKeyPair(publicKey: identityKey, privateKey: privateKey)
    }
    
    // Backward compatibility with Codable - deserialize from Decoder
    public static func deserialize(from decoder: Decoder) throws -> IdentityKeyPair {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        return try deserialize(bytes: [UInt8](data))
    }
    
    // Get the private key as a PrivateKey object
    public func getPrivateKey() -> PrivateKey {
        return PrivateKey(rawKey: privateKey)
    }
} 