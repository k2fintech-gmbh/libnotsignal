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
    
    // Add constructor for PrivateKey and PublicKey
    public init(id: UInt32, timestamp: UInt64, publicKey: PublicKey, privateKey: PrivateKey, signature: Data) {
        self.id = id
        self.timestamp = timestamp
        
        var publicKeyData = Data()
        publicKey.withUnsafeBytes { buffer in
            publicKeyData.append(contentsOf: buffer)
        }
        self.publicKey = publicKeyData
        
        var privateKeyData = Data()
        privateKey.withUnsafeBytes { buffer in
            privateKeyData.append(contentsOf: buffer)
        }
        self.privateKey = privateKeyData
        
        self.signature = signature
    }
    
    // Direct initialization from bytes array
    public init(bytes: [UInt8]) throws {
        self = try SignedPreKeyRecord.deserialize(from: bytes)
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
    
    // Serialize the signed pre-key record
    public func serialize() -> Data {
        var result = Data()
        
        // Add ID (4 bytes)
        var idValue = id
        result.append(contentsOf: withUnsafeBytes(of: &idValue) { Array($0) })
        
        // Add timestamp (8 bytes)
        var timestampValue = timestamp
        result.append(contentsOf: withUnsafeBytes(of: &timestampValue) { Array($0) })
        
        // Add public key length and data
        var publicKeyLength = UInt16(publicKey.count)
        result.append(contentsOf: withUnsafeBytes(of: &publicKeyLength) { Array($0) })
        result.append(publicKey)
        
        // Add private key length and data
        var privateKeyLength = UInt16(privateKey.count)
        result.append(contentsOf: withUnsafeBytes(of: &privateKeyLength) { Array($0) })
        result.append(privateKey)
        
        // Add signature length and data
        var signatureLength = UInt16(signature.count)
        result.append(contentsOf: withUnsafeBytes(of: &signatureLength) { Array($0) })
        result.append(signature)
        
        return result
    }
    
    // Create from serialized data
    public static func deserialize(from bytes: [UInt8]) throws -> SignedPreKeyRecord {
        var offset = 0
        
        // Read ID
        guard bytes.count >= offset + 4 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let id = UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
        offset += 4
        
        // Read timestamp
        guard bytes.count >= offset + 8 else {
            throw LibNotSignalError.invalidSerializedData
        }
        
        var timestamp: UInt64 = 0
        for i in 0..<8 {
            timestamp |= UInt64(bytes[offset + i]) << (8 * (7 - i))
        }
        offset += 8
        
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
        let publicKey = Data(bytes[offset..<offset + Int(publicKeyLength)])
        offset += Int(publicKeyLength)
        
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
        
        // Read signature length
        guard bytes.count >= offset + 2 else {
            throw LibNotSignalError.invalidSerializedData
        }
        let signatureLength = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        
        // Read signature
        guard bytes.count >= offset + Int(signatureLength) else {
            throw LibNotSignalError.invalidSerializedData
        }
        let signature = Data(bytes[offset..<offset + Int(signatureLength)])
        
        return SignedPreKeyRecord(
            id: id,
            timestamp: timestamp,
            publicKey: publicKey,
            privateKey: privateKey,
            signature: signature
        )
    }
    
    // Backward compatibility with Codable - deserialize from Decoder
    public static func deserialize(from decoder: Decoder) throws -> SignedPreKeyRecord {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        return try deserialize(from: [UInt8](data))
    }
    
    // Get the private key as a PrivateKey object
    public func getPrivateKey() -> PrivateKey {
        return PrivateKey(rawKey: privateKey)
    }
    
    // Get the public key as a PublicKey object
    public func getPublicKey() -> PublicKey {
        return PublicKey(rawKey: publicKey)
    }
    
    // Method to get the public key for Registration.swift
    public func getSignedPreKeyPublicKey() -> PublicKey {
        return getPublicKey()
    }
} 