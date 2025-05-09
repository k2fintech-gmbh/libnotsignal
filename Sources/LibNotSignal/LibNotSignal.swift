import Foundation

public class LibNotSignal {
    public static let shared = LibNotSignal()
    
    private init() {}
    
    // MARK: - Key Generation
    
    public func generateIdentityKeyPair() throws -> IdentityKeyPair {
        return try IdentityKeyPair.generate()
    }
    
    public func generateRegistrationId() throws -> UInt32 {
        return try SignalCrypto.shared.randomInt(min: 1, max: 16380)
    }
    
    public func generatePreKeys(start: UInt32, count: UInt32) throws -> [PreKeyRecord] {
        return try PreKeyRecord.generatePreKeys(startId: start, count: count)
    }
    
    public func generateSignedPreKey(identityKeyPair: IdentityKeyPair, id: UInt32, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) throws -> SignedPreKeyRecord {
        return try SignedPreKeyRecord.generate(id: id, identityKeyPair: identityKeyPair, timestamp: timestamp)
    }
    
    // MARK: - Session Management
    
    public func createSessionCipher(store: SignalProtocolStore, remoteAddress: SignalAddress) -> SessionCipher {
        return SessionCipher(store: store, remoteAddress: remoteAddress)
    }
    
    public func createSessionBuilder(store: SignalProtocolStore, remoteAddress: SignalAddress) -> SessionBuilder {
        return SessionBuilder(store: store, remoteAddress: remoteAddress)
    }
    
    // MARK: - Fingerprint Verification
    
    public func generateFingerprint(
        localIdentity: IdentityKey,
        remoteIdentity: IdentityKey,
        localAddress: SignalAddress,
        remoteAddress: SignalAddress
    ) -> String {
        // A very simple fingerprint implementation
        let localData = localIdentity.publicKey
        let remoteData = remoteIdentity.publicKey
        
        let localHash = SignalCrypto.shared.sha256(localData).base64EncodedString()
        let remoteHash = SignalCrypto.shared.sha256(remoteData).base64EncodedString()
        
        return "\(localAddress.name):\(localHash) <-> \(remoteAddress.name):\(remoteHash)"
    }
} 