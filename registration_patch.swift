import Core
import LibNotSignal

public struct Registration {

    public let identityKeyPair: IdentityKeyPair
    public let registrationId: UInt32
    public let preKeys: [PreKeyRecord]
    public let signedPreKeyRecord: SignedPreKeyRecord

    public init(
        identityKeyPair: IdentityKeyPair,
        registrationId: UInt32,
        preKeys: [PreKeyRecord],
        signedPreKeyRecord: SignedPreKeyRecord
    ) {
        self.identityKeyPair = identityKeyPair
        self.registrationId = registrationId
        self.preKeys = preKeys
        self.signedPreKeyRecord = signedPreKeyRecord
    }

    // Mark: - String values are BASE64
    public init(
        identityKeyPair: String,
        registrationId: UInt32,
        preKeys: [String],
        signedPreKeyRecord: String
    ) throws {
        // Use bytes: instead of from: for backward compatibility
        self.identityKeyPair = try IdentityKeyPair(bytes: identityKeyPair.toUInt8())
        self.registrationId = registrationId
        self.preKeys = try preKeys.map { item in
            try PreKeyRecord(bytes: item.toUInt8())
        }
        self.signedPreKeyRecord = try SignedPreKeyRecord(bytes: signedPreKeyRecord.toUInt8())
    }

    public func identityKeyPairBase64() -> String {
        return identityKeyPair.serialize().toBase64()
    }

    public func identityKeyPublicBase64() -> String {
        return identityKeyPair.publicKey.serialize().toBase64()
    }

    public func preKeyIdsBase64() -> [String] {
        preKeys.map { preKeyRecord in
            preKeyRecord.serialize().toBase64()
        }
    }

    public func signedPreKeyRecordBase64() -> String {
        return signedPreKeyRecord.serialize().toBase64()
    }

    public func publicIdentityKeyBase64() -> String {
        return identityKeyPair.publicKey.serialize().toBase64()
    }

    public func signedPreKeyPublicKeyBase64() throws -> String {
        // Use getSignedPreKeyPublicKey() instead of publicKey()
        return signedPreKeyRecord.getSignedPreKeyPublicKey().rawRepresentation.toBase64()
    }

    public func signedPreKeyId() -> UInt32 {
        return signedPreKeyRecord.id
    }

    public func signedPreKeyRecordSignatureBase64() -> String {
        return signedPreKeyRecord.signature.toBase64()
    }
} 