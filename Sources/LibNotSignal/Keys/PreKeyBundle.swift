import Foundation

public struct PreKeyBundle: Codable, Equatable {
    public let registrationId: UInt32
    public let deviceId: UInt32
    public let preKeyId: UInt32?
    public let preKey: Data?
    public let signedPreKeyId: UInt32
    public let signedPreKey: Data
    public let signedPreKeySignature: Data
    public let identityKey: IdentityKey
    
    public init(
        registrationId: UInt32,
        deviceId: UInt32,
        preKeyId: UInt32?,
        preKey: Data?,
        signedPreKeyId: UInt32,
        signedPreKey: Data,
        signedPreKeySignature: Data,
        identityKey: IdentityKey
    ) {
        self.registrationId = registrationId
        self.deviceId = deviceId
        self.preKeyId = preKeyId
        self.preKey = preKey
        self.signedPreKeyId = signedPreKeyId
        self.signedPreKey = signedPreKey
        self.signedPreKeySignature = signedPreKeySignature
        self.identityKey = identityKey
    }

    // Overload for compatibility with older argument labels and types
    public init(
        registrationId: UInt32,
        deviceId: UInt32,
        prekeyId: UInt32?, // Lowercase 'k'
        prekey: PublicKey?, // Lowercase 'k', type PublicKey
        signedPrekeyId: UInt32, // Lowercase 'k'
        signedPrekey: PublicKey, // Lowercase 'k', type PublicKey
        signedPrekeySignature: [UInt8], // Lowercase 'k', type [UInt8]
        identity: IdentityKey // 'identity' instead of 'identityKey'
    ) {
        self.init(
            registrationId: registrationId,
            deviceId: deviceId,
            preKeyId: prekeyId, // Pass through to correct label
            preKey: prekey.map { Data($0.rawRepresentation) }, // Convert PublicKey? to Data?
            signedPreKeyId: signedPrekeyId, // Pass through to correct label
            signedPreKey: Data(signedPrekey.rawRepresentation), // Convert PublicKey to Data
            signedPreKeySignature: Data(signedPrekeySignature), // Convert [UInt8] to Data
            identityKey: identity // Pass through to correct label
        )
    }
} 