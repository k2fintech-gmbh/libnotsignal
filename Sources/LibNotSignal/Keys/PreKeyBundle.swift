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
} 