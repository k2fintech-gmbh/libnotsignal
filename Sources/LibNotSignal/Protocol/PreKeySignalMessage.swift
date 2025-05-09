import Foundation

public class PreKeySignalMessage: Codable, Equatable {
    public let version: UInt8
    public let registrationId: UInt32
    public let preKeyId: UInt32?
    public let signedPreKeyId: UInt32
    public let baseKey: Data
    public let identityKey: IdentityKey
    public let signalMessage: SignalMessage
    
    public init(
        version: UInt8,
        registrationId: UInt32,
        preKeyId: UInt32?,
        signedPreKeyId: UInt32,
        baseKey: Data,
        identityKey: IdentityKey,
        signalMessage: SignalMessage
    ) {
        self.version = version
        self.registrationId = registrationId
        self.preKeyId = preKeyId
        self.signedPreKeyId = signedPreKeyId
        self.baseKey = baseKey
        self.identityKey = identityKey
        self.signalMessage = signalMessage
    }
    
    public static func == (lhs: PreKeySignalMessage, rhs: PreKeySignalMessage) -> Bool {
        return lhs.version == rhs.version &&
               lhs.registrationId == rhs.registrationId &&
               lhs.preKeyId == rhs.preKeyId &&
               lhs.signedPreKeyId == rhs.signedPreKeyId &&
               lhs.baseKey == rhs.baseKey &&
               lhs.identityKey == rhs.identityKey &&
               lhs.signalMessage == rhs.signalMessage
    }
} 