import Foundation

public class PreKeySignalMessage: Codable, Equatable {
    public let version: UInt8
    public let registrationId: UInt32
    private let _preKeyId: UInt32?
    public let signedPreKeyId: UInt32
    public let baseKey: Data
    public let identityKey: IdentityKey
    public let signalMessage: SignalMessage
    
    enum CodingKeys: String, CodingKey {
        case version, registrationId
        case _preKeyId = "preKeyId"
        case signedPreKeyId, baseKey, identityKey, signalMessage
    }
    
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
        self._preKeyId = preKeyId
        self.signedPreKeyId = signedPreKeyId
        self.baseKey = baseKey
        self.identityKey = identityKey
        self.signalMessage = signalMessage
    }
    
    public convenience init(bytes: [UInt8]) throws {
        let data = Data(bytes)
        let decoder = JSONDecoder()
        let decodedMessage = try decoder.decode(PreKeySignalMessage.self, from: data)
        self.init(
            version: decodedMessage.version,
            registrationId: decodedMessage.registrationId,
            preKeyId: decodedMessage._preKeyId,
            signedPreKeyId: decodedMessage.signedPreKeyId,
            baseKey: decodedMessage.baseKey,
            identityKey: decodedMessage.identityKey,
            signalMessage: decodedMessage.signalMessage
        )
    }
    
    public func preKeyId() throws -> UInt32? {
        // Add any necessary throwing logic if conditions arise where this should throw.
        // For now, it directly returns the renamed property.
        return self._preKeyId
    }
    
    public static func == (lhs: PreKeySignalMessage, rhs: PreKeySignalMessage) -> Bool {
        return lhs.version == rhs.version &&
               lhs.registrationId == rhs.registrationId &&
               lhs._preKeyId == rhs._preKeyId &&
               lhs.signedPreKeyId == rhs.signedPreKeyId &&
               lhs.baseKey == rhs.baseKey &&
               lhs.identityKey == rhs.identityKey &&
               lhs.signalMessage == rhs.signalMessage
    }
} 