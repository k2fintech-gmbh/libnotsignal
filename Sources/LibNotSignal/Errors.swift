import Foundation

public enum LibNotSignalError: Error, Equatable {
    case invalidKey
    case invalidKeyType
    case invalidKeyLength
    case invalidSignature
    case invalidMessage
    case invalidMessageVersion
    case duplicateMessage
    case invalidPreKeyId
    case invalidSession
    case sessionNotFound
    case untrustedIdentity
    case invalidState
    case insufficientKeyMaterial
    case noKeyTypeIdentifier
    case legacyCiphertext
    case noSessionForUser
    case invalidCiphertext
    case encryptionError
    case decryptionError
    case noSenderKeyState
    case invalidKeyId
    case invalidSerializedData
    case unsupportedOperation
    
    public var localizedDescription: String {
        switch self {
        case .invalidKey:
            return "Invalid key"
        case .invalidKeyType:
            return "Invalid key type"
        case .invalidKeyLength:
            return "Invalid key length"
        case .invalidSignature:
            return "Invalid signature"
        case .invalidMessage:
            return "Invalid message"
        case .invalidMessageVersion:
            return "Invalid message version"
        case .duplicateMessage:
            return "Duplicate message"
        case .invalidPreKeyId:
            return "Invalid pre-key ID"
        case .invalidSession:
            return "Invalid session"
        case .sessionNotFound:
            return "Session not found"
        case .untrustedIdentity:
            return "Untrusted identity"
        case .invalidState:
            return "Invalid state"
        case .insufficientKeyMaterial:
            return "Insufficient key material"
        case .noKeyTypeIdentifier:
            return "No key type identifier"
        case .legacyCiphertext:
            return "Legacy ciphertext"
        case .noSessionForUser:
            return "No session for user"
        case .invalidCiphertext:
            return "Invalid ciphertext"
        case .encryptionError:
            return "Encryption error"
        case .decryptionError:
            return "Decryption error"
        case .noSenderKeyState:
            return "No sender key state"
        case .invalidKeyId:
            return "Invalid key ID"
        case .invalidSerializedData:
            return "Invalid serialized data"
        case .unsupportedOperation:
            return "Operation not supported by the current provider"
        }
    }
} 