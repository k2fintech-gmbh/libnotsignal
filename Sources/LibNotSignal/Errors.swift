import Foundation

public enum LibNotSignalError: Error {
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
} 