import Foundation

public protocol IdentityKeyStore {
    func getIdentityKeyPair() throws -> IdentityKeyPair
    func getLocalRegistrationId() throws -> UInt32
    func saveIdentity(_ identity: IdentityKey, for address: SignalAddress) throws -> Bool
    func isTrustedIdentity(_ identity: IdentityKey, for address: SignalAddress, direction: Direction) throws -> Bool
    func getIdentity(for address: SignalAddress) throws -> IdentityKey?
}

public enum Direction {
    case sending
    case receiving
} 