import Foundation

public class InMemoryIdentityKeyStore: IdentityKeyStore {
    private let identityKeyPair: IdentityKeyPair
    private let registrationId: UInt32
    private var identities: [String: IdentityKey] = [:]
    
    public init(identityKeyPair: IdentityKeyPair, registrationId: UInt32) {
        self.identityKeyPair = identityKeyPair
        self.registrationId = registrationId
    }
    
    public func getIdentityKeyPair() throws -> IdentityKeyPair {
        return identityKeyPair
    }
    
    public func getLocalRegistrationId() throws -> UInt32 {
        return registrationId
    }
    
    public func saveIdentity(_ identity: IdentityKey, for address: SignalAddress) throws -> Bool {
        let key = address.description
        let existingIdentity = identities[key]
        let changed = existingIdentity != nil && existingIdentity != identity
        
        identities[key] = identity
        return changed
    }
    
    public func isTrustedIdentity(_ identity: IdentityKey, for address: SignalAddress, direction: Direction) throws -> Bool {
        let key = address.description
        let existingIdentity = identities[key]
        
        if existingIdentity == nil {
            return true // Trust on first use
        }
        
        return existingIdentity == identity
    }
    
    public func getIdentity(for address: SignalAddress) throws -> IdentityKey? {
        return identities[address.description]
    }
    
    // Legacy methods with ProtocolAddress and context
    public func getIdentityKeyPair(context: Any?) throws -> IdentityKeyPair {
        return try getIdentityKeyPair()
    }
    
    public func getLocalRegistrationId(context: Any?) throws -> UInt32 {
        return try getLocalRegistrationId()
    }
    
    public func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: Any?) throws -> Bool {
        return try saveIdentity(identity, for: address.toSignalAddress())
    }
    
    public func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: Any?) throws -> Bool {
        return try isTrustedIdentity(identity, for: address.toSignalAddress(), direction: direction)
    }
    
    public func identity(for address: ProtocolAddress, context: Any?) throws -> IdentityKey? {
        return try getIdentity(for: address.toSignalAddress())
    }
} 