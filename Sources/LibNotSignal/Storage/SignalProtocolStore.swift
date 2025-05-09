import Foundation

public protocol SignalProtocolStore: IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore {
    // This protocol combines all the required stores
} 