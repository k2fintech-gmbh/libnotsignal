import Foundation

public class SessionBuilder {
    let store: SignalProtocolStore
    let remoteAddress: SignalAddress
    
    public init(store: SignalProtocolStore, remoteAddress: SignalAddress) {
        self.store = store
        self.remoteAddress = remoteAddress
    }
    
    public func process(preKeyBundle: PreKeyBundle) throws {
        // Check that the identity key is trusted
        if !(try store.isTrustedIdentity(preKeyBundle.identityKey, for: remoteAddress, direction: .sending)) {
            throw LibNotSignalError.untrustedIdentity
        }
        
        // Verify the signed prekey signature
        let validSignature = try preKeyBundle.identityKey.verifySignature(
            for: preKeyBundle.signedPreKey,
            signature: preKeyBundle.signedPreKeySignature
        )
        
        if !validSignature {
            throw LibNotSignalError.invalidSignature
        }
        
        // Create a new session
        let ourBaseKey = try KeyPair.generate()
        let ourIdentityKeyPair = try store.getIdentityKeyPair()
        
        let sessionState = try RatchetingSession.initializeAsAlice(
            ourIdentityKeyPair: ourIdentityKeyPair,
            ourBaseKey: ourBaseKey,
            theirIdentityKey: preKeyBundle.identityKey,
            theirSignedPreKey: preKeyBundle.signedPreKey,
            theirOneTimePreKey: preKeyBundle.preKey
        )
        
        // Store the new session
        try store.storeSession(sessionState, for: remoteAddress)
        
        // Save their identity
        try store.saveIdentity(preKeyBundle.identityKey, for: remoteAddress)
    }
    
    public func process(preKeySignalMessage: PreKeySignalMessage) throws {
        // Extract the parts of the message
        let version = preKeySignalMessage.version
        let theirIdentityKey = preKeySignalMessage.identityKey
        let signedPreKeyId = preKeySignalMessage.signedPreKeyId
        let preKeyIdOptional = try? preKeySignalMessage.preKeyId()
        let baseKey = preKeySignalMessage.baseKey
        let signalMessage = preKeySignalMessage.signalMessage
        
        // Check that the identity key is trusted
        if !(try store.isTrustedIdentity(theirIdentityKey, for: remoteAddress, direction: .receiving)) {
            throw LibNotSignalError.untrustedIdentity
        }
        
        // Get our identity and prekeys
        let ourIdentityKeyPair = try store.getIdentityKeyPair()
        let ourSignedPreKey = try store.loadSignedPreKey(id: signedPreKeyId)
        
        if ourSignedPreKey == nil {
            throw LibNotSignalError.invalidKeyId
        }
        
        var ourOneTimePreKey: PreKeyRecord? = nil
        if let unwrappedPreKeyId = preKeyIdOptional {
            ourOneTimePreKey = try store.loadPreKey(id: unwrappedPreKeyId)
        }
        
        // Create a new session
        let sessionState = try RatchetingSession.initializeAsBob(
            ourIdentityKeyPair: ourIdentityKeyPair,
            ourSignedPreKey: ourSignedPreKey!,
            ourOneTimePreKey: ourOneTimePreKey,
            theirIdentityKey: theirIdentityKey,
            theirBaseKey: baseKey
        )
        
        // Store the new session
        try store.storeSession(sessionState, for: remoteAddress)
        
        // Save their identity
        try store.saveIdentity(theirIdentityKey, for: remoteAddress)
        
        // Remove one-time prekey if used
        if let unwrappedPreKeyId = preKeyIdOptional {
            try store.removePreKey(id: unwrappedPreKeyId)
        }
    }
} 