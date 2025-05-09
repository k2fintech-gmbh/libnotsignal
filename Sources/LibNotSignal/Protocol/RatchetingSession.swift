import Foundation

public class RatchetingSession {
    
    private static let MESSAGE_KEY_SEED = "MessageKeySeed".data(using: .utf8)!
    private static let CHAIN_KEY_SEED = "ChainKeySeed".data(using: .utf8)!
    private static let ROOT_KEY_INFO = "WhisperRatchet".data(using: .utf8)!
    
    public static func initializeAsAlice(
        ourIdentityKeyPair: IdentityKeyPair,
        ourBaseKey: KeyPair,
        theirIdentityKey: IdentityKey,
        theirSignedPreKey: Data,
        theirOneTimePreKey: Data? = nil
    ) throws -> SessionState {
        let sessionState = SessionState()
        
        // Calculate master secret
        var agreements = [
            try calculateAgreement(ourIdentityKeyPair.privateKey, theirSignedPreKey),
            try calculateAgreement(ourBaseKey.privateKey.data, theirIdentityKey.publicKey),
            try calculateAgreement(ourBaseKey.privateKey.data, theirSignedPreKey)
        ]
        
        if let theirOneTimePreKey = theirOneTimePreKey {
            let agreement = try calculateAgreement(ourBaseKey.privateKey.data, theirOneTimePreKey)
            agreements.append(agreement)
        }
        
        let masterSecret = agreements.reduce(Data(), +)
        
        // Derive root key, chain keys and sender ratchet keys
        let derivedKeys = try deriveInitialKeys(masterSecret)
        let senderRatchetKeyPair = try KeyPair.generate()
        
        let rootKey = derivedKeys.rootKey
        let chainKey = derivedKeys.chainKey
        
        let sendingChain = try initializeSendingChain(rootKey, theirSignedPreKey, senderRatchetKeyPair.privateKey.data)
        
        // Set session parameters
        sessionState.remoteIdentityKey = theirIdentityKey
        sessionState.localIdentityKey = ourIdentityKeyPair.publicKey
        sessionState.rootKey = sendingChain.rootKey
        sessionState.sendingChain = SendingChain(
            key: sendingChain.chainKey,
            index: 0,
            ratchetKey: senderRatchetKeyPair.publicKey.data
        )
        
        return sessionState
    }
    
    public static func initializeAsBob(
        ourIdentityKeyPair: IdentityKeyPair,
        ourSignedPreKey: SignedPreKeyRecord,
        ourOneTimePreKey: PreKeyRecord?,
        theirIdentityKey: IdentityKey,
        theirBaseKey: Data
    ) throws -> SessionState {
        let sessionState = SessionState()
        
        // Calculate master secret
        var agreements = [
            try calculateAgreement(ourSignedPreKey.privateKey, theirIdentityKey.publicKey),
            try calculateAgreement(ourIdentityKeyPair.privateKey, theirBaseKey),
            try calculateAgreement(ourSignedPreKey.privateKey, theirBaseKey)
        ]
        
        if let ourOneTimePreKey = ourOneTimePreKey {
            let agreement = try calculateAgreement(ourOneTimePreKey.privateKey, theirBaseKey)
            agreements.append(agreement)
        }
        
        let masterSecret = agreements.reduce(Data(), +)
        
        // Derive root key and chain keys
        let derivedKeys = try deriveInitialKeys(masterSecret)
        
        // Set session parameters
        sessionState.remoteIdentityKey = theirIdentityKey
        sessionState.localIdentityKey = ourIdentityKeyPair.publicKey
        sessionState.rootKey = derivedKeys.rootKey
        sessionState.receivingChains.append(ReceivingChain(
            key: derivedKeys.chainKey,
            index: 0,
            ratchetKey: theirBaseKey
        ))
        
        return sessionState
    }
    
    // MARK: - Private Methods
    
    private static func calculateAgreement(_ privateKey: Data, _ publicKey: Data) throws -> Data {
        return try SignalCrypto.shared.calculateAgreement(privateKey: privateKey, publicKey: publicKey)
    }
    
    private static func deriveInitialKeys(_ masterSecret: Data) throws -> (rootKey: Data, chainKey: Data) {
        let derived = try SignalCrypto.shared.hkdfDeriveSecrets(
            inputKeyMaterial: masterSecret,
            info: ROOT_KEY_INFO,
            outputLength: 64,
            salt: Data(repeating: 0, count: 32)
        )
        
        let rootKey = derived.subdata(in: 0..<32)
        let chainKey = derived.subdata(in: 32..<64)
        
        return (rootKey, chainKey)
    }
    
    private static func initializeSendingChain(_ rootKey: Data, _ theirRatchetKey: Data, _ ourRatchetKey: Data) throws -> (rootKey: Data, chainKey: Data) {
        // Calculate shared secret
        let sharedSecret = try calculateAgreement(ourRatchetKey, theirRatchetKey)
        
        // Derive new root key and chain key
        let derivedKeys = try SignalCrypto.shared.hkdfDeriveSecrets(
            inputKeyMaterial: sharedSecret,
            info: ROOT_KEY_INFO,
            outputLength: 64,
            salt: rootKey
        )
        
        let nextRootKey = derivedKeys.subdata(in: 0..<32)
        let nextChainKey = derivedKeys.subdata(in: 32..<64)
        
        return (nextRootKey, nextChainKey)
    }
} 