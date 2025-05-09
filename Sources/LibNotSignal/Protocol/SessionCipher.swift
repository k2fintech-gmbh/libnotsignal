import Foundation

public class SessionCipher {
    private let store: SignalProtocolStore
    private let remoteAddress: SignalAddress
    private let sessionBuilder: SessionBuilder
    
    public init(store: SignalProtocolStore, remoteAddress: SignalAddress) {
        self.store = store
        self.remoteAddress = remoteAddress
        self.sessionBuilder = SessionBuilder(store: store, remoteAddress: remoteAddress)
    }
    
    public func encrypt(_ plaintext: Data) throws -> CiphertextMessage {
        guard let sessionState = try store.loadSession(for: remoteAddress) else {
            throw LibNotSignalError.noSessionForUser
        }
        
        // Get the sending chain
        guard let sendingChain = sessionState.sendingChain else {
            throw LibNotSignalError.invalidState
        }
        
        // Derive the message keys
        let chainKey = ChainKey(key: sendingChain.key, index: sendingChain.index)
        let messageKeys = try sessionState.deriveMessageKeys(chainKey: chainKey)
        
        // Increment the chain key
        let nextChainKey = try sessionState.deriveNextChainKey()
        sessionState.sendingChain?.key = nextChainKey.key
        sessionState.sendingChain?.index = nextChainKey.index
        
        // Create the message
        let version: UInt8 = 3 // Current version
        
        // Encrypt the message
        let iv = messageKeys.iv
        let ciphertext = try SignalCrypto.shared.encrypt(
            key: messageKeys.cipherKey,
            iv: iv,
            data: plaintext
        )
        
        // Create the signal message
        let signalMessage = SignalMessage(
            version: version,
            senderRatchetKey: sendingChain.ratchetKey,
            counter: messageKeys.index,
            previousCounter: sessionState.previousCounter,
            ciphertext: ciphertext,
            serialized: Data() // This would be serialized in a real implementation
        )
        
        // Store the updated session
        try store.storeSession(sessionState, for: remoteAddress)
        
        return CiphertextMessage(type: .whisper, body: signalMessage.serialized)
    }
    
    public func decrypt(message: SignalMessage) throws -> Data {
        guard let sessionState = try store.loadSession(for: remoteAddress) else {
            throw LibNotSignalError.noSessionForUser
        }
        
        // Check if we have the sender ratchet key
        if !sessionState.hasReceiverChain(senderRatchetKey: message.senderRatchetKey) {
            // We need to derive a new ratchet for this sender key
            try createNewReceiverChain(sessionState: sessionState, senderRatchetKey: message.senderRatchetKey)
        }
        
        // Try to decrypt
        let plaintext = try decryptWithSessionState(sessionState: sessionState, message: message)
        
        // Store the updated session
        try store.storeSession(sessionState, for: remoteAddress)
        
        return plaintext
    }
    
    public func decrypt(preKeyMessage: PreKeySignalMessage) throws -> Data {
        // First, try to process the PreKeySignalMessage to create a session
        try sessionBuilder.process(preKeySignalMessage: preKeyMessage)
        
        // Then try to decrypt the inner signal message
        return try decrypt(message: preKeyMessage.signalMessage)
    }
    
    private func createNewReceiverChain(sessionState: SessionState, senderRatchetKey: Data) throws {
        guard let sendingChain = sessionState.sendingChain else {
            throw LibNotSignalError.invalidState
        }
        
        // Calculate shared secret and derive keys
        let derived = try sessionState.deriveSendingKeys(remoteRatchetKey: senderRatchetKey)
        
        // Add the receiver chain
        let chainKey = ChainKey(key: derived.chainKey, index: 0)
        sessionState.addReceiverChain(senderRatchetKey: senderRatchetKey, chainKey: chainKey)
        
        // Update root key
        sessionState.rootKey = derived.rootKey
        
        // Create a new sending ratchet
        let ourNewRatchetKeyPair = try KeyPair.generate()
        
        // Create a new sending chain
        let sendingDerived = try calculateSendingKeys(
            rootKey: derived.rootKey,
            ourRatchetKey: ourNewRatchetKeyPair.privateKey.data,
            theirRatchetKey: senderRatchetKey
        )
        
        // Update chains
        sessionState.rootKey = sendingDerived.rootKey
        let sendingChainKey = ChainKey(key: sendingDerived.chainKey, index: 0)
        sessionState.setSenderChain(keyPair: ourNewRatchetKeyPair, chainKey: sendingChainKey)
    }
    
    private func calculateSendingKeys(rootKey: Data, ourRatchetKey: Data, theirRatchetKey: Data) throws -> (rootKey: Data, chainKey: Data) {
        // Calculate shared secret
        let sharedSecret = try SignalCrypto.shared.calculateAgreement(
            privateKey: ourRatchetKey,
            publicKey: theirRatchetKey
        )
        
        // Derive new keys
        let derivedKeys = try SignalCrypto.shared.hkdfDeriveSecrets(
            inputKeyMaterial: sharedSecret,
            info: "WhisperRatchet".data(using: .utf8)!,
            outputLength: 64,
            salt: rootKey
        )
        
        let newRootKey = derivedKeys.subdata(in: 0..<32)
        let newChainKey = derivedKeys.subdata(in: 32..<64)
        
        return (newRootKey, newChainKey)
    }
    
    private func decryptWithSessionState(sessionState: SessionState, message: SignalMessage) throws -> Data {
        guard let chain = sessionState.getReceiverChainByRatchetKey(senderRatchetKey: message.senderRatchetKey) else {
            throw LibNotSignalError.invalidMessage
        }
        
        // Check if we've already decrypted this message
        if message.counter < chain.index {
            if let messageKeys = sessionState.getMessageKeys(
                senderRatchetKey: message.senderRatchetKey,
                counter: message.counter
            ) {
                // We have the keys, decrypt the message
                let plaintext = try decrypt(
                    ciphertext: message.ciphertext,
                    iv: messageKeys.iv,
                    key: messageKeys.cipherKey
                )
                
                // Remove used message keys
                sessionState.removeMessageKeys(
                    senderRatchetKey: message.senderRatchetKey,
                    counter: message.counter
                )
                
                return plaintext
            }
            
            // We don't have the keys anymore, this is an error
            throw LibNotSignalError.duplicateMessage
        }
        
        // If the message is far ahead in the chain, we need to skip ahead
        if message.counter > chain.index {
            // Check if we're skipping too many messages
            if message.counter - chain.index > UInt32(SessionState.maxSkip) {
                throw LibNotSignalError.invalidMessage
            }
            
            // Generate and store skipped message keys
            var chainKey = ChainKey(key: chain.key, index: chain.index)
            while chainKey.index < message.counter {
                let messageKeys = try sessionState.deriveMessageKeys(chainKey: chainKey)
                
                // Store message keys for later use
                var foundChain = sessionState.getReceiverChainByRatchetKey(senderRatchetKey: message.senderRatchetKey)!
                foundChain.messageKeys.append(messageKeys)
                
                // Advance chain key
                chainKey = ChainKey(key: chainKey.key, index: chainKey.index + 1)
            }
            
            // Update the chain key for this sender
            if let index = sessionState.receivingChains.firstIndex(where: { $0.ratchetKey == message.senderRatchetKey }) {
                sessionState.receivingChains[index].key = chainKey.key
                sessionState.receivingChains[index].index = chainKey.index
            }
        }
        
        // Derive the message keys
        let chainKey = ChainKey(key: chain.key, index: chain.index)
        let messageKeys = try sessionState.deriveMessageKeys(chainKey: chainKey)
        
        // Decrypt the message
        let plaintext = try decrypt(
            ciphertext: message.ciphertext,
            iv: messageKeys.iv,
            key: messageKeys.cipherKey
        )
        
        // Update the chain key index
        if let index = sessionState.receivingChains.firstIndex(where: { $0.ratchetKey == message.senderRatchetKey }) {
            sessionState.receivingChains[index].index = chainKey.index + 1
            sessionState.previousCounter = message.counter
        }
        
        return plaintext
    }
    
    private func decrypt(ciphertext: Data, iv: Data, key: Data) throws -> Data {
        return try SignalCrypto.shared.decrypt(
            key: key,
            iv: iv,
            data: ciphertext
        )
    }
}

public struct CiphertextMessage {
    public enum MessageType {
        case preKey
        case whisper
        case senderKey
    }
    
    public let type: MessageType
    public let body: Data
    
    // Compatibility alias for EncryptedSession.swift
    public var messageType: MessageType {
        return type
    }
    
    public init(type: MessageType, body: Data) {
        self.type = type
        self.body = body
    }
} 