import Foundation

public class SessionState: Codable, Equatable {
    public var rootKey: Data = Data()
    public var localIdentityKey: IdentityKey?
    public var remoteIdentityKey: IdentityKey?
    public var sendingChain: SendingChain?
    public var receivingChains: [ReceivingChain] = []
    public var previousCounter: UInt32 = 0
    
    // Maximum number of ratchet steps we'll take in a single message
    public static let maxSkip: Int = 1000
    
    public init() {}
    
    public static func == (lhs: SessionState, rhs: SessionState) -> Bool {
        return lhs.rootKey == rhs.rootKey &&
               lhs.localIdentityKey == rhs.localIdentityKey &&
               lhs.remoteIdentityKey == rhs.remoteIdentityKey &&
               lhs.sendingChain == rhs.sendingChain &&
               lhs.receivingChains == rhs.receivingChains &&
               lhs.previousCounter == rhs.previousCounter
    }
    
    public func deriveSendingKeys(remoteRatchetKey: Data) throws -> (rootKey: Data, chainKey: Data) {
        guard let sendingChain = sendingChain else {
            throw LibNotSignalError.invalidState
        }
        
        // Calculate shared secret
        let sharedSecret = try SignalCrypto.shared.calculateAgreement(
            privateKey: sendingChain.key,
            publicKey: remoteRatchetKey
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
    
    public func deriveNextChainKey() throws -> ChainKey {
        guard let sendingChain = sendingChain else {
            throw LibNotSignalError.invalidState
        }
        
        // Derive the next chain key
        let hmac = SignalCrypto.shared.hmacSHA256(
            key: sendingChain.key,
            data: "WhisperChain".data(using: .utf8)!
        )
        
        return ChainKey(key: hmac, index: sendingChain.index + 1)
    }
    
    public func deriveMessageKeys(chainKey: ChainKey) throws -> MessageKey {
        // Derive keys for encryption
        let inputKeyMaterial = SignalCrypto.shared.hmacSHA256(
            key: chainKey.key,
            data: "WhisperMessageKeys".data(using: .utf8)!
        )
        
        let kdf = try SignalCrypto.shared.hkdfDeriveSecrets(
            inputKeyMaterial: inputKeyMaterial,
            info: "WhisperMessageKeys".data(using: .utf8)!,
            outputLength: 80,
            salt: Data()
        )
        
        return MessageKey(
            index: chainKey.index,
            cipherKey: kdf.subdata(in: 0..<32),
            macKey: kdf.subdata(in: 32..<64),
            iv: kdf.subdata(in: 64..<80)
        )
    }
    
    public func hasReceiverChain(senderRatchetKey: Data) -> Bool {
        return receivingChains.contains { $0.ratchetKey == senderRatchetKey }
    }
    
    public func getReceiverChainByRatchetKey(senderRatchetKey: Data) -> ReceivingChain? {
        return receivingChains.first { $0.ratchetKey == senderRatchetKey }
    }
    
    public func getMessageKeys(senderRatchetKey: Data, counter: UInt32) -> MessageKey? {
        guard let chain = getReceiverChainByRatchetKey(senderRatchetKey: senderRatchetKey) else {
            return nil
        }
        
        // Find message keys for this counter
        return chain.messageKeys.first { $0.index == counter }
    }
    
    public func removeMessageKeys(senderRatchetKey: Data, counter: UInt32) {
        guard var chain = getReceiverChainByRatchetKey(senderRatchetKey: senderRatchetKey) else {
            return
        }
        
        // Remove message keys for this counter
        chain.messageKeys.removeAll { $0.index == counter }
        
        // Update in the array
        if let index = receivingChains.firstIndex(where: { $0.ratchetKey == senderRatchetKey }) {
            receivingChains[index] = chain
        }
    }
    
    public func addReceiverChain(senderRatchetKey: Data, chainKey: ChainKey) {
        let chain = ReceivingChain(
            key: chainKey.key,
            index: chainKey.index,
            ratchetKey: senderRatchetKey
        )
        
        receivingChains.append(chain)
        
        // Limit the number of chains we store
        if receivingChains.count > 5 {
            receivingChains.removeFirst(receivingChains.count - 5)
        }
    }
    
    public func setSenderChain(keyPair: KeyPair, chainKey: ChainKey) {
        sendingChain = SendingChain(
            key: chainKey.key,
            index: chainKey.index,
            ratchetKey: keyPair.publicKey.data
        )
    }
}

public struct ChainKey: Codable, Equatable {
    public let key: Data
    public let index: UInt32
    
    public init(key: Data, index: UInt32) {
        self.key = key
        self.index = index
    }
} 