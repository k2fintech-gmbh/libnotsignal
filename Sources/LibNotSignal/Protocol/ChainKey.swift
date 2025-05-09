import Foundation

public struct SendingChain: Codable, Equatable {
    public var key: Data
    public var index: UInt32
    public let ratchetKey: Data
    
    public init(key: Data, index: UInt32, ratchetKey: Data) {
        self.key = key
        self.index = index
        self.ratchetKey = ratchetKey
    }
}

public struct ReceivingChain: Codable, Equatable {
    public var key: Data
    public var index: UInt32
    public let ratchetKey: Data
    public var messageKeys: [MessageKey] = []
    
    public init(key: Data, index: UInt32, ratchetKey: Data) {
        self.key = key
        self.index = index
        self.ratchetKey = ratchetKey
    }
}

public struct MessageKey: Codable, Equatable {
    public let index: UInt32
    public let cipherKey: Data
    public let macKey: Data
    public let iv: Data
    
    public init(index: UInt32, cipherKey: Data, macKey: Data, iv: Data) {
        self.index = index
        self.cipherKey = cipherKey
        self.macKey = macKey
        self.iv = iv
    }
} 