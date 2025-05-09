import Foundation

public class SignalMessage: Codable, Equatable {
    public let version: UInt8
    public let senderRatchetKey: Data
    public let counter: UInt32
    public let previousCounter: UInt32
    public let ciphertext: Data
    public let serialized: Data
    
    public init(
        version: UInt8,
        senderRatchetKey: Data,
        counter: UInt32,
        previousCounter: UInt32,
        ciphertext: Data,
        serialized: Data
    ) {
        self.version = version
        self.senderRatchetKey = senderRatchetKey
        self.counter = counter
        self.previousCounter = previousCounter
        self.ciphertext = ciphertext
        self.serialized = serialized
    }
    
    public convenience init(bytes: [UInt8]) throws {
        let data = Data(bytes)
        let decoder = JSONDecoder()
        let decodedMessage = try decoder.decode(SignalMessage.self, from: data)
        self.init(
            version: decodedMessage.version,
            senderRatchetKey: decodedMessage.senderRatchetKey,
            counter: decodedMessage.counter,
            previousCounter: decodedMessage.previousCounter,
            ciphertext: decodedMessage.ciphertext,
            serialized: data
        )
    }
    
    public static func == (lhs: SignalMessage, rhs: SignalMessage) -> Bool {
        return lhs.version == rhs.version &&
               lhs.senderRatchetKey == rhs.senderRatchetKey &&
               lhs.counter == rhs.counter &&
               lhs.previousCounter == rhs.previousCounter &&
               lhs.ciphertext == rhs.ciphertext &&
               lhs.serialized == rhs.serialized
    }
} 