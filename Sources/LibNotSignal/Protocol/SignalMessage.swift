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
        try self.init(data: data)
    }
    
    public convenience init(data: Data) throws {
        // Get original data for serialized
        let originalData = data
        
        // Check minimum length
        guard data.count >= 9 else { // Version (1) + counter (4) + previousCounter (4)
            throw LibNotSignalError.invalidMessage
        }
        
        // Read version (1 byte)
        let version = data[0]
        
        // Read counter (4 bytes)
        let counter: UInt32 = data.subdata(in: 1..<5).withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Read previousCounter (4 bytes)
        let previousCounter: UInt32 = data.subdata(in: 5..<9).withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Read senderRatchetKey length (4 bytes)
        guard data.count >= 13 else {
            throw LibNotSignalError.invalidMessage
        }
        
        let senderRatchetKeyLength: UInt32 = data.subdata(in: 9..<13).withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Read senderRatchetKey
        let senderRatchetKeyEnd = 13 + Int(senderRatchetKeyLength)
        guard data.count >= senderRatchetKeyEnd + 4 else {
            throw LibNotSignalError.invalidMessage
        }
        
        let senderRatchetKey = data.subdata(in: 13..<senderRatchetKeyEnd)
        
        // Read ciphertext length (4 bytes)
        let ciphertextLength: UInt32 = data.subdata(in: senderRatchetKeyEnd..<(senderRatchetKeyEnd + 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Read ciphertext
        let ciphertextStart = senderRatchetKeyEnd + 4
        let ciphertextEnd = ciphertextStart + Int(ciphertextLength)
        
        guard data.count >= ciphertextEnd else {
            throw LibNotSignalError.invalidMessage
        }
        
        let ciphertext = data.subdata(in: ciphertextStart..<ciphertextEnd)
        
        self.init(
            version: version,
            senderRatchetKey: senderRatchetKey,
            counter: counter,
            previousCounter: previousCounter,
            ciphertext: ciphertext,
            serialized: originalData
        )
    }
    
    public func serializedData() -> Data {
        var result = Data()
        
        // Write version (1 byte)
        result.append(version)
        
        // Write counter (4 bytes)
        withUnsafeBytes(of: counter) { result.append(contentsOf: $0) }
        
        // Write previousCounter (4 bytes)
        withUnsafeBytes(of: previousCounter) { result.append(contentsOf: $0) }
        
        // Write sender ratchet key length (4 bytes) and data
        let senderRatchetKeyLength = UInt32(senderRatchetKey.count)
        withUnsafeBytes(of: senderRatchetKeyLength) { result.append(contentsOf: $0) }
        result.append(senderRatchetKey)
        
        // Write ciphertext length (4 bytes) and data
        let ciphertextLength = UInt32(ciphertext.count)
        withUnsafeBytes(of: ciphertextLength) { result.append(contentsOf: $0) }
        result.append(ciphertext)
        
        return result
    }
    
    public static func == (lhs: SignalMessage, rhs: SignalMessage) -> Bool {
        return lhs.version == rhs.version &&
               lhs.senderRatchetKey == rhs.senderRatchetKey &&
               lhs.counter == rhs.counter &&
               lhs.previousCounter == rhs.previousCounter &&
               lhs.ciphertext == rhs.ciphertext
    }
} 