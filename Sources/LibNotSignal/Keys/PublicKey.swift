import Foundation
import Crypto

public struct PublicKey: Codable, Equatable, ContiguousBytes {
    private let rawKey: Data
    
    public init(rawKey: Data) {
        self.rawKey = rawKey
    }
    
    public init<D: ContiguousBytes>(rawRepresentation bytes: D) {
        var data = Data()
        bytes.withUnsafeBytes { buffer in
            data.append(contentsOf: buffer)
        }
        self.rawKey = data
    }
    
    public init(_ data: Data) {
        self.rawKey = data
    }
    
    public var rawRepresentation: Data {
        return rawKey
    }
    
    // Allow implicit conversion to Data
    public var data: Data {
        return rawKey
    }
    
    public func verify(signature: Data, for message: Data) throws -> Bool {
        return try SignalCrypto.shared.verify(publicKey: rawKey, message: message, signature: signature)
    }
    
    // ContiguousBytes conformance
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try rawKey.withUnsafeBytes(body)
    }
}

// MARK: - Data conversion

extension PublicKey: ExpressibleByData {
    public var asData: Data {
        return rawKey
    }
}

extension PublicKey: CustomStringConvertible {
    public var description: String {
        return "<PublicKey: \(rawKey.count) bytes>"
    }
}

// Allow implicit conversion from PublicKey to Data
extension Data {
    public init(_ publicKey: PublicKey) {
        self = publicKey.asData
    }
} 