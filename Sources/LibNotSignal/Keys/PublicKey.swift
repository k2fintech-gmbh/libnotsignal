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
    
    public var rawRepresentation: Data {
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