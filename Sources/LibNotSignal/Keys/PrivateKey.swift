import Foundation
import Crypto

public struct PrivateKey: Codable, Equatable, ContiguousBytes {
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
    
    public static func generate() throws -> PrivateKey {
        let (privateKey, _) = try SignalCrypto.shared.generateKeyPair()
        return PrivateKey(rawKey: privateKey)
    }
    
    public func publicKey() throws -> PublicKey {
        // This is a simplified approach - in a real implementation we'd properly derive the public key
        let (_, publicKey) = try SignalCrypto.shared.generateKeyPair(privateKey: rawKey)
        return PublicKey(rawKey: publicKey)
    }
    
    public func sign(_ message: Data) throws -> Data {
        return try SignalCrypto.shared.sign(privateKey: rawKey, message: message)
    }
    
    public func calculateAgreement(with publicKey: PublicKey) throws -> Data {
        return try SignalCrypto.shared.calculateAgreement(privateKey: rawKey, publicKey: publicKey.rawRepresentation)
    }
    
    // ContiguousBytes conformance
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try rawKey.withUnsafeBytes(body)
    }
} 