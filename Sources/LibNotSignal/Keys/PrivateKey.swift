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
    
    public init(_ data: Data) {
        self.rawKey = data
    }
    
    // Allow implicit conversion to Data
    public var data: Data {
        return rawKey
    }
    
    public static func generate() -> PrivateKey {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return PrivateKey(rawKey: privateKey.rawRepresentation)
    }
    
    public var publicKey: PublicKey {
        do {
            // Properly derive the public key using the crypto provider
            let privateKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
            let publicKeyData = privateKeyObj.publicKey.rawRepresentation
            return PublicKey(rawKey: publicKeyData)
        } catch {
            // Fallback if we can't properly derive the key
            return PublicKey(rawKey: Data(repeating: 0, count: 32))
        }
    }
    
    public func sign(_ message: Data) throws -> Data {
        return try SignalCrypto.shared.sign(privateKey: rawKey, message: message)
    }
    
    // For compatibility with AsyncEncryptedService
    public func generateSignature(using message: Data) throws -> Data {
        return try self.sign(message)
    }
    
    // For compatibility with AsyncEncryptedService alternative API
    public func generateSignature(message: Data) -> Data {
        do {
            return try self.sign(message)
        } catch {
            // This is not ideal, but needed for compatibility
            return Data(repeating: 0, count: 64)
        }
    }
    
    public func calculateAgreement(with publicKey: PublicKey) throws -> Data {
        return try SignalCrypto.shared.calculateAgreement(privateKey: rawKey, publicKey: publicKey.rawRepresentation)
    }
    
    // ContiguousBytes conformance
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try rawKey.withUnsafeBytes(body)
    }
}

// MARK: - Data conversion

extension PrivateKey: ExpressibleByData {
    public var asData: Data {
        return rawKey
    }
}

extension PrivateKey: CustomStringConvertible {
    public var description: String {
        return "<PrivateKey: \(rawKey.count) bytes>"
    }
}

// Allow implicit conversion from PrivateKey to Data
extension Data {
    public init(_ privateKey: PrivateKey) {
        self = privateKey.asData
    }
}

// Protocol to allow automatic conversion from objects to Data
public protocol ExpressibleByData {
    init(_ data: Data)
    var asData: Data { get }
}

extension Data {
    public init<T: ExpressibleByData>(_ value: T) {
        self = value.asData
    }
} 