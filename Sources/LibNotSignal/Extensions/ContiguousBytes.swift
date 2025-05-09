import Foundation

// Define our own ContiguousBytes protocol
public protocol ContiguousBytes {
    /// Invokes the given closure with the contents of the underlying storage.
    /// - Parameter body: A closure that takes a raw buffer pointer to the
    ///   collection's contiguous storage and returns a value of type `R`.
    /// - Returns: The value returned by the body closure.
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}

// Make Data conform to ContiguousBytes
extension Data: ContiguousBytes {
    // No need to implement withUnsafeBytes since Data already has this method
    // and it will use the native implementation
}

// Add a generateSignature method to Data for encryption operations
extension Data {
    public func generateSignature(using privateKey: PrivateKey) throws -> Data {
        return try privateKey.sign(self)
    }
    
    public func verifySignature(_ signature: Data, using publicKey: PublicKey) throws -> Bool {
        return try publicKey.verify(signature: signature, for: self)
    }
} 