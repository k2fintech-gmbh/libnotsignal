import Foundation

// Add Data extensions for serialization
extension Data {
    // This method is to fix "Cannot call value of non-function type 'Data'" error
    // It allows calling data as a function with a buffer argument
    public func callAsFunction(_ buffer: UnsafeRawBufferPointer) -> Data {
        return Data(buffer)
    }
    
    // Another helper method to convert Data to bytes
    public var bytes: [UInt8] {
        return [UInt8](self)
    }
} 