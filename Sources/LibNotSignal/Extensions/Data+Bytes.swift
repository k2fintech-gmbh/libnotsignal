import Foundation

public extension Data {
    /// Returns an array of bytes from the Data object.
    var byteArray: [UInt8] {
        return [UInt8](self)
    }

    /// Initializes Data from an array of bytes.
    /// - Parameter bytes: The array of UInt8 to create Data from. If nil, creates an empty Data object.
    init(_ bytes: [UInt8]?) {
        guard let bytes = bytes else {
            self = Data()
            return
        }
        self = Data(bytes)
    }
} 