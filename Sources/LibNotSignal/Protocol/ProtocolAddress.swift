import Foundation

public struct ProtocolAddress: Hashable, Codable, Equatable, CustomStringConvertible {
    public let name: String
    public let deviceId: UInt32
    
    public init(name: String, deviceId: UInt32) {
        self.name = name
        self.deviceId = deviceId
    }
    
    // Create a ProtocolAddress from a SignalAddress for backward compatibility
    public init(from signalAddress: SignalAddress) {
        self.name = signalAddress.name
        self.deviceId = signalAddress.deviceId
    }
    
    // Convert to a SignalAddress for backward compatibility
    public func toSignalAddress() -> SignalAddress {
        return SignalAddress(name: name, deviceId: deviceId)
    }
    
    public var description: String {
        return "\(name):\(deviceId)"
    }
} 