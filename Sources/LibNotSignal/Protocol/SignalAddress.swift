import Foundation

public struct SignalAddress: Hashable, Codable, Equatable, CustomStringConvertible {
    public let name: String
    public let deviceId: UInt32
    
    public init(name: String, deviceId: UInt32) {
        self.name = name
        self.deviceId = deviceId
    }
    
    public var description: String {
        return "\(name):\(deviceId)"
    }
} 