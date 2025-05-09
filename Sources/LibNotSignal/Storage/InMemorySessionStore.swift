import Foundation

public class InMemorySessionStore: SessionStore {
    private var sessions: [String: SessionRecord] = [:]
    
    public init() {}
    
    // Protocol methods
    public func loadSession(for address: SignalAddress) throws -> SessionState? {
        let key = address.description
        return sessions[key]?.sessionState
    }
    
    public func storeSession(_ session: SessionState, for address: SignalAddress) throws {
        let key = address.description
        if let existingRecord = sessions[key] {
            existingRecord.sessionState = session
        } else {
            sessions[key] = SessionRecord(sessionState: session)
        }
    }
    
    public func containsSession(for address: SignalAddress) throws -> Bool {
        let key = address.description
        return sessions[key] != nil
    }
    
    public func deleteSession(for address: SignalAddress) throws {
        let key = address.description
        sessions.removeValue(forKey: key)
    }
    
    public func deleteAllSessions(for name: String) throws {
        let keysToRemove = sessions.keys.filter { $0.hasPrefix("\(name):") }
        for key in keysToRemove {
            sessions.removeValue(forKey: key)
        }
    }
    
    public func getAllAddresses() throws -> [SignalAddress] {
        return sessions.keys.compactMap { key in
            let components = key.split(separator: ":")
            if components.count == 2, let deviceId = UInt32(components[1]) {
                return SignalAddress(name: String(components[0]), deviceId: deviceId)
            }
            return nil
        }
    }
    
    // Legacy methods with ProtocolAddress and context
    public func loadSession(for address: ProtocolAddress, context: Any?) throws -> SessionRecord? {
        return sessions[address.description]
    }
    
    public func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: Any?) throws {
        sessions[address.description] = record
    }
    
    public func containsSession(for address: ProtocolAddress, context: Any?) throws -> Bool {
        return sessions[address.description] != nil
    }
    
    public func deleteSession(for address: ProtocolAddress, context: Any?) throws {
        sessions.removeValue(forKey: address.description)
    }
    
    public func deleteAllSessions(for name: String, context: Any?) throws {
        try deleteAllSessions(for: name)
    }
} 