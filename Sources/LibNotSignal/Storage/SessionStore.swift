import Foundation

public protocol SessionStore {
    func loadSession(for address: SignalAddress) throws -> SessionState?
    func storeSession(_ session: SessionState, for address: SignalAddress) throws
    func containsSession(for address: SignalAddress) throws -> Bool
    func deleteSession(for address: SignalAddress) throws
    func deleteAllSessions(for name: String) throws
    func getAllAddresses() throws -> [SignalAddress]
} 