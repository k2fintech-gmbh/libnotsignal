import Foundation

public class SessionRecord: Codable, Equatable {
    public var sessionState: SessionState
    public var previousStates: [SessionState] = []
    
    // Maximum number of previous session states we keep
    private static let maxPreviousSessionStates = 40
    
    public init(sessionState: SessionState = SessionState()) {
        self.sessionState = sessionState
    }
    
    public convenience init(bytes: [UInt8]) throws {
        let data = Data(bytes)
        let decoder = JSONDecoder()
        let record = try decoder.decode(SessionRecord.self, from: data)
        self.init(sessionState: record.sessionState)
        self.previousStates = record.previousStates
    }
    
    public func serialize() throws -> Data {
        let encoder = JSONEncoder()
        return try encoder.encode(self)
    }
    
    public static func == (lhs: SessionRecord, rhs: SessionRecord) -> Bool {
        return lhs.sessionState == rhs.sessionState &&
               lhs.previousStates == rhs.previousStates
    }
    
    public func archiveCurrentState() {
        let currentState = sessionState
        previousStates.insert(currentState, at: 0)
        sessionState = SessionState()
        
        // Trim excess states
        if previousStates.count > Self.maxPreviousSessionStates {
            previousStates.removeLast(previousStates.count - Self.maxPreviousSessionStates)
        }
    }
    
    public func promoteState(_ promotedState: SessionState) {
        if promotedState !== sessionState {
            // Remove the state from previous states if it's there
            previousStates.removeAll { $0 === promotedState }
            
            // Archive current state
            previousStates.insert(sessionState, at: 0)
            
            // Set the promoted state as current
            sessionState = promotedState
            
            // Trim excess states
            if previousStates.count > Self.maxPreviousSessionStates {
                previousStates.removeLast(previousStates.count - Self.maxPreviousSessionStates)
            }
        }
    }
    
    public func hasSessionState(version: UInt32, aliceBaseKey: Data) -> Bool {
        // For now, we only support protocol version 3
        if version != 3 {
            return false
        }
        
        // Check if current state matches
        if sessionState.remoteIdentityKey != nil {
            return true
        }
        
        // Check previous states
        return previousStates.contains { state in
            state.remoteIdentityKey != nil
        }
    }
} 