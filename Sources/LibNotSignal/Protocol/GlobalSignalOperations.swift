import Foundation

// MARK: - Recreated Global Signal Operations for Compatibility

// Corresponds to:
// try signalEncrypt(message: buf, for: remoteUserProtocolAddress, sessionStore: protocolStore, identityStore: protocolStore, context: NullContext())
// In the new API, encryption is handled by SessionCipher.
public func signalEncrypt(
    message: [UInt8], // Original was [UInt8], SessionCipher expects Data
    for remoteAddress: ProtocolAddress, // Original name
    sessionStore: SignalProtocolStore, // Assuming this is the primary store
    identityStore: SignalProtocolStore, // Will use sessionStore, or needs more complex logic
    context: NullContext // Ignored for now
) throws -> CiphertextMessage { // Original return type
    
    let signalAddress = SignalAddress(name: remoteAddress.name, deviceId: remoteAddress.deviceId)
    let cipher = SessionCipher(store: sessionStore, remoteAddress: signalAddress)
    
    // The original EncryptedSession.swift passed [UInt8], SessionCipher.encrypt takes Data.
    let messageData = Data(message)
    
    return try cipher.encrypt(messageData)
}

// Corresponds to:
// try signalDecryptPreKey(message: preKeySignalMessage, from: remoteUserProtocolAddress, sessionStore: protocolStore, identityStore: protocolStore, preKeyStore: protocolStore, signedPreKeyStore: protocolStore, kyberPreKeyStore: protocolStore, context: NullContext())
// In the new API, PreKey decryption is handled by SessionCipher.
public func signalDecryptPreKey(
    message: PreKeySignalMessage, // Original type
    from remoteAddress: ProtocolAddress, // Original name
    sessionStore: SignalProtocolStore, // Primary store
    identityStore: SignalProtocolStore,
    preKeyStore: SignalProtocolStore,
    signedPreKeyStore: SignalProtocolStore,
    kyberPreKeyStore: SignalProtocolStore, // This store is not in the new simple SessionCipher.
                                         // If Kyber support was separate, this needs more thought.
                                         // For now, assuming SessionCipher handles it via the main store.
    context: NullContext // Ignored
) throws -> [UInt8] { // Original was [UInt8] (plain text bytes)
    
    let signalAddress = SignalAddress(name: remoteAddress.name, deviceId: remoteAddress.deviceId)
    // SessionBuilder is typically used for initial PreKeyMessage processing to establish a session.
    // SessionCipher.decrypt(preKeyMessage:) handles this.
    let cipher = SessionCipher(store: sessionStore, remoteAddress: signalAddress)
    
    let plaintextData = try cipher.decrypt(preKeyMessage: message)
    return [UInt8](plaintextData)
}

// Corresponds to:
// try signalDecrypt(message: signalMessage, from: remoteUserProtocolAddress, sessionStore: protocolStore, identityStore: protocolStore, context: NullContext())
// In the new API, regular message decryption is handled by SessionCipher.
public func signalDecrypt(
    message: SignalMessage, // Original type
    from remoteAddress: ProtocolAddress, // Original name
    sessionStore: SignalProtocolStore, // Primary store
    identityStore: SignalProtocolStore,
    context: NullContext // Ignored
) throws -> [UInt8] { // Original was [UInt8]
    
    let signalAddress = SignalAddress(name: remoteAddress.name, deviceId: remoteAddress.deviceId)
    let cipher = SessionCipher(store: sessionStore, remoteAddress: signalAddress)
    
    let plaintextData = try cipher.decrypt(message: message)
    return [UInt8](plaintextData)
}

// Corresponds to:
// try processPreKeyBundle(preKeyBundle, for: remoteUser.protocolAddress, sessionStore: protocolStore, identityStore: protocolStore, context: NullContext())
// In the new API, PreKeyBundle processing is handled by SessionBuilder.
public func processPreKeyBundle(
    _ bundle: PreKeyBundle, // Original type, first argument no label
    for remoteAddress: ProtocolAddress, // Original name
    sessionStore: SignalProtocolStore, // Primary store
    identityStore: SignalProtocolStore,
    context: NullContext // Ignored
) throws {
    let signalAddress = SignalAddress(name: remoteAddress.name, deviceId: remoteAddress.deviceId)
    // SessionBuilder is responsible for processing PreKeyBundles to establish a session.
    let builder = SessionBuilder(store: sessionStore, remoteAddress: signalAddress)
    
    // SessionBuilder has process(preKeyBundle: PreKeyBundle)
    try builder.process(preKeyBundle: bundle)
} 