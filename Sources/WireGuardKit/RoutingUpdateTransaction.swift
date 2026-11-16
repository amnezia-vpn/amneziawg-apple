import Foundation

public enum WireGuardRoutingUpdateResult: Equatable {
    case applied
    case notApplied
    case stateUnknown
}

enum NetworkSettingsApplication {
    case applied
    case rejected(Error)
    case stateUnknown
}

final class NetworkSettingsCompletion {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var result: NetworkSettingsApplication?

    func complete(_ error: Error?) {
        lock.lock()
        guard result == nil else {
            lock.unlock()
            return
        }
        result = error.map(NetworkSettingsApplication.rejected) ?? .applied
        lock.unlock()
        semaphore.signal()
    }

    func wait(timeout: TimeInterval) -> NetworkSettingsApplication {
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            return .stateUnknown
        }
        lock.lock()
        defer { lock.unlock() }
        return result ?? .stateUnknown
    }
}

struct RoutingUpdateTransaction {
    struct Operations {
        let updatePeer: () -> Bool
        let applySettings: () -> NetworkSettingsApplication
        let restoreSettings: () -> NetworkSettingsApplication
        let restorePeer: () -> Bool
    }

    static func apply(_ operations: Operations) -> WireGuardRoutingUpdateResult {
        guard operations.updatePeer() else {
            return operations.restorePeer() ? .notApplied : .stateUnknown
        }
        switch operations.applySettings() {
        case .applied:
            return .applied
        case .stateUnknown:
            return .stateUnknown
        case .rejected:
            let settingsRestored: Bool
            if case .applied = operations.restoreSettings() {
                settingsRestored = true
            } else {
                settingsRestored = false
            }
            let peerRestored = operations.restorePeer()
            return settingsRestored && peerRestored ? .notApplied : .stateUnknown
        }
    }
}
