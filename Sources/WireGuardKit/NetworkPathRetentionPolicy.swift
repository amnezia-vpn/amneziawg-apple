// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

enum NetworkPathRetentionPolicy {
    static func shouldPauseBackend(
        hasSatisfiablePath: Bool,
        hasPhysicalInterface: Bool,
        lastNetworkSettingsUpdateAt: Date?,
        now: Date,
        gracePeriod: TimeInterval
    ) -> Bool {
        guard !hasSatisfiablePath else { return false }

        // NetworkExtension can briefly report an unsatisfied path while Wi-Fi or
        // cellular remains available during a route transition. Keep an already
        // established backend alive; WireGuard will resume traffic naturally.
        if hasPhysicalInterface {
            return false
        }

        if let lastNetworkSettingsUpdateAt,
           now.timeIntervalSince(lastNetworkSettingsUpdateAt) < gracePeriod {
            return false
        }

        return true
    }

    static func isPhysicalInterfaceType(_ type: NWInterface.InterfaceType) -> Bool {
        switch type {
        case .wifi, .cellular, .wiredEthernet:
            return true
        case .loopback, .other:
            return false
        @unknown default:
            return false
        }
    }
}
