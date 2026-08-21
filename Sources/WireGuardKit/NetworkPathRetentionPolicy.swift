// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

enum NetworkPathRetentionPolicy {
    static func shouldPauseBackend(
        hasSatisfiablePath: Bool,
        hasPhysicalInterface _: Bool,
        lastNetworkSettingsUpdateAt graceStartedAt: Date?,
        now: Date,
        gracePeriod: TimeInterval
    ) -> Bool {
        guard !hasSatisfiablePath else { return false }

        // The adapter supplies the newest relevant grace anchor: either the
        // network-settings update or the start of an unsatisfied physical-path
        // transition. A listed interface alone is not proof of connectivity.
        if let graceStartedAt,
           now.timeIntervalSince(graceStartedAt) < gracePeriod {
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
