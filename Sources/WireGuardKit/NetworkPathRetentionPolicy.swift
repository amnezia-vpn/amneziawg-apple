// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation

enum NetworkPathRetentionPolicy {
    static func shouldPauseBackend(
        hasSatisfiablePath: Bool,
        hasPhysicalInterface: Bool,
        everHadHandshake: Bool,
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

        return everHadHandshake
    }
}
