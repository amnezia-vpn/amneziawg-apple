// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import XCTest
@testable import WireGuardKit

final class NetworkPathRetentionPolicyTests: XCTestCase {
    func testKeepsEstablishedBackendWhenPhysicalInterfaceRemainsAvailable() {
        XCTAssertFalse(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: true,
                everHadHandshake: true,
                lastNetworkSettingsUpdateAt: Date().addingTimeInterval(-60),
                now: Date(),
                gracePeriod: 12
            )
        )
    }

    func testPausesEstablishedBackendWhenNoPhysicalInterfaceRemains() {
        XCTAssertTrue(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: false,
                everHadHandshake: true,
                lastNetworkSettingsUpdateAt: Date().addingTimeInterval(-60),
                now: Date(),
                gracePeriod: 12
            )
        )
    }

    func testKeepsBootstrapBackendDuringGracePeriodWithoutPhysicalInterface() {
        XCTAssertFalse(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: false,
                everHadHandshake: true,
                lastNetworkSettingsUpdateAt: Date(),
                now: Date(),
                gracePeriod: 12
            )
        )
    }

    func testKeepsBackendWithoutCompletedHandshake() {
        XCTAssertFalse(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: false,
                everHadHandshake: false,
                lastNetworkSettingsUpdateAt: Date().addingTimeInterval(-60),
                now: Date(),
                gracePeriod: 12
            )
        )
    }
}
