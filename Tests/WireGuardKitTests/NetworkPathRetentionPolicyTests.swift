// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import XCTest
@testable import WireGuardKit

final class NetworkPathRetentionPolicyTests: XCTestCase {
    func testPausesBackendWhenPhysicalInterfaceRemainsUnsatisfiedAfterGracePeriod() {
        XCTAssertTrue(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: true,
                lastNetworkSettingsUpdateAt: Date().addingTimeInterval(-60),
                now: Date(),
                gracePeriod: 12
            )
        )
    }

    func testKeepsBackendWhenPhysicalInterfaceIsUnsatisfiedDuringGracePeriod() {
        let now = Date()
        XCTAssertFalse(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: true,
                lastNetworkSettingsUpdateAt: now.addingTimeInterval(-5),
                now: now,
                gracePeriod: 12
            )
        )
    }

    func testPausesEstablishedBackendWhenNoPhysicalInterfaceRemains() {
        XCTAssertTrue(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: false,
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
                lastNetworkSettingsUpdateAt: Date(),
                now: Date(),
                gracePeriod: 12
            )
        )
    }

    func testPausesBackendWithoutCompletedHandshakeAfterGracePeriod() {
        XCTAssertTrue(
            NetworkPathRetentionPolicy.shouldPauseBackend(
                hasSatisfiablePath: false,
                hasPhysicalInterface: false,
                lastNetworkSettingsUpdateAt: Date().addingTimeInterval(-60),
                now: Date(),
                gracePeriod: 12
            )
        )
    }

    func testTreatsWiredEthernetAsPhysicalInterface() {
        XCTAssertTrue(NetworkPathRetentionPolicy.isPhysicalInterfaceType(.wiredEthernet))
    }
}
