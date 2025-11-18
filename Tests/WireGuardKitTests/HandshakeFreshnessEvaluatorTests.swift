// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import XCTest
@testable import WireGuardKit

final class HandshakeFreshnessEvaluatorTests: XCTestCase {
    func testNoPeersIsNotFresh() {
        XCTAssertFalse(HandshakeFreshnessEvaluator.containsFreshHandshake(peers: [], cutoffDate: Date()))
    }

    func testPeersWithoutHandshakeAreNotFresh() throws {
        let peer = try makePeer()
        XCTAssertNil(peer.lastHandshakeTime)
        XCTAssertFalse(HandshakeFreshnessEvaluator.containsFreshHandshake(peers: [peer], cutoffDate: Date()))
    }

    func testHandshakeExactlyAtCutoffIsFresh() throws {
        var peer = try makePeer()
        let handshake = Date()
        peer.lastHandshakeTime = handshake
        XCTAssertTrue(HandshakeFreshnessEvaluator.containsFreshHandshake(peers: [peer], cutoffDate: handshake))
    }

    func testLatestHandshakeOlderThanCutoffIsNotFresh() throws {
        var peer = try makePeer()
        let handshake = Date().addingTimeInterval(-10)
        peer.lastHandshakeTime = handshake
        XCTAssertFalse(HandshakeFreshnessEvaluator.containsFreshHandshake(peers: [peer], cutoffDate: Date()))
    }

    func testAnyFreshPeerIsEnough() throws {
        var stalePeer = try makePeer(index: 1)
        stalePeer.lastHandshakeTime = Date().addingTimeInterval(-20)

        var freshPeer = try makePeer(index: 2)
        let cutoff = Date()
        freshPeer.lastHandshakeTime = cutoff.addingTimeInterval(1)

        XCTAssertTrue(HandshakeFreshnessEvaluator.containsFreshHandshake(peers: [stalePeer, freshPeer], cutoffDate: cutoff))
    }

    // MARK: - Helpers

    private func makePeer(index: Int = 0) throws -> PeerConfiguration {
        let privateKey = PrivateKey()
        var peer = PeerConfiguration(publicKey: privateKey.publicKey)
        peer.persistentKeepAlive = UInt16(index)
        return peer
    }
}
