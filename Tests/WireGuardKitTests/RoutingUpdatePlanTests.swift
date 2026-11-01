import XCTest
@testable import WireGuardKit

final class RoutingUpdatePlanTests: XCTestCase {
    private func configuration(allowed: [String] = ["192.0.2.1/32"], excluded: [String] = []) -> TunnelConfiguration {
        var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
        peer.allowedIPs = allowed.map { IPAddressRange(from: $0)! }
        peer.excludeIPs = excluded.map { IPAddressRange(from: $0)! }
        return TunnelConfiguration(name: "test", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [peer])
    }

    private func copy(_ configuration: TunnelConfiguration) -> TunnelConfiguration {
        return TunnelConfiguration(name: configuration.name, interface: configuration.interface, peers: configuration.peers)
    }

    func testInclusionAdditionChangesOnlyAllowedIPs() throws {
        let old = configuration()
        let requested = copy(old)
        requested.peers[0].allowedIPs.append(IPAddressRange(from: "198.51.100.0/24")!)
        let plan = try XCTUnwrap(RoutingUpdatePlan(previous: old, requested: requested))
        XCTAssertTrue(plan.changesPeer)
        let message = plan.peerConfiguration()
        XCTAssertTrue(message.contains("update_only=true\n"))
        XCTAssertTrue(message.contains("replace_allowed_ips=true\n"))
        XCTAssertFalse(message.contains("replace_peers"))
        XCTAssertFalse(message.contains("private_key"))
        XCTAssertFalse(message.contains("endpoint"))
    }

    func testExclusionAdditionDoesNotRewriteThePeer() throws {
        let old = configuration(allowed: ["0.0.0.0/0", "::/0"], excluded: ["192.0.2.1/32"])
        let requested = copy(old)
        requested.peers[0].excludeIPs.append(IPAddressRange(from: "198.51.100.1/32")!)
        let plan = try XCTUnwrap(RoutingUpdatePlan(previous: old, requested: requested))
        XCTAssertFalse(plan.changesPeer)
    }

    func testRemovalIsRejected() {
        let old = configuration()
        let requested = copy(old)
        requested.peers[0].allowedIPs = []
        XCTAssertNil(RoutingUpdatePlan(previous: old, requested: requested))
    }

    func testExclusionRemovalIsRejected() {
        let old = configuration(excluded: ["198.51.100.1/32"])
        let requested = copy(old)
        requested.peers[0].excludeIPs = []
        XCTAssertNil(RoutingUpdatePlan(previous: old, requested: requested))
    }

    func testSimultaneousAllowedAndExcludedChangesAreRejected() {
        let old = configuration()
        let requested = copy(old)
        requested.peers[0].allowedIPs.append(IPAddressRange(from: "198.51.100.1")!)
        requested.peers[0].excludeIPs.append(IPAddressRange(from: "203.0.113.1")!)
        XCTAssertNil(RoutingUpdatePlan(previous: old, requested: requested))
    }

    func testKeyChangeIsRejected() {
        let old = configuration()
        let requested = copy(old)
        requested.interface.privateKey = PrivateKey()
        XCTAssertNil(RoutingUpdatePlan(previous: old, requested: requested))
    }

    func testPeerReplacementIsRejected() {
        let old = configuration()
        let requested = copy(old)
        requested.peers[0].publicKey = PrivateKey().publicKey
        XCTAssertNil(RoutingUpdatePlan(previous: old, requested: requested))
    }

    func testSnapshotDoesNotAliasMutableCallerConfiguration() throws {
        let old = configuration()
        let requested = copy(old)
        let plan = try XCTUnwrap(RoutingUpdatePlan(previous: old, requested: requested))
        requested.peers.removeAll()
        old.peers.removeAll()
        XCTAssertEqual(plan.previous.peers.count, 1)
        XCTAssertEqual(plan.requested.peers.count, 1)
    }

    func testRuntimeMustConfirmExpectedPeerAndNormalizedPrefixes() throws {
        let old = configuration(allowed: ["192.0.2.9/24"])
        let plan = try XCTUnwrap(RoutingUpdatePlan(previous: old, requested: copy(old)))
        let key = old.peers[0].publicKey.hexKey
        XCTAssertTrue(plan.matchesRuntime("public_key=\(key)\nallowed_ip=192.0.2.0/24\n"))
        XCTAssertFalse(plan.matchesRuntime("public_key=\(key)\nallowed_ip=198.51.100.0/24\n"))
        XCTAssertFalse(plan.matchesRuntime("allowed_ip=192.0.2.0/24\n"))
        XCTAssertFalse(plan.matchesRuntime("public_key=\(key)\npublic_key=\(key)\nallowed_ip=192.0.2.0/24\n"))
    }

    func testEmptyAllowedIPsCompensationExplicitlyClearsTheList() throws {
        let old = configuration(allowed: [])
        let requested = copy(old)
        requested.peers[0].allowedIPs = [IPAddressRange(from: "192.0.2.1/32")!]
        let plan = try XCTUnwrap(RoutingUpdatePlan(previous: old, requested: requested))
        let restore = plan.peerConfiguration(restoring: true)
        XCTAssertTrue(restore.contains("replace_allowed_ips=true\n"))
        XCTAssertFalse(restore.contains("allowed_ip="))
    }
}
