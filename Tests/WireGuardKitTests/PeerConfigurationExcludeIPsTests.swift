// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import XCTest
import NetworkExtension
@testable import WireGuardKit

final class PeerConfigurationExcludeIPsTests: XCTestCase {
    private func makePeer(excludeIPs: [String]) -> PeerConfiguration {
        var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
        peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]
        peer.excludeIPs = excludeIPs.map { IPAddressRange(from: $0)! }
        return peer
    }

    func testExcludeIPsParticipateInEquality() {
        let base = makePeer(excludeIPs: ["213.59.252.0/22"])
        var same = base
        same.excludeIPs = [IPAddressRange(from: "213.59.252.0/22")!]
        var different = base
        different.excludeIPs = []

        XCTAssertEqual(base, same)
        XCTAssertEqual(base.hashValue, same.hashValue)
        XCTAssertNotEqual(base, different)
    }

    func testExcludeIPsBecomeExcludedRoutes() {
        var interface = InterfaceConfiguration(privateKey: PrivateKey())
        interface.addresses = [IPAddressRange(from: "10.0.0.2/32")!]
        let peer = makePeer(excludeIPs: ["213.59.252.0/22", "fd42::/64"])
        let tunnel = TunnelConfiguration(name: "test", interface: interface, peers: [peer])
        let endpoint = Endpoint(from: "203.0.113.10:51820")

        let settings = PacketTunnelSettingsGenerator(tunnelConfiguration: tunnel, resolvedEndpoints: [endpoint]).generateNetworkSettings()

        let ipv4Excluded = settings.ipv4Settings?.excludedRoutes?.map { "\($0.destinationAddress)/\($0.destinationSubnetMask)" } ?? []
        let ipv6Excluded = settings.ipv6Settings?.excludedRoutes?.map { "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)" } ?? []

        XCTAssertTrue(ipv4Excluded.contains("213.59.252.0/255.255.252.0"), "\(ipv4Excluded)")
        XCTAssertTrue(ipv4Excluded.contains("203.0.113.10/255.255.255.255"), "endpoint must stay excluded: \(ipv4Excluded)")
        XCTAssertTrue(ipv6Excluded.contains("fd42::/64"), "\(ipv6Excluded)")
        XCTAssertEqual(settings.ipv4Settings?.includedRoutes?.count, 2, "interface address + 0.0.0.0/0 only")
    }
}
