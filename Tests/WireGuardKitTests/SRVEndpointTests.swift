// SPDX-License-Identifier: MIT

import XCTest
import Network
@testable import WireGuardKit

final class SRVEndpointTests: XCTestCase {
    func testSystemResolverIntegrationWhenRequested() throws {
        guard let name = ProcessInfo.processInfo.environment["AWG_SRV_INTEGRATION_NAME"], !name.isEmpty else {
            throw XCTSkip("Set AWG_SRV_INTEGRATION_NAME to opt into a live system DNS-SD query")
        }
        let records = try SRVResolver.lookup(name)
        XCTAssertFalse(records.isEmpty)
        let endpoint = try XCTUnwrap(Endpoint(from: "srv://\(name)"))
        let resolved = try DNSResolver.resolveSync(endpoint: endpoint)
        XCTAssertTrue(resolved.hasHostAsIPAddress())
        XCTAssertTrue(records.contains(where: { $0.port == resolved.port.rawValue }))
        print("System SRV discovery resolved \(name) to \(resolved.stringRepresentation)")
    }

    func testExplicitServiceEndpointRoundTrips() throws {
        for text in ["srv://_wireguard._udp.vpn.example.com", "srv://_awg._udp.vpn.example.com."] {
            let endpoint = try XCTUnwrap(Endpoint(from: text))
            XCTAssertEqual(endpoint.stringRepresentation, text)
            XCTAssertEqual(endpoint.srvRecordName, String(text.dropFirst(6)))
            XCTAssertFalse(endpoint.hasHostAsIPAddress())
        }
    }

    func testFixedEndpointsRemainUnchanged() throws {
        for text in ["vpn.example.com:51820", "192.0.2.1:51820", "[2001:db8::1]:51820"] {
            let endpoint = try XCTUnwrap(Endpoint(from: text))
            XCTAssertNil(endpoint.srvRecordName)
            XCTAssertEqual(endpoint.stringRepresentation, text)
        }
    }

    func testRejectsAmbiguousServiceEndpoints() {
        for text in ["srv://", "srv://vpn.example.com", "srv://_wg._tcp.example.com",
                     "srv://_wg._udp.example.com:51820", "srv://_wg._udp.example.com/path",
                     "srv://_wg._udp.example.com?port=1", "srv://_wg._udp..example.com",
                     "srv://_wg._udp.example.com..", "srv://_wg._udp.exam ple.com",
                     "srv://_wg._udp." + String(repeating: "a", count: 64) + ".com"] {
            XCTAssertNil(Endpoint(from: text), text)
        }
    }

    func testDiscoveryDoesNotCompareEqualToAPortZeroHostname() throws {
        let discovered = try XCTUnwrap(Endpoint(from: "srv://_wg._udp.example.com"))
        let fixed = try XCTUnwrap(Endpoint(from: "_wg._udp.example.com:0"))
        XCTAssertNotEqual(discovered, fixed)
        XCTAssertEqual(Set([discovered, fixed]).count, 2)
    }

    func testParsesNetworkByteOrderAndTarget() throws {
        let record = try makeRecord(priority: 10, weight: 20, port: 9783, target: "vpn.example.com")
        XCTAssertEqual(record.priority, 10)
        XCTAssertEqual(record.weight, 20)
        XCTAssertEqual(record.port, 9783)
        XCTAssertEqual(record.target, "vpn.example.com.")
    }

    func testRejectsTruncatedCompressedAndMalformedRdata() {
        let invalid: [[UInt8]] = [[], [0, 1, 0, 1, 0, 1], [0, 1, 0, 1, 0, 1, 3, 97],
                              [0, 1, 0, 1, 0, 1, 0xc0, 0x0c],
                              [0, 1, 0, 1, 0, 1, 1, 97, 0, 1],
                              [0, 1, 0, 1, 0, 1, 1, 255, 0],
                              [0, 1, 0, 1, 0, 0, 1, 97, 0]]
        for bytes in invalid {
            XCTAssertNil(SRVRecord(rdata: Data(bytes)))
        }
    }

    func testRejectsOverlongTarget() {
        var bytes: [UInt8] = [0, 0, 0, 0, 0, 1]
        for _ in 0..<4 { bytes += [63] + Array(repeating: UInt8(97), count: 63) }
        bytes += [0]
        XCTAssertNil(SRVRecord(rdata: Data(bytes)))
    }

    func testRootTargetSignalsUnavailableService() throws {
        let record = try makeRecord(port: 0, target: ".")
        XCTAssertEqual(record.target, ".")
        let endpoint = try XCTUnwrap(Endpoint(from: "srv://_wg._udp.example.com"))
        XCTAssertThrowsError(try DNSResolver.resolveSync(endpoint: endpoint, lookupSRV: { _ in [record] }, resolveAddress: { _ in
            XCTFail("An unavailable service must not fall back to an address lookup")
            throw DNSResolutionError(errorCode: 1, address: "unexpected")
        }))
    }

    func testPriorityPrecedesWeightAndRecordsAreNotRepeated() throws {
        let first = try makeRecord(priority: 1, weight: 0, port: 1)
        let second = try makeRecord(priority: 2, weight: 65535, port: 2)
        XCTAssertEqual(SRVRecord.ordered([second, first]), [first, second])
    }

    func testWeightsAndZeroWeightBoundary() throws {
        let zero = try makeRecord(weight: 0, port: 1)
        let low = try makeRecord(weight: 1, port: 2)
        let high = try makeRecord(weight: 9, port: 3)
        XCTAssertEqual(SRVRecord.ordered([low, high, zero], random: { _ in 0 }).first, zero)
        XCTAssertEqual(SRVRecord.ordered([low, high], random: { $0.upperBound }).first, high)
        XCTAssertEqual(SRVRecord.ordered([zero, zero], random: { $0.lowerBound }).count, 2)
    }

    func testAddressFailureTriesNextPriorityAndUsesDiscoveredPort() throws {
        let endpoint = try XCTUnwrap(Endpoint(from: "srv://_wg._udp.example.com"))
        let records = [try makeRecord(priority: 1, port: 1000, target: "unavailable.example.com"),
                       try makeRecord(priority: 2, port: 9783, target: "vpn.example.com")]
        var attempted = [String]()
        let resolved = try DNSResolver.resolveSync(endpoint: endpoint, lookupSRV: { name in
            XCTAssertEqual(name, "_wg._udp.example.com")
            return records
        }, resolveAddress: { candidate in
            attempted.append(candidate.stringRepresentation)
            if candidate.port.rawValue == 1000 {
                throw DNSResolutionError(errorCode: 1, address: candidate.hostname()!)
            }
            return Endpoint(host: .ipv4(IPv4Address("192.0.2.1")!), port: candidate.port)
        })
        XCTAssertEqual(attempted, ["unavailable.example.com.:1000", "vpn.example.com.:9783"])
        XCTAssertEqual(resolved.stringRepresentation, "192.0.2.1:9783")
        XCTAssertNil(resolved.srvRecordName)
    }

    func testFixedEndpointDoesNotQuerySRV() throws {
        let endpoint = try XCTUnwrap(Endpoint(from: "vpn.example.com:51820"))
        let resolved = try DNSResolver.resolveSync(endpoint: endpoint, lookupSRV: { _ in
            XCTFail("SRV lookup must be opt-in")
            return []
        }, resolveAddress: { $0 })
        XCTAssertEqual(resolved, endpoint)
    }

    func testEmptyAnswerAndLookupFailureAreReported() throws {
        let endpoint = try XCTUnwrap(Endpoint(from: "srv://_wg._udp.example.com"))
        XCTAssertThrowsError(try DNSResolver.resolveSync(endpoint: endpoint, lookupSRV: { _ in [] }, resolveAddress: { $0 }))
        XCTAssertThrowsError(try DNSResolver.resolveSync(endpoint: endpoint, lookupSRV: { _ in
            throw DNSResolutionError(errorCode: 1, address: "_wg._udp.example.com")
        }, resolveAddress: { $0 }))
    }

    func testRefreshUpdatesOnlyServicePeersAndPreservesConfiguration() throws {
        let fixture = try generator()
        let changed = try XCTUnwrap(Endpoint(from: "192.0.2.1:60000"))
        let (config, _, endpoints) = fixture.srvEndpointUapiConfiguration { requested in
            XCTAssertNotNil(requested[0]?.srvRecordName)
            XCTAssertNil(requested[1])
            return [.success(changed), nil]
        }
        XCTAssertTrue(config.contains("endpoint=192.0.2.1:60000\n"))
        XCTAssertFalse(config.contains("replace_peers"))
        XCTAssertFalse(config.contains("private_key"))
        XCTAssertEqual(endpoints[0], changed)
        XCTAssertEqual(endpoints[1], fixture.resolvedEndpoints[1])
        XCTAssertNotNil(fixture.tunnelConfiguration.peers[0].endpoint?.srvRecordName)
    }

    func testRefreshFailureRetainsLastWorkingEndpoint() throws {
        let fixture = try generator()
        let (config, _, endpoints) = fixture.srvEndpointUapiConfiguration { _ in
            [.failure(DNSResolutionError(errorCode: 1, address: "_wg._udp.example.com")), nil]
        }
        XCTAssertTrue(config.isEmpty)
        XCTAssertEqual(endpoints, fixture.resolvedEndpoints)
    }

    func testUnchangedAnswerDoesNotResetBackendRoaming() throws {
        let fixture = try generator()
        let (config, _, _) = fixture.srvEndpointUapiConfiguration { _ in
            [.success(fixture.resolvedEndpoints[0]!), nil]
        }
        XCTAssertTrue(config.isEmpty)
    }

    private func makeRecord(priority: UInt16 = 0, weight: UInt16 = 0, port: UInt16, target: String = "vpn.example.com") throws -> SRVRecord {
        var bytes = [UInt8]()
        for value in [priority, weight, port] { bytes += [UInt8(value >> 8), UInt8(value & 255)] }
        if target != "." {
            for label in target.split(separator: ".") { bytes += [UInt8(label.utf8.count)] + Array(label.utf8) }
        }
        bytes += [0]
        return try XCTUnwrap(SRVRecord(rdata: Data(bytes)))
    }

    private func generator() throws -> PacketTunnelSettingsGenerator {
        var service = PeerConfiguration(publicKey: PrivateKey().publicKey)
        service.endpoint = try XCTUnwrap(Endpoint(from: "srv://_wg._udp.example.com"))
        var fixed = PeerConfiguration(publicKey: PrivateKey().publicKey)
        fixed.endpoint = try XCTUnwrap(Endpoint(from: "192.0.2.2:51820"))
        let tunnel = TunnelConfiguration(name: "SRV test", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [service, fixed])
        return PacketTunnelSettingsGenerator(tunnelConfiguration: tunnel, resolvedEndpoints: [Endpoint(from: "192.0.2.1:9783"), fixed.endpoint])
    }
}
