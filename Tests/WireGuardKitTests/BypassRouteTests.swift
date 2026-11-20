// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

#if os(macOS)
import dnssd
import NetworkExtension
import XCTest
@testable import WireGuardKit

final class BypassRouteTests: XCTestCase {
    func testEmptyPolicyKeepsBaselineRoutesAndSkipsDNS() {
        let config = makeConfiguration(allowed: ["0.0.0.0/0", "::/0"])
        let routes = snapshot(hostnames: [], allowedIPs: config.peers[0].allowedIPs) { _ in
            XCTFail("An empty policy must skip DNS resolution")
            return []
        }
        XCTAssertEqual(routes, [])

        let settings = makeGenerator(config).generateNetworkSettings()
        XCTAssertTrue(settings.ipv4Settings?.includedRoutes?.contains {
            $0.destinationAddress == "0.0.0.0" && $0.destinationSubnetMask == "0.0.0.0"
        } == true)
        XCTAssertTrue(settings.ipv6Settings?.includedRoutes?.contains {
            $0.destinationAddress == "::" && $0.destinationNetworkPrefixLength.intValue == 0
        } == true)
        XCTAssertEqual(settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress), ["192.0.2.5"])
        XCTAssertEqual(settings.ipv6Settings?.excludedRoutes?.count, 0)
    }

    func testDualStackSnapshotRetainsIncludedRoutesAndExistingExclusions() throws {
        let config = makeConfiguration(allowed: ["0.0.0.0/0", "::/0"])
        config.peers[0].excludeIPs = [range("192.0.2.128/25")]
        let generator = makeGenerator(config)
        let baseline = generator.generateNetworkSettings()
        let backendBefore = generator.uapiConfiguration().0

        let routes = try XCTUnwrap(snapshot(
            hostnames: ["first.example", "second.example"], allowedIPs: config.peers[0].allowedIPs,
            dnsServers: config.interface.dns
        ) { hostname in
            switch hostname {
            case "first.example.":
                return ["198.51.100.2/32", "2001:db8::2/128"].map(self.range)
            case "second.example.":
                return ["198.51.100.2/32", "2001:db8::3/128"].map(self.range)
            default:
                XCTFail("Unexpected DNS query: \(hostname)")
                return []
            }
        })
        config.peers[0].excludeIPs.append(contentsOf: routes)

        let settings = generator.generateNetworkSettings()
        let ipv4RouteValues = { (route: NEIPv4Route) in
            [route.destinationAddress, route.destinationSubnetMask, route.gatewayAddress]
        }
        let ipv6RouteValues = { (route: NEIPv6Route) in
            [route.destinationAddress, route.destinationNetworkPrefixLength.stringValue, route.gatewayAddress]
        }
        XCTAssertEqual(settings.ipv4Settings?.includedRoutes?.map(ipv4RouteValues), baseline.ipv4Settings?.includedRoutes?.map(ipv4RouteValues))
        XCTAssertEqual(settings.ipv6Settings?.includedRoutes?.map(ipv6RouteValues), baseline.ipv6Settings?.includedRoutes?.map(ipv6RouteValues))
        XCTAssertEqual(settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress), ["192.0.2.5", "192.0.2.128", "198.51.100.2"])
        XCTAssertEqual(settings.ipv4Settings?.excludedRoutes?.last?.destinationSubnetMask, "255.255.255.255")
        XCTAssertEqual(settings.ipv6Settings?.excludedRoutes?.map(\.destinationAddress), ["2001:db8::2", "2001:db8::3"])
        XCTAssertEqual(settings.ipv6Settings?.excludedRoutes?.map { $0.destinationNetworkPrefixLength.intValue }, [128, 128])
        let dns = try XCTUnwrap(settings.dnsSettings)
        XCTAssertEqual(dns.servers, baseline.dnsSettings?.servers)
        XCTAssertEqual(dns.searchDomains, baseline.dnsSettings?.searchDomains)
        XCTAssertEqual(dns.matchDomains, baseline.dnsSettings?.matchDomains)
        XCTAssertEqual(generator.uapiConfiguration().0, backendBefore)
    }

    func testSnapshotUsesOnlyFamiliesWithADefaultRoute() {
        let ipv4 = range("198.51.100.2/32")
        let ipv6 = range("2001:db8::2/128")
        for (allowed, expected) in [(["0.0.0.0/0", "2001:db8::/64"], ipv4), (["::/0"], ipv6)] {
            let routes = snapshot(hostnames: ["host.example"], allowedIPs: allowed.map(range)) { _ in
                [ipv4, ipv6]
            }
            XCTAssertEqual(routes, [expected])
        }
    }

    func testOneUnresolvedHostnameInvalidatesTheWholeSnapshot() {
        let routes = snapshot(
            hostnames: ["first.example", "missing.example"], allowedIPs: [range("0.0.0.0/0")]
        ) { hostname in
            hostname == "first.example." ? [self.range("198.51.100.2/32")] : []
        }
        XCTAssertNil(routes)
    }

    func testSnapshotRejectsUntunneledAnswersAndTunnelDNSConflicts() throws {
        let allowed = [range("0.0.0.0/0")]
        let dnsServer = try XCTUnwrap(DNSServer(from: "198.51.100.2"))
        XCTAssertNil(snapshot(hostnames: ["host.example"], allowedIPs: allowed) { _ in
            [self.range("2001:db8::2/128")]
        })
        XCTAssertNil(snapshot(hostnames: ["host.example"], allowedIPs: allowed, dnsServers: [dnsServer]) { _ in
            [self.range("198.51.100.2/32"), self.range("198.51.100.3/32")]
        })
    }

    func testEachSnapshotQueriesAgainWithoutReusingOldRoutes() {
        let allowed = [range("0.0.0.0/0")]
        let old = range("198.51.100.2/32")
        let new = range("198.51.100.3/32")
        var replies = [[old], [new], []]
        func resolve() -> [IPAddressRange]? {
            snapshot(hostnames: ["host.example"], allowedIPs: allowed) { _ in
                replies.removeFirst()
            }
        }
        XCTAssertEqual(resolve(), [old])
        XCTAssertEqual(resolve(), [new])
        XCTAssertNil(resolve())
    }

    func testSupersedingLookupCancelsStalledQueryAndRejectsItsLateAnswer() {
        var callbacks = [DNSResolver.BypassLookup.Completion]()
        var cancelled = [String]()
        let resolver = DNSResolver.BypassLookup { name, _, reply in
            callbacks.append(reply)
            return { cancelled.append(name) }
        }
        let allowed = [range("0.0.0.0/0")]
        let cancelledStart = expectation(description: "Superseded start")
        let retry = expectation(description: "New start succeeds")
        resolver.start(hostnames: ["old.example"], allowedIPs: allowed, dnsServers: []) { result in
            guard case .failure(.cancelled) = result else { return XCTFail("Old start was not cancelled") }
            cancelledStart.fulfill()
        }
        let expected = range("198.51.100.3/32")
        resolver.start(hostnames: ["new.example"], allowedIPs: allowed, dnsServers: []) { result in
            XCTAssertEqual(try? result.get(), [expected])
            retry.fulfill()
        }
        XCTAssertEqual(cancelled, ["old.example."])
        XCTAssertEqual(callbacks.count, 2)
        callbacks[0](.success([range("198.51.100.2/32")]))
        callbacks[1](.success([expected]))
        wait(for: [cancelledStart, retry], timeout: 1)
        XCTAssertEqual(cancelled, ["old.example.", "new.example."])
    }

    func testExplicitCancellationDiscardsAnAlreadyQueuedAnswer() {
        var reply: DNSResolver.BypassLookup.Completion?
        var cancellations = 0
        let resolver = DNSResolver.BypassLookup { _, _, callback in
            reply = callback
            return { cancellations += 1 }
        }
        let cancelled = expectation(description: "Cancelled start")
        resolver.start(hostnames: ["host.example"], allowedIPs: [range("0.0.0.0/0")], dnsServers: []) { result in
            guard case .failure(.cancelled) = result else { return XCTFail("Cancelled start produced routes") }
            cancelled.fulfill()
        }
        reply?(.success([range("198.51.100.2/32")]))
        XCTAssertTrue(resolver.cancel())
        XCTAssertFalse(resolver.cancel())
        let drained = expectation(description: "Queued answer discarded")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [cancelled, drained], timeout: 1)
        XCTAssertEqual(cancellations, 1)
    }

    func testTimedOutQueryReleasesItsResourcesAndCanRetry() {
        var cancellations = 0
        let expected = range("198.51.100.2/32")
        let resolver = DNSResolver.BypassLookup { name, _, reply in
            if name == "retry.example." { reply(.success([expected])) }
            return { cancellations += 1 }
        }
        let allowed = [range("0.0.0.0/0")]
        let timeout = expectation(description: "Stalled query timed out")
        resolver.start(hostnames: ["stall.example"], allowedIPs: allowed, dnsServers: [], timeout: .milliseconds(40)) { result in
            guard case .failure(.unresolved) = result else { return XCTFail("Stalled start produced routes") }
            timeout.fulfill()
        }
        wait(for: [timeout], timeout: 2)
        XCTAssertEqual(cancellations, 1)
        let retry = expectation(description: "Retry succeeds")
        resolver.start(hostnames: ["retry.example"], allowedIPs: allowed, dnsServers: []) { result in
            XCTAssertEqual(try? result.get(), [expected])
            retry.fulfill()
        }
        wait(for: [retry], timeout: 1)
        XCTAssertEqual(cancellations, 2)
    }

    func testAOnlyAnswerSucceedsWithDualStackDefaults() {
        let address = range("198.51.100.2/32")
        XCTAssertEqual(snapshot(hostnames: ["host.example"], allowedIPs: ["0.0.0.0/0", "::/0"].map(range)) { _ in
            [address]
        }, [address])
    }

    func testIPv4DefaultDoesNotQueryFailingAAAAFamily() {
        let ipv4 = DNSServiceProtocol(kDNSServiceProtocol_IPv4)
        let address = range("198.51.100.2/32")
        let resolver = DNSResolver.BypassLookup { _, families, reply in
            XCTAssertEqual(families, [ipv4])
            reply(families == [ipv4] ? .success([address]) : .failure(.unresolved))
            return {}
        }
        XCTAssertEqual(resolve(resolver, hostnames: ["host.example"], allowedIPs: [range("0.0.0.0/0")]), .success([address]))
    }

    func testIPv6DefaultDoesNotWaitForUnusedAQuery() {
        let ipv6 = DNSServiceProtocol(kDNSServiceProtocol_IPv6)
        let address = range("2001:db8::2/128")
        let resolver = DNSResolver.BypassLookup { _, families, reply in
            XCTAssertEqual(families, [ipv6])
            if families == [ipv6] { reply(.success([address])) }
            return {}
        }
        XCTAssertEqual(resolve(resolver, hostnames: ["host.example"], allowedIPs: [range("::/0")]), .success([address]))
    }

    func testDualStackQueriesBothFamiliesAndFailsOnRequiredFamilyError() {
        let ipv4 = DNSServiceProtocol(kDNSServiceProtocol_IPv4)
        let ipv6 = DNSServiceProtocol(kDNSServiceProtocol_IPv6)
        let addresses = ["198.51.100.2/32", "2001:db8::2/128"].map(range)
        let allowed = ["0.0.0.0/0", "::/0"].map(range)
        var familyError = false
        let resolver = DNSResolver.BypassLookup { _, families, reply in
            XCTAssertEqual(families, [ipv4, ipv6])
            reply(familyError ? .failure(.unresolved) : .success(addresses))
            return {}
        }
        XCTAssertEqual(resolve(resolver, hostnames: ["host.example"], allowedIPs: allowed), .success(addresses))
        familyError = true
        XCTAssertEqual(resolve(resolver, hostnames: ["host.example"], allowedIPs: allowed), .failure(.unresolved))
    }

    func testExplicitDNSErrorDiscardsEarlierAnswersAndCancelsQuery() {
        let address = range("198.51.100.2/32")
        var cancelled = [String]()
        let resolver = DNSResolver.BypassLookup { hostname, _, reply in
            reply(hostname == "first.example." ? .success([address]) : .failure(.unresolved))
            return { cancelled.append(hostname) }
        }
        let result = resolve(resolver, hostnames: ["first.example", "error.example", "unqueried.example"],
                             allowedIPs: [range("0.0.0.0/0")])
        XCTAssertEqual(result, .failure(.unresolved))
        XCTAssertEqual(cancelled, ["first.example.", "error.example."])
    }

    func testExactAddressLimitsAllowDuplicateRoutesAcrossHostnames() {
        let perHost = DNSResolver.BypassLookup.maxAddressesPerHostname
        let total = DNSResolver.BypassLookup.maxRoutesPerActivation
        let addresses = (0..<total).map { range("198.51.100.\($0)/32") }
        let hostnames = (0..<(total / perHost)).map { "host\($0).example" }
        let routes = snapshot(hostnames: hostnames + ["duplicate.example"], allowedIPs: [range("0.0.0.0/0")]) { hostname in
            guard let index = hostnames.firstIndex(of: String(hostname.dropLast())) else { return [addresses[0]] }
            let offset = index * perHost
            return Array(addresses[offset..<(offset + perHost)])
        }
        XCTAssertEqual(routes, addresses)
    }

    func testOversizedLookupCancelsAndCanRetryWithoutPartialRoutes() {
        let maxAddresses = DNSResolver.BypassLookup.maxAddressesPerHostname
        let address = range("198.51.100.2/32")
        var cancelled = [String]()
        var lateReply: DNSResolver.BypassLookup.Completion?
        let resolver = DNSResolver.BypassLookup { hostname, _, reply in
            switch hostname {
            case "raw-overflow.example.":
                reply(.failure(.tooManyAddresses))
            case "oversized.example.":
                lateReply = reply
                reply(.success(Array(repeating: address, count: maxAddresses + 1)))
            default:
                lateReply?(.success([address]))
                reply(.success([address]))
            }
            return { cancelled.append(hostname) }
        }
        let allowed = [range("0.0.0.0/0")]
        XCTAssertEqual(resolve(resolver, hostnames: ["raw-overflow.example"], allowedIPs: allowed), .failure(.tooManyAddresses))
        XCTAssertEqual(resolve(resolver, hostnames: ["oversized.example"], allowedIPs: allowed), .failure(.tooManyAddresses))
        XCTAssertEqual(cancelled, ["raw-overflow.example.", "oversized.example."])
        XCTAssertFalse(resolver.cancel())
        XCTAssertEqual(resolve(resolver, hostnames: ["retry.example"], allowedIPs: allowed), .success([address]))
        XCTAssertEqual(cancelled, ["raw-overflow.example.", "oversized.example.", "retry.example."])
    }

    func testAggregateOverflowRejectsEntireSnapshotAndStopsResolving() {
        let perHost = DNSResolver.BypassLookup.maxAddressesPerHostname
        let total = DNSResolver.BypassLookup.maxRoutesPerActivation
        let addresses = (0...total).map { range("198.51.\(100 + $0 / 256).\($0 % 256)/32") }
        let allowed = [range("0.0.0.0/0")]
        let hostnames = (0...(total / perHost)).map { "host\($0).example" }
        var cancelled = [String]()
        let resolver = DNSResolver.BypassLookup { hostname, _, reply in
            guard let index = hostnames.firstIndex(of: String(hostname.dropLast())) else {
                XCTFail("Queried a hostname after overflowing the snapshot")
                reply(.failure(.unresolved))
                return {}
            }
            let offset = index * perHost
            reply(.success(Array(addresses[offset..<min(offset + perHost, addresses.count)])))
            return { cancelled.append(hostname) }
        }
        XCTAssertEqual(resolve(resolver, hostnames: hostnames + ["unqueried.example"], allowedIPs: allowed),
                       .failure(.tooManyAddresses))
        XCTAssertEqual(cancelled, hostnames.map { $0 + "." })
    }

    func testNetworkSettingsAcceptSuccessfulCallback() {
        XCTAssertNoThrow(try WireGuardAdapter.HostnameBypassActivation().confirmNetworkSettings { reply in reply(nil) })
    }

    func testNetworkSettingsPropagateCallbackError() {
        XCTAssertThrowsError(try WireGuardAdapter.HostnameBypassActivation().confirmNetworkSettings { reply in reply(POSIXError(.EIO)) }) { error in
            guard case WireGuardAdapterError.setNetworkSettings(let underlying) = error else {
                return XCTFail("Expected network settings error, got \(error)")
            }
            XCTAssertEqual((underlying as? POSIXError)?.code, .EIO)
        }
    }

    func testNetworkSettingsTimeOutAndIgnoreLateSuccessDuringRetry() {
        var lateReply: ((Error?) -> Void)?
        XCTAssertThrowsError(try WireGuardAdapter.HostnameBypassActivation().confirmNetworkSettings(timeout: .milliseconds(10)) { reply in
            lateReply = reply
        }) { error in
            guard case WireGuardAdapterError.setNetworkSettings(let underlying) = error else {
                return XCTFail("Expected network settings error, got \(error)")
            }
            XCTAssertEqual((underlying as? POSIXError)?.code, .ETIMEDOUT)
        }
        XCTAssertThrowsError(try WireGuardAdapter.HostnameBypassActivation().confirmNetworkSettings { reply in
            lateReply?(nil)
            reply(POSIXError(.EIO))
        }) { error in
            guard case WireGuardAdapterError.setNetworkSettings(let underlying) = error else {
                return XCTFail("Expected network settings error, got \(error)")
            }
            XCTAssertEqual((underlying as? POSIXError)?.code, .EIO)
        }
    }

    func testStopWakesPendingSettingsWaitWithoutCallback() {
        let activation = WireGuardAdapter.HostnameBypassActivation()
        assertCancelled {
            try activation.confirmNetworkSettings {
                _ in DispatchQueue.global().async { activation.cancel() }
            }
        }
        assertCancelled { _ = try activation.startBackend { XCTFail("Backend started after Stop"); return 0 } }
    }

    func testLateSuccessOrFailureCannotCompleteCancelledActivationOrAffectRetry() {
        for error: Error? in [nil, POSIXError(.EIO)] {
            let cancelled = WireGuardAdapter.HostnameBypassActivation()
            var lateReply: ((Error?) -> Void)?
            assertCancelled {
                try cancelled.confirmNetworkSettings { reply in
                    lateReply = reply
                    cancelled.cancel()
                }
            }
            let retry = WireGuardAdapter.HostnameBypassActivation()
            XCTAssertNoThrow(try retry.confirmNetworkSettings { reply in
                lateReply?(error)
                reply(nil)
            })
            assertCancelled { _ = try cancelled.startBackend { XCTFail("Stale callback started backend"); return 0 } }
            XCTAssertEqual(try retry.startBackend { 42 }, 42)
        }
    }

    func testStopAfterAcknowledgementStillPreventsBackendStartup() throws {
        let activation = WireGuardAdapter.HostnameBypassActivation()
        try activation.confirmNetworkSettings { reply in reply(nil) }
        activation.cancel()
        assertCancelled { _ = try activation.startBackend { XCTFail("Backend started after Stop"); return 0 } }
    }

    func testStopAndAcknowledgementInEitherOrderCancelBeforeWaitReturns() {
        for stopFirst in [true, false] {
            let activation = WireGuardAdapter.HostnameBypassActivation()
            assertCancelled {
                try activation.confirmNetworkSettings { reply in
                    if stopFirst {
                        activation.cancel()
                        reply(nil)
                    } else {
                        reply(nil)
                        activation.cancel()
                    }
                }
            }
        }
    }

    func testOrdinaryStartRetainsOriginalPublicSignature() {
        _ = WireGuardAdapter.start(tunnelConfiguration:completionHandler:)
    }

    private func assertCancelled(_ operation: () throws -> Void, file: StaticString = #file, line: UInt = #line) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            guard case WireGuardAdapterError.setNetworkSettings(let underlying) = error else {
                return XCTFail("Expected cancellation, got \(error)", file: file, line: line)
            }
            XCTAssertEqual((underlying as? POSIXError)?.code, .ECANCELED, file: file, line: line)
        }
    }

    private func snapshot(hostnames: [String], allowedIPs: [IPAddressRange], dnsServers: [DNSServer] = [],
                          lookup: @escaping (String) -> [IPAddressRange]) -> [IPAddressRange]? {
        let resolver = DNSResolver.BypassLookup { hostname, _, reply in
            reply(.success(lookup(hostname)))
            return {}
        }
        return try? resolve(resolver, hostnames: hostnames, allowedIPs: allowedIPs, dnsServers: dnsServers).get()
    }

    private func resolve(_ resolver: DNSResolver.BypassLookup, hostnames: [String], allowedIPs: [IPAddressRange],
                         dnsServers: [DNSServer] = []) -> Result<[IPAddressRange], DNSResolver.BypassLookupError> {
        let finished = expectation(description: "Lookup finished")
        var result: Result<[IPAddressRange], DNSResolver.BypassLookupError> = .failure(.unresolved)
        resolver.start(hostnames: hostnames, allowedIPs: allowedIPs, dnsServers: dnsServers) { reply in
            result = reply
            finished.fulfill()
        }
        wait(for: [finished], timeout: 1)
        return result
    }

    private func range(_ value: String) -> IPAddressRange {
        IPAddressRange(from: value)!
    }

    private func makeConfiguration(allowed: [String]) -> TunnelConfiguration {
        var interface = InterfaceConfiguration(privateKey: PrivateKey())
        interface.addresses = ["10.0.0.2/32", "fd00::2/128"].map(range)
        interface.dns = [DNSServer(from: "192.0.2.53")!, DNSServer(from: "2001:db8::53")!]
        interface.dnsSearch = ["vpn.example"]
        var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
        peer.allowedIPs = allowed.map(range)
        peer.endpoint = Endpoint(from: "192.0.2.5:51820")
        return TunnelConfiguration(name: "Test", interface: interface, peers: [peer])
    }

    private func makeGenerator(_ config: TunnelConfiguration) -> PacketTunnelSettingsGenerator {
        PacketTunnelSettingsGenerator(tunnelConfiguration: config, resolvedEndpoints: config.peers.map(\.endpoint))
    }
}
#endif
