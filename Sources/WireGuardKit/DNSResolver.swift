// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Network
import Foundation
#if os(macOS)
import dnssd
#endif

enum DNSResolver {}

extension DNSResolver {

    /// Concurrent queue used for DNS resolutions
    private static let resolverQueue = DispatchQueue(label: "DNSResolverQueue", qos: .default, attributes: .concurrent)

    static func resolveSync(endpoints: [Endpoint?]) -> [Result<Endpoint, DNSResolutionError>?] {
        let isAllEndpointsAlreadyResolved = endpoints.allSatisfy { maybeEndpoint -> Bool in
            return maybeEndpoint?.hasHostAsIPAddress() ?? true
        }

        if isAllEndpointsAlreadyResolved {
            return endpoints.map { endpoint in
                return endpoint.map { .success($0) }
            }
        }

        return endpoints.concurrentMap(queue: resolverQueue) { endpoint -> Result<Endpoint, DNSResolutionError>? in
            guard let endpoint = endpoint else { return nil }

            if endpoint.hasHostAsIPAddress() {
                return .success(endpoint)
            } else {
                return Result { try DNSResolver.resolveSync(endpoint: endpoint) }
                    .mapError { error -> DNSResolutionError in
                        // swiftlint:disable:next force_cast
                        return error as! DNSResolutionError
                    }
            }
        }
    }

    private static func resolveSync(endpoint: Endpoint) throws -> Endpoint {
        guard case .name(let name, _) = endpoint.host else {
            return endpoint
        }

        var hints = addrinfo()
        hints.ai_flags = AI_ALL // We set this to ALL so that we get v4 addresses even on DNS64 networks
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP

        var resultPointer: UnsafeMutablePointer<addrinfo>?
        defer {
            resultPointer.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo(name, "\(endpoint.port)", &hints, &resultPointer)
        if errorCode != 0 {
            throw DNSResolutionError(errorCode: errorCode, address: name)
        }

        var ipv4Address: IPv4Address?
        var ipv6Address: IPv6Address?

        var next: UnsafeMutablePointer<addrinfo>? = resultPointer
        let iterator = AnyIterator { () -> addrinfo? in
            let result = next?.pointee
            next = result?.ai_next
            return result
        }

        for addrInfo in iterator {
            if let maybeIpv4Address = IPv4Address(addrInfo: addrInfo) {
                ipv4Address = maybeIpv4Address
                break // If we found an IPv4 address, we can stop
            } else if let maybeIpv6Address = IPv6Address(addrInfo: addrInfo) {
                ipv6Address = maybeIpv6Address
                continue // If we already have an IPv6 address, we can skip this one
            }
        }

        // We prefer an IPv4 address over an IPv6 address
        if let ipv4Address = ipv4Address {
            return Endpoint(host: .ipv4(ipv4Address), port: endpoint.port)
        } else if let ipv6Address = ipv6Address {
            return Endpoint(host: .ipv6(ipv6Address), port: endpoint.port)
        } else {
            // Must never happen
            fatalError()
        }
    }
}

#if os(macOS)
extension DNSResolver {
    enum BypassLookupError: Error {
        case cancelled
        case unresolved
        case tooManyAddresses
    }

    // The provider and DNS callbacks use the main queue. One hostname is queried
    // at a time, with one cancellable DNS service operation per address family.
    final class BypassLookup {
        typealias Completion = (Result<[IPAddressRange], BypassLookupError>) -> Void
        typealias Lookup = (String, [DNSServiceProtocol], @escaping Completion) -> (() -> Void)

        // Budget for one combined A/AAAA reply (including duplicates), and for
        // the distinct VPN exclusions installed by one activation.
        static let maxAddressesPerHostname = 64
        static let maxRoutesPerActivation = 256

        private struct Attempt {
            let id = UUID()
            let deadline: DispatchTime
            let timer: DispatchSourceTimer
            let completion: Completion
            let families: [DNSServiceProtocol]
            let dnsAddresses: Set<Data>
            var cancelQuery: (() -> Void)?
            var seen = Set<IPAddressRange>()
            var routes = [IPAddressRange]()

            mutating func appendRoutes(from addresses: [IPAddressRange]) -> BypassLookupError? {
                guard addresses.count <= BypassLookup.maxAddressesPerHostname else { return .tooManyAddresses }
                var hasApplicableAddress = false
                for route in addresses {
                    let family = route.address is IPv4Address ? kDNSServiceProtocol_IPv4 : kDNSServiceProtocol_IPv6
                    guard families.contains(DNSServiceProtocol(family)) else { continue }
                    guard !dnsAddresses.contains(route.address.rawValue) else { return .unresolved }
                    hasApplicableAddress = true
                    if seen.contains(route) { continue }
                    guard routes.count < BypassLookup.maxRoutesPerActivation else { return .tooManyAddresses }
                    seen.insert(route)
                    routes.append(route)
                }
                return hasApplicableAddress ? nil : .unresolved
            }
        }

        private var attempt: Attempt?
        private let lookup: Lookup

        init(lookup: @escaping Lookup = DNSResolver.lookupHostRoutes) {
            self.lookup = lookup
        }

        func start(
            hostnames: [String], allowedIPs: [IPAddressRange], dnsServers: [DNSServer],
            timeout: DispatchTimeInterval = .seconds(8), completion: @escaping Completion
        ) {
            cancel()
            var families = [DNSServiceProtocol]()
            if allowedIPs.contains(where: { $0.stringRepresentation == "0.0.0.0/0" }) {
                families.append(DNSServiceProtocol(kDNSServiceProtocol_IPv4))
            }
            if allowedIPs.contains(where: { $0.stringRepresentation == "::/0" }) {
                families.append(DNSServiceProtocol(kDNSServiceProtocol_IPv6))
            }
            guard hostnames.isEmpty || !families.isEmpty else {
                completion(.failure(.unresolved))
                return
            }
            let deadline = DispatchTime.now() + timeout
            let timer = DispatchSource.makeTimerSource(queue: .main)
            let pending = Attempt(
                deadline: deadline, timer: timer, completion: completion,
                families: families, dnsAddresses: Set(dnsServers.map { $0.address.rawValue }))
            let id = pending.id
            attempt = pending
            timer.schedule(deadline: deadline)
            timer.setEventHandler { [weak self] in
                guard let self = self, self.attempt?.id == id else { return }
                self.finish(.failure(.unresolved))
            }
            timer.resume()
            resolveNext(hostnames, index: 0, id: id)
        }

        private func resolveNext(_ hostnames: [String], index: Int, id: UUID) {
            guard let current = attempt, current.id == id else { return }
            guard DispatchTime.now() < current.deadline else {
                finish(.failure(.unresolved))
                return
            }
            guard index < hostnames.count else {
                finish(.success(current.routes))
                return
            }
            attempt?.cancelQuery = lookup(hostnames[index] + ".", current.families) { [weak self] result in
                // Defer delivery so the query's cancellation handle is installed first.
                DispatchQueue.main.async {
                    guard let self = self, self.attempt?.id == id else { return }
                    self.attempt?.cancelQuery?()
                    self.attempt?.cancelQuery = nil
                    switch result {
                    case .failure(let error):
                        self.finish(.failure(error))
                    case .success(let addresses):
                        if let error = self.attempt?.appendRoutes(from: addresses) {
                            self.finish(.failure(error))
                        } else {
                            self.resolveNext(hostnames, index: index + 1, id: id)
                        }
                    }
                }
            }
        }

        @discardableResult
        func cancel() -> Bool {
            guard attempt != nil else { return false }
            finish(.failure(.cancelled))
            return true
        }

        private func finish(_ result: Result<[IPAddressRange], BypassLookupError>) {
            guard let current = attempt else { return }
            attempt = nil
            current.timer.cancel()
            current.cancelQuery?()
            current.completion(result)
        }
    }

    private static func lookupHostRoutes(
        _ hostname: String, families: [DNSServiceProtocol], completion: @escaping BypassLookup.Completion
    ) -> (() -> Void) {
        var remaining = families.count
        var addressCount = 0
        var routes = [IPAddressRange]()
        let reserveAddress: () -> Bool = {
            guard remaining > 0, addressCount < BypassLookup.maxAddressesPerHostname else { return false }
            addressCount += 1
            return true
        }
        let receive: BypassLookup.Completion = { result in
            guard remaining > 0 else { return }
            switch result {
            case .failure(let error):
                remaining = 0
                completion(.failure(error))
            case .success(let addresses):
                routes.append(contentsOf: addresses)
                remaining -= 1
                if remaining == 0 { completion(.success(routes)) }
            }
        }
        let queries = families.map { _ in BypassAddressQuery(reserveAddress: reserveAddress, completion: receive) }
        for (family, query) in zip(families, queries) {
            guard query.start(hostname, family: family) else {
                queries.forEach { $0.cancel() }
                receive(.failure(.unresolved))
                break
            }
        }
        return { queries.forEach { $0.cancel() } }
    }
}

private final class BypassAddressQuery {
    private var service: DNSServiceRef?
    private var routes = [IPAddressRange]()
    private let reserveAddress: () -> Bool
    private let completion: DNSResolver.BypassLookup.Completion

    init(reserveAddress: @escaping () -> Bool, completion: @escaping DNSResolver.BypassLookup.Completion) {
        self.reserveAddress = reserveAddress
        self.completion = completion
    }

    func start(_ hostname: String, family: DNSServiceProtocol) -> Bool {
        let error = DNSServiceGetAddrInfo(
            &service, DNSServiceFlags(kDNSServiceFlagsReturnIntermediates), 0, family, hostname,
            { _, flags, _, error, _, address, _, context in
                let query = Unmanaged<BypassAddressQuery>.fromOpaque(context!).takeUnretainedValue()
                query.receive(flags: flags, error: error, address: address)
            }, Unmanaged.passUnretained(self).toOpaque()
        )
        guard error == kDNSServiceErr_NoError, let service = service else { return false }
        return DNSServiceSetDispatchQueue(service, .main) == kDNSServiceErr_NoError
    }

    func cancel() {
        guard let service = service else { return }
        self.service = nil
        DNSServiceRefDeallocate(service)
    }

    private func receive(flags: DNSServiceFlags, error: DNSServiceErrorType, address: UnsafePointer<sockaddr>?) {
        guard service != nil else { return }
        if error != kDNSServiceErr_NoError {
            cancel()
            completion(error == kDNSServiceErr_NoSuchRecord ? .success([]) : .failure(.unresolved))
            return
        }
        if let address = address, flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0 {
            var info = addrinfo()
            info.ai_family = Int32(address.pointee.sa_family)
            info.ai_addr = UnsafeMutablePointer(mutating: address)
            let route: IPAddressRange?
            if let address = IPv4Address(addrInfo: info) {
                route = IPAddressRange(address: address, networkPrefixLength: 32)
            } else if info.ai_family == AF_INET6,
                      address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1, { $0.pointee.sin6_scope_id == 0 }),
                      let address = IPv6Address(addrInfo: info) {
                route = IPAddressRange(address: address, networkPrefixLength: 128)
            } else {
                route = nil
            }
            if let route = route {
                guard reserveAddress() else {
                    cancel()
                    completion(.failure(.tooManyAddresses))
                    return
                }
                routes.append(route)
            }
        }
        guard flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 else { return }
        cancel()
        completion(.success(routes))
    }
}
#endif

extension Endpoint {
    func withReresolvedIP() throws -> Endpoint {
        #if os(iOS)
        let hostname: String
        switch host {
        case .name(let name, _):
            hostname = name
        case .ipv4(let address):
            hostname = "\(address)"
        case .ipv6(let address):
            hostname = "\(address)"
        @unknown default:
            fatalError()
        }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        hints.ai_flags = 0 // We set this to zero so that we actually resolve this using DNS64

        var result: UnsafeMutablePointer<addrinfo>?
        defer {
            result.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo(hostname, "\(self.port)", &hints, &result)
        if errorCode != 0 {
            throw DNSResolutionError(errorCode: errorCode, address: hostname)
        }

        let addrInfo = result!.pointee
        if let ipv4Address = IPv4Address(addrInfo: addrInfo) {
            return Endpoint(host: .ipv4(ipv4Address), port: port)
        } else if let ipv6Address = IPv6Address(addrInfo: addrInfo) {
            return Endpoint(host: .ipv6(ipv6Address), port: port)
        } else {
            fatalError()
        }
        #elseif os(macOS)
        return self
        #else
        #error("Unimplemented")
        #endif
    }
}

/// An error type describing DNS resolution error
public struct DNSResolutionError: LocalizedError {
    public let errorCode: Int32
    public let address: String

    init(errorCode: Int32, address: String) {
        self.errorCode = errorCode
        self.address = address
    }

    public var errorDescription: String? {
        return String(cString: gai_strerror(errorCode))
    }
}
