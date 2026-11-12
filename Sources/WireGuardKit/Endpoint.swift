// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public struct Endpoint {
    public let host: NWEndpoint.Host
    public let port: NWEndpoint.Port
    /// An explicitly selected DNS SRV owner name, rather than a host and fixed port.
    public let srvRecordName: String?

    public init(host: NWEndpoint.Host, port: NWEndpoint.Port) {
        self.host = host
        self.port = port
        self.srvRecordName = nil
    }
}

extension Endpoint: Equatable {
    public static func == (lhs: Endpoint, rhs: Endpoint) -> Bool {
        return lhs.host == rhs.host && lhs.port == rhs.port && lhs.srvRecordName == rhs.srvRecordName
    }
}

extension Endpoint: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(host)
        hasher.combine(port)
        hasher.combine(srvRecordName)
    }
}

extension Endpoint {
    public var stringRepresentation: String {
        if let srvRecordName = srvRecordName {
            return "srv://\(srvRecordName)"
        }
        switch host {
        case .name(let hostname, _):
            return "\(hostname):\(port)"
        case .ipv4(let address):
            return "\(address):\(port)"
        case .ipv6(let address):
            return "[\(address)]:\(port)"
        @unknown default:
            fatalError()
        }
    }

    public init?(from string: String) {
        // Separation of host and port is based on 'parse_endpoint' function in
        // https://git.zx2c4.com/wireguard-tools/tree/src/config.c
        guard !string.isEmpty else { return nil }
        if string.hasPrefix("srv://") {
            let name = String(string.dropFirst("srv://".count))
            let labels = name.split(separator: ".", omittingEmptySubsequences: false)
            let significantLabels = name.hasSuffix(".") ? labels.dropLast() : labels[...]
            // A UDP service name is explicit: no implicit service, URL port or path.
            guard name.utf8.count <= (name.hasSuffix(".") ? 254 : 253),
                  significantLabels.count >= 3,
                  significantLabels[0].hasPrefix("_"), significantLabels[0].count > 1,
                  significantLabels[1].lowercased() == "_udp",
                  significantLabels.allSatisfy({ label in
                      !label.isEmpty && label.utf8.count <= 63 && label.utf8.allSatisfy {
                          (65...90).contains($0) || (97...122).contains($0) ||
                          (48...57).contains($0) || $0 == 45 || $0 == 95
                      }
                  }) else { return nil }
            self.host = .name(name, nil)
            // Only the resolved endpoint's port is ever sent to the backend.
            self.port = .any
            self.srvRecordName = name
            return
        }
        let startOfPort: String.Index
        let hostString: String
        if string.first! == "[" {
            // Look for IPv6-style endpoint, like [::1]:80
            let startOfHost = string.index(after: string.startIndex)
            guard let endOfHost = string.dropFirst().firstIndex(of: "]") else { return nil }
            let afterEndOfHost = string.index(after: endOfHost)
            if afterEndOfHost == string.endIndex { return nil }
            guard string[afterEndOfHost] == ":" else { return nil }
            startOfPort = string.index(after: afterEndOfHost)
            hostString = String(string[startOfHost ..< endOfHost])
        } else {
            // Look for an IPv4-style endpoint, like 127.0.0.1:80
            guard let endOfHost = string.firstIndex(of: ":") else { return nil }
            startOfPort = string.index(after: endOfHost)
            hostString = String(string[string.startIndex ..< endOfHost])
        }
        guard let endpointPort = NWEndpoint.Port(String(string[startOfPort ..< string.endIndex])) else { return nil }
        let invalidCharacterIndex = hostString.unicodeScalars.firstIndex { char in
            return !CharacterSet.urlHostAllowed.contains(char)
        }
        guard invalidCharacterIndex == nil else { return nil }
        host = NWEndpoint.Host(hostString)
        port = endpointPort
        srvRecordName = nil
    }
}

extension Endpoint {
    public func hasHostAsIPAddress() -> Bool {
        switch host {
        case .name:
            return false
        case .ipv4:
            return true
        case .ipv6:
            return true
        @unknown default:
            fatalError()
        }
    }

    public func hostname() -> String? {
        switch host {
        case .name(let hostname, _):
            return hostname
        case .ipv4:
            return nil
        case .ipv6:
            return nil
        @unknown default:
            fatalError()
        }
    }
}
