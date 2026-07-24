// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

public struct PeerConfiguration {
    public var publicKey: PublicKey
    public var preSharedKey: PreSharedKey?
    public var allowedIPs = [IPAddressRange]()
    public var excludeIPs = [IPAddressRange]()
    public var endpoint: Endpoint?
    /// A single value ("22") or a range ("22-30"), per AmneziaWG 3+ `PersistentKeepalive`.
    public var persistentKeepAlive: String?
    public var rxBytes: UInt64?
    public var txBytes: UInt64?
    public var lastHandshakeTime: Date?

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }
}

extension PeerConfiguration: Equatable {
    public static func == (lhs: PeerConfiguration, rhs: PeerConfiguration) -> Bool {
        return lhs.publicKey == rhs.publicKey &&
            lhs.preSharedKey == rhs.preSharedKey &&
            Set(lhs.allowedIPs) == Set(rhs.allowedIPs) &&
            lhs.endpoint == rhs.endpoint &&
            lhs.persistentKeepAlive == rhs.persistentKeepAlive
    }
}

extension PeerConfiguration: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
        hasher.combine(preSharedKey)
        hasher.combine(Set(allowedIPs))
        hasher.combine(endpoint)
        hasher.combine(persistentKeepAlive)

    }
}
