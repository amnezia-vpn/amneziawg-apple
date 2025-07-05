// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public struct InterfaceConfiguration {
    public var privateKey: PrivateKey
    public var addresses = [IPAddressRange]()
    public var junkPacketCount: UInt16?
    public var junkPacketMinSize: UInt16?
    public var junkPacketMaxSize: UInt16?
    public var initPacketJunkSize: UInt16?
    public var responsePacketJunkSize: UInt16?
    public var s3: UInt16?
    public var s4: UInt16?
    public var initPacketMagicHeader: UInt32?
    public var responsePacketMagicHeader: UInt32?
    public var underloadPacketMagicHeader: UInt32?
    public var transportPacketMagicHeader: UInt32?
    public var listenPort: UInt16?
    public var mtu: UInt16?
    public var dns = [DNSServer]()
    public var dnsSearch = [String]()
    public var i1: String?
    public var i2: String?
    public var i3: String?
    public var i4: String?
    public var i5: String?
    public var j1: String?
    public var j2: String?
    public var j3: String?
    public var itime: Int?

    public init(privateKey: PrivateKey) {
        self.privateKey = privateKey
    }
}

extension InterfaceConfiguration: Equatable {
    public static func == (lhs: InterfaceConfiguration, rhs: InterfaceConfiguration) -> Bool {
        let lhsAddresses = lhs.addresses.filter { $0.address is IPv4Address } + lhs.addresses.filter { $0.address is IPv6Address }
        let rhsAddresses = rhs.addresses.filter { $0.address is IPv4Address } + rhs.addresses.filter { $0.address is IPv6Address }

        return lhs.privateKey == rhs.privateKey &&
            lhsAddresses == rhsAddresses &&
            lhs.listenPort == rhs.listenPort &&
            lhs.mtu == rhs.mtu &&
            lhs.dns == rhs.dns &&
            lhs.dnsSearch == rhs.dnsSearch &&
            lhs.junkPacketCount == rhs.junkPacketCount &&
            lhs.junkPacketMinSize == rhs.junkPacketMinSize &&
            lhs.junkPacketMaxSize == rhs.junkPacketMaxSize &&
            lhs.initPacketJunkSize == rhs.initPacketJunkSize &&
            lhs.responsePacketJunkSize == rhs.responsePacketJunkSize &&
            lhs.initPacketMagicHeader == rhs.initPacketMagicHeader &&
            lhs.responsePacketMagicHeader == rhs.responsePacketMagicHeader &&
            lhs.underloadPacketMagicHeader == rhs.underloadPacketMagicHeader &&
            lhs.transportPacketMagicHeader == rhs.transportPacketMagicHeader
    }
}
