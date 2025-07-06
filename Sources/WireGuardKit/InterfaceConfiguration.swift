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
    public var cookieReplyPacketJunkSize: UInt16?
    public var transportPacketJunkSize: UInt16?
    public var initPacketMagicHeader: UInt32?
    public var responsePacketMagicHeader: UInt32?
    public var underloadPacketMagicHeader: UInt32?
    public var transportPacketMagicHeader: UInt32?
    public var listenPort: UInt16?
    public var mtu: UInt16?
    public var dns = [DNSServer]()
    public var dnsSearch = [String]()
    public var specialJunk1: String?
    public var specialJunk2: String?
    public var specialJunk3: String?
    public var specialJunk4: String?
    public var specialJunk5: String?
    public var controlledJunk1: String?
    public var controlledJunk2: String?
    public var controlledJunk3: String?
    public var specialHandshakeTimeout: Int?

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
            lhs.cookieReplyPacketJunkSize == rhs.cookieReplyPacketJunkSize &&
            lhs.transportPacketJunkSize == rhs.transportPacketJunkSize &&
            lhs.initPacketMagicHeader == rhs.initPacketMagicHeader &&
            lhs.responsePacketMagicHeader == rhs.responsePacketMagicHeader &&
            lhs.underloadPacketMagicHeader == rhs.underloadPacketMagicHeader &&
            lhs.transportPacketMagicHeader == rhs.transportPacketMagicHeader &&
            lhs.specialJunk1 == rhs.specialJunk1 &&
            lhs.specialJunk2 == rhs.specialJunk2 &&
            lhs.specialJunk3 == rhs.specialJunk3 &&
            lhs.specialJunk4 == rhs.specialJunk4 &&
            lhs.specialJunk5 == rhs.specialJunk5 &&
            lhs.controlledJunk1 == rhs.controlledJunk1 &&
            lhs.controlledJunk2 == rhs.controlledJunk2 &&
            lhs.controlledJunk3 == rhs.controlledJunk3 &&
            lhs.specialHandshakeTimeout == rhs.specialHandshakeTimeout
    }
}
