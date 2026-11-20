// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import NetworkExtension

enum PacketTunnelProviderError: String, Error {
    case savedProtocolConfigurationIsInvalid
    case dnsResolutionFailure
    case couldNotStartBackend
    case couldNotDetermineFileDescriptor
    case couldNotSetNetworkSettings
    #if os(macOS)
    case invalidBypassHostnames
    case unsupportedBypassRouting
    case bypassResolutionFailure
    case bypassAddressLimitExceeded
    case bypassSettingsUnconfirmed
    #endif
}

#if os(macOS)
extension NETunnelProviderProtocol {
    private static let bypassHostnamesKey = "BypassHostnames"

    var hasBypassHostnamePolicy: Bool {
        return providerConfiguration?[Self.bypassHostnamesKey] != nil
    }

    func readBypassHostnames() throws -> [String] {
        guard let value = providerConfiguration?[Self.bypassHostnamesKey] else { return [] }
        guard let hostnames = value as? [String] else {
            throw PacketTunnelProviderError.invalidBypassHostnames
        }
        return try Self.normalizeBypassHostnames(hostnames)
    }

    func setBypassHostnames(_ hostnames: [String]) {
        var metadata = providerConfiguration ?? [:]
        metadata[Self.bypassHostnamesKey] = hostnames.isEmpty ? nil : hostnames
        providerConfiguration = metadata
    }

    static func normalizeBypassHostnames(_ values: [String]) throws -> [String] {
        var hostnames = Set<String>()
        for value in values {
            var hostname = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if hostname.isEmpty { continue }
            if hostname.hasSuffix(".") { hostname.removeLast() }
            let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
            guard hostname.utf8.count <= 253, labels.count > 1,
                  let lastLabel = labels.last,
                  lastLabel.utf8.contains(where: { (65...90).contains($0) || (97...122).contains($0) }),
                  labels.allSatisfy({ label in
                      (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-"
                          && label.utf8.allSatisfy {
                              (65...90).contains($0) || (97...122).contains($0)
                                  || (48...57).contains($0) || $0 == 45
                          }
                  }) else {
                throw PacketTunnelProviderError.invalidBypassHostnames
            }
            hostnames.insert(hostname.lowercased())
        }
        return hostnames.sorted()
    }

    static func supportsBypassRouting(for configuration: TunnelConfiguration, includeAllNetworks: Bool = false) -> Bool {
        guard !includeAllNetworks, configuration.peers.count == 1 else { return false }
        return configuration.peers[0].allowedIPs.contains {
            $0.stringRepresentation == "0.0.0.0/0" || $0.stringRepresentation == "::/0"
        }
    }
}
#endif

extension NETunnelProviderProtocol {
    convenience init?(tunnelConfiguration: TunnelConfiguration, previouslyFrom old: NEVPNProtocol? = nil) {
        self.init()

        guard let name = tunnelConfiguration.name else { return nil }
        guard let appId = Bundle.main.bundleIdentifier else { return nil }
        providerBundleIdentifier = "\(appId).network-extension"
        passwordReference = Keychain.makeReference(containing: tunnelConfiguration.asWgQuickConfig(), called: name, previouslyReferencedBy: old?.passwordReference)
        if passwordReference == nil {
            return nil
        }
        #if os(macOS)
        providerConfiguration = ["UID": getuid()]
        #endif

        let endpoints = tunnelConfiguration.peers.compactMap { $0.endpoint }
        if endpoints.count == 1 {
            serverAddress = endpoints[0].stringRepresentation
        } else if endpoints.isEmpty {
            serverAddress = "Unspecified"
        } else {
            serverAddress = "Multiple endpoints"
        }
    }

    func asTunnelConfiguration(called name: String? = nil) -> TunnelConfiguration? {
        if let passwordReference = passwordReference,
            let config = Keychain.openReference(called: passwordReference) {
            #if os(macOS)
            if let parsed = try? TunnelConfiguration(fromWgQuickConfig: config, called: name) { return parsed }
            #else
            return try? TunnelConfiguration(fromWgQuickConfig: config, called: name)
            #endif
        }
        if let oldConfig = providerConfiguration?["WgQuickConfig"] as? String {
            return try? TunnelConfiguration(fromWgQuickConfig: oldConfig, called: name)
        }
        return nil
    }

    func destroyConfigurationReference() {
        guard let ref = passwordReference else { return }
        Keychain.deleteReference(called: ref)
    }

    func verifyConfigurationReference() -> Bool {
        guard let ref = passwordReference else { return false }
        return Keychain.verifyReference(called: ref)
    }

    @discardableResult
    func migrateConfigurationIfNeeded(called name: String) -> Bool {
        /* This is how we did things before we switched to putting items
         * in the keychain. But it's still useful to keep the migration
         * around so that .mobileconfig files are easier.
         */
        if let oldConfig = providerConfiguration?["WgQuickConfig"] as? String {
            #if os(macOS)
            return migrateLegacyConfiguration(oldConfig, called: name)
            #elseif os(iOS)
            providerConfiguration = nil
            guard passwordReference == nil else { return true }
            wg_log(.info, message: "Migrating tunnel configuration '\(name)'")
            passwordReference = Keychain.makeReference(containing: oldConfig, called: name)
            return true
            #else
            #error("Unimplemented")
            #endif
        }
        #if os(macOS)
        if passwordReference != nil && providerConfiguration?["UID"] == nil && verifyConfigurationReference() {
            var metadata = providerConfiguration ?? [:]
            metadata["UID"] = getuid()
            providerConfiguration = metadata
            return true
        }
        #elseif os(iOS)
        /* Update the stored reference from the old iOS 14 one to the canonical iOS 15 one.
         * The iOS 14 ones are 96 bits, while the iOS 15 ones are 160 bits. We do this so
         * that we can have fast set exclusion in deleteReferences safely. */
        if passwordReference != nil && passwordReference!.count == 12 {
            var result: CFTypeRef?
            let ret = SecItemCopyMatching([kSecValuePersistentRef: passwordReference!,
                                           kSecReturnPersistentRef: true] as CFDictionary,
                                           &result)
            if ret != errSecSuccess || result == nil {
                return false
            }
            guard let newReference = result as? Data else { return false }
            if !newReference.elementsEqual(passwordReference!) {
                wg_log(.info, message: "Migrating iOS 14-style keychain reference to iOS 15-style keychain reference for '\(name)'")
                passwordReference = newReference
                return true
            }
        }
        #endif
        return false
    }

    #if os(macOS)
    func migrateLegacyConfiguration(
        _ legacyConfig: String, called name: String,
        read: (Data) -> String? = Keychain.openReference,
        create: (String, String) -> Data? = { Keychain.makeReference(containing: $0, called: $1) },
        delete: (Data) -> Void = Keychain.deleteReference
    ) -> Bool {
        // A different user's Keychain item may be unreadable from this process.
        if let owner = providerConfiguration?["UID"] as? uid_t, owner != getuid() { return false }

        if let reference = passwordReference {
            guard let payload = read(reference),
                  (try? TunnelConfiguration(fromWgQuickConfig: payload, called: name)) != nil else { return false }
        } else {
            wg_log(.info, message: "Migrating tunnel configuration '\(name)'")
            guard let reference = create(legacyConfig, name) else { return false }
            guard read(reference) == legacyConfig else {
                delete(reference)
                return false
            }
            passwordReference = reference
        }
        var metadata = providerConfiguration ?? [:]
        metadata.removeValue(forKey: "WgQuickConfig")
        if metadata["UID"] == nil { metadata["UID"] = getuid() }
        providerConfiguration = metadata
        return true
    }
    #endif
}
