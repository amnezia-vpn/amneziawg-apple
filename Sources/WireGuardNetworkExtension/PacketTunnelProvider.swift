// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import os

class PacketTunnelProvider: NEPacketTunnelProvider {

    private lazy var adapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
    }()


    private func logAppGroupInfo() {
        let appGroupId = FileManager.appGroupId ?? "nil"
        let logPath = FileManager.logFileURL?.path ?? "nil"
        let errorPath = FileManager.networkExtensionLastErrorFileURL?.path ?? "nil"
        wg_log(.info, message: "App group id: \(appGroupId)")
        wg_log(.info, message: "Log file path: \(logPath)")
        wg_log(.info, message: "Last error file path: \(errorPath)")
    }

    private func logTunnelConfigurationSummary(_ tunnelConfiguration: TunnelConfiguration) {
        let interface = tunnelConfiguration.interface
        let addressStrings = interface.addresses.map { $0.stringRepresentation }
        let dnsStrings = interface.dns.map { $0.stringRepresentation }
        let mtuString = interface.mtu.map { String($0) } ?? "auto"
        let peerSummaries = tunnelConfiguration.peers.enumerated().map { index, peer in
            let endpoint = peer.endpoint?.stringRepresentation ?? "nil"
            let keepalive = peer.persistentKeepAlive.map { String($0) } ?? "0"
            return "peer[\(index)]: endpoint=\(endpoint) allowedIPs=\(peer.allowedIPs.count) excludeIPs=\(peer.excludeIPs.count) keepalive=\(keepalive)"
        }
        let peersSummary = peerSummaries.isEmpty ? "none" : peerSummaries.joined(separator: "; ")
        wg_log(.info, message: "Config summary: addresses=\(addressStrings) dns=\(dnsStrings) mtu=\(mtuString) peers=\(peersSummary)")
    }

    private func logRuntimeConfigSummary(_ settings: String) {
        var peerCount = 0
        var handshakeValues = [String]()
        var rxValues = [String]()
        var txValues = [String]()
        let handshakePrefix = "last_handshake_time_sec="
        let rxPrefix = "rx_bytes="
        let txPrefix = "tx_bytes="
        for line in settings.split(separator: "\n") {
            if line.hasPrefix("public_key=") {
                peerCount += 1
            } else if line.hasPrefix(handshakePrefix) {
                handshakeValues.append(String(line.dropFirst(handshakePrefix.count)))
            } else if line.hasPrefix(rxPrefix) {
                rxValues.append(String(line.dropFirst(rxPrefix.count)))
            } else if line.hasPrefix(txPrefix) {
                txValues.append(String(line.dropFirst(txPrefix.count)))
            }
        }
        wg_log(.debug, message: "Runtime config summary: peers=\(peerCount) last_handshake_time_sec=\(handshakeValues) rx_bytes=\(rxValues) tx_bytes=\(txValues)")
    }


    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let activationAttemptId = options?["activationAttemptId"] as? String
        let errorNotifier = ErrorNotifier(activationAttemptId: activationAttemptId)

        Logger.configureGlobal(tagged: "NET", withFilePath: FileManager.logFileURL?.path)

        let optionKeys = options?.keys.sorted().joined(separator: ", ") ?? "none"
        wg_log(.info, message: "Start options keys: \(optionKeys)")
        logAppGroupInfo()

        wg_log(.info, message: "Starting tunnel from the " + (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

        guard let tunnelProviderProtocol = self.protocolConfiguration as? NETunnelProviderProtocol,
              let tunnelConfiguration = tunnelProviderProtocol.asTunnelConfiguration() else {
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        logTunnelConfigurationSummary(tunnelConfiguration)

        // Start the tunnel
        adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
            guard let adapterError = adapterError else {
                let interfaceName = self.adapter.interfaceName ?? "unknown"

                wg_log(.info, message: "Tunnel interface is \(interfaceName)")

                completionHandler(nil)
                return
            }

            switch adapterError {
            case .cannotLocateTunnelFileDescriptor:
                wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                completionHandler(PacketTunnelProviderError.couldNotDetermineFileDescriptor)

            case .dnsResolution(let dnsErrors):
                let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                    .joined(separator: ", ")
                wg_log(.error, message: "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                completionHandler(PacketTunnelProviderError.dnsResolutionFailure)

            case .setNetworkSettings(let error):
                wg_log(.error, message: "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)

            case .startWireGuardBackend(let errorCode):
                wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                completionHandler(PacketTunnelProviderError.couldNotStartBackend)

            case .invalidState:
                // Must never happen
                fatalError()
            }
        }
    }

    override func
    stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, message: "Stopping tunnel, reason=\(reason.rawValue) (\(reason))")

        adapter.stop { error in
            ErrorNotifier.removeLastErrorFile()

            if let error = error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }
            completionHandler()

            #if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
            #endif
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }

        wg_log(.debug, message: "handleAppMessage: received \(messageData.count) bytes")
        if messageData.count == 1 && messageData[0] == 0 {
            wg_log(.debug, message: "handleAppMessage: runtime configuration requested")
            adapter.getRuntimeConfiguration { [weak self] settings in
                var data: Data?
                if let settings = settings {
                    self?.logRuntimeConfigSummary(settings)
                    data = settings.data(using: .utf8)!
                } else {
                    wg_log(.debug, message: "handleAppMessage: runtime configuration unavailable")
                }
                completionHandler(data)
            }
        } else {
            wg_log(.debug, message: "handleAppMessage: unsupported message payload")
            completionHandler(nil)
        }
    }
}

extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            return .debug
        case .error:
            return .error
        }
    }
}
