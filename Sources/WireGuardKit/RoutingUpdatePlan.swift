import Foundation

struct RoutingUpdatePlan {
    let previous: TunnelConfiguration
    let requested: TunnelConfiguration

    init?(previous: TunnelConfiguration, requested: TunnelConfiguration) {
        guard previous.interface == requested.interface,
              previous.peers.count == 1, requested.peers.count == 1 else { return nil }
        let oldPeer = previous.peers[0]
        let newPeer = requested.peers[0]
        var unchangedPeer = newPeer
        unchangedPeer.allowedIPs = oldPeer.allowedIPs
        unchangedPeer.excludeIPs = oldPeer.excludeIPs
        guard unchangedPeer == oldPeer else { return nil }
        let oldAllowed = Self.normalized(oldPeer.allowedIPs)
        let newAllowed = Self.normalized(newPeer.allowedIPs)
        let oldExcluded = Self.normalized(oldPeer.excludeIPs)
        let newExcluded = Self.normalized(newPeer.excludeIPs)
        guard (oldExcluded == newExcluded && oldAllowed.isSubset(of: newAllowed))
                || (oldAllowed == newAllowed && oldExcluded.isSubset(of: newExcluded)) else { return nil }
        self.previous = TunnelConfiguration(name: previous.name, interface: previous.interface, peers: previous.peers)
        self.requested = TunnelConfiguration(name: requested.name, interface: requested.interface, peers: requested.peers)
    }

    var changesPeer: Bool {
        Self.normalized(previous.peers[0].allowedIPs) != Self.normalized(requested.peers[0].allowedIPs)
    }

    func peerConfiguration(restoring: Bool = false) -> String {
        let peer = (restoring ? previous : requested).peers[0]
        var lines = ["public_key=\(peer.publicKey.hexKey)", "update_only=true", "replace_allowed_ips=true"]
        lines.append(contentsOf: Self.normalized(peer.allowedIPs).sorted().map { "allowed_ip=\($0)" })
        return lines.joined(separator: "\n") + "\n"
    }

    func matchesRuntime(_ configuration: String, restoring: Bool = false) -> Bool {
        let peer = (restoring ? previous : requested).peers[0]
        var keys = [String]()
        var allowed = [IPAddressRange]()
        for line in configuration.split(separator: "\n") {
            let pair = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2 else { continue }
            if pair[0] == "public_key" {
                keys.append(String(pair[1]))
            } else if pair[0] == "allowed_ip" {
                guard let prefix = IPAddressRange(from: String(pair[1])) else { return false }
                allowed.append(prefix)
            }
        }
        return keys == [peer.publicKey.hexKey] && Self.normalized(allowed) == Self.normalized(peer.allowedIPs)
    }

    private static func normalized(_ prefixes: [IPAddressRange]) -> Set<String> {
        return Set(prefixes.map { "\($0.maskedAddress())/\($0.networkPrefixLength)" })
    }
}
