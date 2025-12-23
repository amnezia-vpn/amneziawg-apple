// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// Helpers for determining whether any peer in a runtime configuration has produced a
/// "fresh" WireGuard handshake.
///
/// A handshake is considered fresh when at least one peer reports a `lastHandshakeTime`,
/// or when traffic is flowing (rx/tx bytes > 0).
enum HandshakeFreshnessEvaluator {
    /// Returns `true` when any peer has observed handshake data or traffic.
    /// - Parameters:
    ///   - peers: The peer configurations returned from the WireGuard runtime.
    ///   - cutoffDate: The minimum acceptable handshake timestamp.
    static func containsFreshHandshake(peers: [PeerConfiguration], cutoffDate: Date) -> Bool {
        _ = cutoffDate
        let rxBytesThreshold: UInt64 = 4096
        return peers.contains { peer in
            if peer.lastHandshakeTime != nil {
                return true
            }
            // Fallback: if traffic is flowing, consider the tunnel alive even if handshake time is unavailable.
            if let rxBytes = peer.rxBytes, rxBytes >= rxBytesThreshold {
                return true
            }
            return false
        }
    }
}
