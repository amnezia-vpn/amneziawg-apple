// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// Helpers for determining whether any peer in a runtime configuration has produced a
/// "fresh" WireGuard handshake.
///
/// A handshake is considered fresh when at least one peer reports a `lastHandshakeTime`
/// that is greater than or equal to the provided `cutoffDate`. Callers are expected to
/// pass a cutoff that has already been adjusted for their desired tolerance (for example,
/// the moment the connection reported `.connected` minus a small grace window).
enum HandshakeFreshnessEvaluator {
    /// Returns `true` when any of the provided peers exposes a `lastHandshakeTime`
    /// newer than the supplied cutoff.
    /// - Parameters:
    ///   - peers: The peer configurations returned from the WireGuard runtime.
    ///   - cutoffDate: The minimum acceptable handshake timestamp.
    static func containsFreshHandshake(peers: [PeerConfiguration], cutoffDate: Date) -> Bool {
        return peers.contains { peer in
            guard let handshake = peer.lastHandshakeTime else { return false }
            return handshake >= cutoffDate
        }
    }
}
