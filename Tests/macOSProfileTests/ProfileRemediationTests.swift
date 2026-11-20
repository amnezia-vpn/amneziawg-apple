// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import AppKit
import NetworkExtension
import XCTest
@testable import AmneziaWG

final class ProfileRemediationTests: XCTestCase {
    func testHostnamePolicyNormalizesAndDeduplicatesExactNames() throws {
        let proto = NETunnelProviderProtocol()
        proto.providerConfiguration = ["BypassHostnames": [" Example.COM.\n", "example.com", "", "A.example"]]
        XCTAssertEqual(try proto.readBypassHostnames(), ["a.example", "example.com"])
    }

    func testHostnamePolicyRejectsInvalidInput() {
        let longLabel = String(repeating: "a", count: 64)
        let longName = Array(repeating: String(repeating: "a", count: 63), count: 4).joined(separator: ".")
        for invalid in ["*.example.com", "127.0.0.1", "::1", "one..example", "example.com..", "-bad.example",
                        "bad-.example", "https://example.com", "host_name.example", "é.example", "localhost",
                        "\(longLabel).example", longName] {
            XCTAssertThrowsError(try NETunnelProviderProtocol.normalizeBypassHostnames(["valid.example", invalid]), invalid)
        }
        let proto = NETunnelProviderProtocol()
        proto.providerConfiguration = ["BypassHostnames": "example.com"]
        XCTAssertThrowsError(try proto.readBypassHostnames())
    }

    func testUnreadableExistingReferenceRetainsLegacyPayloadAndOwnership() throws {
        let (proto, legacy) = makeLegacyProfile()
        let oldReference = Data([1])
        proto.passwordReference = oldReference

        XCTAssertFalse(proto.migrateLegacyConfiguration(legacy, called: "Test", read: { _ in nil },
            create: { _, _ in XCTFail("Existing reference was replaced"); return nil },
            delete: { _ in XCTFail("Existing reference was deleted") }))
        XCTAssertEqual(proto.passwordReference, oldReference)
        XCTAssertEqual(proto.providerConfiguration?["WgQuickConfig"] as? String, legacy)
        XCTAssertEqual(try proto.readBypassHostnames(), ["host.example"])
        XCTAssertTrue(proto.enforceRoutes)
    }

    func testReplacementReadFailureDiscardsOnlyCandidateAndPreservesFallback() {
        let (proto, legacy) = makeLegacyProfile()
        let candidate = Data([2])
        var discarded = [Data]()

        XCTAssertFalse(proto.migrateLegacyConfiguration(legacy, called: "Test", read: { _ in nil },
            create: { payload, _ in XCTAssertEqual(payload, legacy); return candidate },
            delete: { discarded.append($0) }))
        XCTAssertNil(proto.passwordReference)
        XCTAssertEqual(discarded, [candidate])
        XCTAssertEqual(proto.providerConfiguration?["WgQuickConfig"] as? String, legacy)
    }

    func testReadableReplacementRemovesFallbackAndKeepsMetadata() throws {
        let (proto, legacy) = makeLegacyProfile()
        let candidate = Data([3])

        XCTAssertTrue(proto.migrateLegacyConfiguration(legacy, called: "Test", read: { reference in
            XCTAssertEqual(reference, candidate)
            return legacy
        }, create: { _, _ in candidate }, delete: { _ in XCTFail("Readable replacement was deleted") }))
        XCTAssertEqual(proto.passwordReference, candidate)
        XCTAssertNil(proto.providerConfiguration?["WgQuickConfig"])
        XCTAssertEqual(proto.providerConfiguration?["UID"] as? uid_t, getuid())
        XCTAssertEqual(try proto.readBypassHostnames(), ["host.example"])
        XCTAssertTrue(proto.enforceRoutes)
    }

    func testVerifiedConfigurationReplacementDeletesOldReferenceOnlyAfterSave() throws {
        let edit = try makeReplacementEdit(keepLegacyFallback: false)
        var completed = false
        edit.save { error in
            XCTAssertNil(error)
            completed = true
        }

        XCTAssertFalse(completed)
        XCTAssertEqual(edit.store.reads, [edit.store.newReference])
        XCTAssertEqual(edit.store.payload, edit.configuration.asWgQuickConfig())
        XCTAssertTrue(edit.store.deleted.isEmpty)
        XCTAssertEqual(edit.provider.savedProtocol?.passwordReference, edit.store.oldReference)
        XCTAssertEqual(edit.provider.session.stopCount, 0)

        try XCTUnwrap(edit.provider.pendingSave)(nil)
        XCTAssertTrue(completed)
        XCTAssertEqual(edit.store.deleted, [edit.store.oldReference])
        XCTAssertEqual(edit.provider.savedProtocol?.passwordReference, edit.store.newReference)
        XCTAssertEqual(edit.provider.savedProtocol?.serverAddress, "192.0.2.25:51820")
        XCTAssertEqual(try edit.provider.savedProtocol?.readBypassHostnames(), ["new.example"])
        XCTAssertEqual(edit.provider.session.stopCount, 1)
    }

    func testUnreadableConfigurationReplacementLeavesOriginalAndDiscardsCandidate() throws {
        let edit = try makeReplacementEdit()
        edit.store.isReadable = false
        var failed = false
        edit.save { error in
            guard case .systemErrorOnModifyTunnel? = error else { return XCTFail("Expected an unreadable-replacement error") }
            failed = true
        }

        XCTAssertTrue(failed)
        XCTAssertEqual(edit.store.reads, [edit.store.newReference])
        XCTAssertEqual(edit.store.deleted, [edit.store.newReference])
        XCTAssertTrue(edit.provider.protocolConfiguration === edit.original)
        XCTAssertNotNil(edit.original.providerConfiguration?["WgQuickConfig"])
        XCTAssertEqual(try edit.original.readBypassHostnames(), ["host.example"])
        XCTAssertEqual(edit.provider.saveCount, 0)
        XCTAssertEqual(edit.provider.session.stopCount, 0)
    }

    func testFailedReplacementSaveRestoresOriginalAndDiscardsOnlyCandidate() throws {
        let edit = try makeReplacementEdit()
        var failed = false
        edit.save { error in
            guard case .systemErrorOnModifyTunnel? = error else { return XCTFail("Expected a preference-save error") }
            failed = true
        }
        let candidate = try XCTUnwrap(edit.provider.protocolConfiguration as? NETunnelProviderProtocol)
        XCTAssertNil(candidate.providerConfiguration?["WgQuickConfig"])
        XCTAssertNotNil(edit.original.providerConfiguration?["WgQuickConfig"])
        XCTAssertTrue(edit.store.deleted.isEmpty)

        try XCTUnwrap(edit.provider.pendingSave)(NSError(domain: "Preferences", code: 1))
        XCTAssertTrue(failed)
        let restored = try XCTUnwrap(edit.provider.protocolConfiguration as? NETunnelProviderProtocol)
        XCTAssertEqual(restored.passwordReference, edit.store.oldReference)
        XCTAssertEqual(restored.providerConfiguration?["WgQuickConfig"] as? String,
                       edit.original.providerConfiguration?["WgQuickConfig"] as? String)
        XCTAssertEqual(restored.serverAddress, edit.original.serverAddress)
        XCTAssertEqual(edit.provider.savedProtocol?.passwordReference, edit.store.oldReference)
        XCTAssertEqual(try restored.readBypassHostnames(), ["host.example"])
        XCTAssertEqual(edit.store.deleted, [edit.store.newReference])
        XCTAssertEqual(edit.provider.session.stopCount, 0)
    }

    func testReplacementAfterIncompleteMigrationCannotFallBackToOldPayload() throws {
        let edit = try makeReplacementEdit()
        XCTAssertNotNil(edit.original.providerConfiguration?["WgQuickConfig"])
        edit.save { XCTAssertNil($0) }
        try XCTUnwrap(edit.provider.pendingSave)(nil)

        let saved = try XCTUnwrap(edit.provider.savedProtocol)
        XCTAssertNil(saved.providerConfiguration?["WgQuickConfig"])
        XCTAssertEqual(saved.providerConfiguration?["UID"] as? uid_t, getuid())
        XCTAssertTrue(saved.enforceRoutes)
        XCTAssertEqual(try saved.readBypassHostnames(), ["new.example"])
        XCTAssertEqual(edit.store.payload, edit.configuration.asWgQuickConfig())
        // The fake persistent reference cannot be read by the real Keychain.
        XCTAssertNil(saved.asTunnelConfiguration())
    }

    func testInvalidCombinedEditDoesNotStopOrSave() throws {
        let duplicate = NETunnelProviderManager()
        duplicate.localizedDescription = "Duplicate"
        let (provider, manager, tunnel) = try makeActiveTunnel(additionalProfiles: [duplicate])
        let edited = try XCTUnwrap(tunnel.tunnelConfiguration)
        let renamed = TunnelConfiguration(name: "Duplicate", interface: edited.interface, peers: edited.peers)

        var rejected = false
        manager.modify(tunnel: tunnel, tunnelConfiguration: renamed,
                       onDemandOption: .anyInterface(.anySSID), bypassHostnames: ["new.example"]) { error in
            guard case .tunnelAlreadyExistsWithThatName? = error else { return XCTFail("Expected duplicate-name error") }
            rejected = true
        }
        XCTAssertTrue(rejected)
        XCTAssertNil(provider.pendingSave)
        XCTAssertEqual(provider.session.stopCount, 0)
        XCTAssertEqual(tunnel.status, .active)
    }

    func testFailedCombinedSaveKeepsActiveTunnelAndOldProfile() throws {
        let (provider, manager, tunnel) = try makeActiveTunnel()
        let edited = try XCTUnwrap(tunnel.tunnelConfiguration)
        let originalProtocol = try XCTUnwrap(provider.protocolConfiguration as? NETunnelProviderProtocol)
        let originalReference = Data([4])
        originalProtocol.passwordReference = originalReference
        provider.protocolConfiguration = originalProtocol
        let saveError = NSError(domain: "Preferences", code: 1)
        var reportedFailure = false

        manager.modify(tunnel: tunnel, tunnelConfiguration: edited,
                       onDemandOption: .anyInterface(.anySSID), bypassHostnames: ["new.example"]) { error in
            guard case .systemErrorOnModifyTunnel? = error else { return XCTFail("Expected save error") }
            reportedFailure = true
        }
        XCTAssertEqual(provider.session.stopCount, 0)
        try XCTUnwrap(provider.pendingSave)(saveError)
        XCTAssertTrue(reportedFailure)
        XCTAssertEqual(provider.session.stopCount, 0)
        XCTAssertEqual(tunnel.status, .active)
        XCTAssertFalse(provider.isOnDemandEnabled)
        XCTAssertNil(provider.onDemandRules)
        let restored = try XCTUnwrap(provider.protocolConfiguration as? NETunnelProviderProtocol)
        XCTAssertEqual(restored.passwordReference, originalReference)
        XCTAssertEqual(try restored.readBypassHostnames(), ["host.example"])
        XCTAssertTrue(restored.enforceRoutes)
    }

    func testSuccessfulCombinedSaveRestartsOnlyAfterPreferencesSucceed() throws {
        let (provider, manager, tunnel) = try makeActiveTunnel()
        let edited = try XCTUnwrap(tunnel.tunnelConfiguration)
        var saved = false

        manager.modify(tunnel: tunnel, tunnelConfiguration: edited,
                       onDemandOption: .anyInterface(.anySSID), bypassHostnames: ["new.example"]) { error in
            XCTAssertNil(error)
            saved = true
        }
        XCTAssertEqual(provider.session.stopCount, 0)
        try XCTUnwrap(provider.pendingSave)(nil)
        XCTAssertTrue(saved)
        XCTAssertEqual(provider.session.stopCount, 1)
        XCTAssertEqual(tunnel.status, .restarting)
        XCTAssertTrue(provider.isOnDemandEnabled)
        XCTAssertEqual(tunnel.bypassHostnames, ["new.example"])
    }

    @MainActor
    func testClearingPolicyRemovesItWhenProfileReopens() throws {
        let (provider, manager, tunnel) = try makeActiveTunnel()
        let editor = makeEditor(manager: manager, tunnel: tunnel)
        XCTAssertEqual(editor.bypassHostnamesRow.value, "host.example")
        editor.bypassHostnamesRow.value = ""
        editor.handleSaveAction()
        try XCTUnwrap(provider.pendingSave)(nil)

        let saved = try XCTUnwrap(provider.savedProtocol)
        XCTAssertFalse(saved.hasBypassHostnamePolicy)
        let reopenedManager = TunnelsManager(tunnelProviders: [try reopen(provider)])
        let reopened = try XCTUnwrap(reopenedManager.tunnel(named: "Test"))
        XCTAssertEqual(makeEditor(manager: reopenedManager, tunnel: reopened).bypassHostnamesRow.value, "")
        XCTAssertEqual(provider.session.stopCount, 1)
    }

    func testPolicyEditsStayIsolatedBetweenSavedProfiles() throws {
        let secondProvider = TestProvider()
        secondProvider.localizedDescription = "Second"
        secondProvider.protocolConfiguration = makeLegacyProfile().0
        let (firstProvider, manager, first) = try makeActiveTunnel(additionalProfiles: [secondProvider])
        let second = try XCTUnwrap(manager.tunnel(named: "Second"))

        for (provider, tunnel, hostname) in [(firstProvider, first, "first.example"), (secondProvider, second, "second.example")] {
            manager.modify(tunnel: tunnel, tunnelConfiguration: try XCTUnwrap(tunnel.tunnelConfiguration),
                           onDemandOption: .off, bypassHostnames: [hostname]) { XCTAssertNil($0) }
            try XCTUnwrap(provider.pendingSave)(nil)
        }

        XCTAssertEqual(firstProvider.saveCount, 1)
        XCTAssertEqual(secondProvider.saveCount, 1)
        let reopened = TunnelsManager(tunnelProviders: [try reopen(firstProvider), try reopen(secondProvider)])
        XCTAssertEqual(reopened.tunnel(named: "Test")?.bypassHostnames, ["first.example"])
        XCTAssertEqual(reopened.tunnel(named: "Second")?.bypassHostnames, ["second.example"])
    }

    func testUnsupportedRoutingRejectsPolicyWithoutSavingOrStopping() throws {
        let (provider, manager, tunnel) = try makeActiveTunnel()
        let config = try XCTUnwrap(tunnel.tunnelConfiguration)
        let proto = try XCTUnwrap(provider.protocolConfiguration as? NETunnelProviderProtocol)
        let extraPeer = PeerConfiguration(publicKey: PrivateKey().publicKey)
        var splitPeer = try XCTUnwrap(config.peers.first)
        splitPeer.allowedIPs = [try XCTUnwrap(IPAddressRange(from: "10.0.0.0/8"))]
        let cases = [
            ("multiple peers", config.peers + [extraPeer], false),
            ("no default route", [splitPeer], false),
            ("Include All Networks", config.peers, true)
        ]

        for (name, peers, includeAllNetworks) in cases {
            proto.includeAllNetworks = includeAllNetworks
            let edited = TunnelConfiguration(name: config.name, interface: config.interface, peers: peers)
            var rejected = false
            manager.modify(tunnel: tunnel, tunnelConfiguration: edited, onDemandOption: .off,
                           bypassHostnames: ["new.example"]) { error in
                guard case .invalidBypassPolicy(.unsupportedBypassRouting)? = error else {
                    return XCTFail("Expected unsupported routing for \(name)")
                }
                rejected = true
            }
            XCTAssertTrue(rejected, name)
            XCTAssertEqual(provider.saveCount, 0, name)
            XCTAssertEqual(provider.session.stopCount, 0, name)
            XCTAssertEqual(tunnel.bypassHostnames, ["host.example"], name)
        }
    }

    @MainActor
    func testEditorRejectsDuplicateSaveAndRecoversAfterFailure() throws {
        let (provider, manager, tunnel) = try makeActiveTunnel()
        let editor = makeEditor(manager: manager, tunnel: tunnel)
        editor.bypassHostnamesRow.value = "new.example"
        editor.handleSaveAction()
        editor.handleSaveAction()
        XCTAssertEqual(provider.saveCount, 1)
        XCTAssertFalse(editor.saveButton.isEnabled)

        try XCTUnwrap(provider.pendingSave)(NSError(domain: "Preferences", code: 1))
        guard case .systemErrorOnModifyTunnel? = editor.saveAlert else {
            return XCTFail("Expected a preference-save error")
        }
        XCTAssertTrue(editor.saveButton.isEnabled)
        XCTAssertEqual(editor.bypassHostnamesRow.value, "new.example")
        XCTAssertEqual(tunnel.bypassHostnames, ["host.example"])
        XCTAssertEqual(provider.session.stopCount, 0)

        editor.handleSaveAction()
        XCTAssertEqual(provider.saveCount, 2)
        try XCTUnwrap(provider.pendingSave)(nil)
        editor.handleSaveAction()
        XCTAssertEqual(provider.saveCount, 2)
        XCTAssertFalse(editor.saveButton.isEnabled)
        XCTAssertEqual(tunnel.bypassHostnames, ["new.example"])
        XCTAssertEqual(provider.session.stopCount, 1)
    }

    @MainActor
    func testReloadFailureKeepsSavedProfileAndFinishesWithoutRepeatingSave() throws {
        let (provider, manager, tunnel) = try makeActiveTunnel()
        let editor = makeEditor(manager: manager, tunnel: tunnel)
        let delegate = EditDelegate()
        editor.delegate = delegate
        editor.bypassHostnamesRow.value = "new.example"
        editor.onDemandControlsRow.onDemandEthernetCheckbox.state = .on
        let reloadError = NSError(domain: "Preferences", code: 2)
        provider.reloadError = reloadError

        editor.handleSaveAction()
        try XCTUnwrap(provider.pendingSave)(nil)
        guard case .savedButOnDemandReloadFailed(let error)? = editor.saveAlert else {
            return XCTFail("Expected a successful-save warning")
        }
        XCTAssertEqual(error as NSError, reloadError)
        XCTAssertEqual(try provider.savedProtocol?.readBypassHostnames(), ["new.example"])
        XCTAssertEqual(delegate.saveCount, 0)
        XCTAssertFalse(editor.saveButton.isEnabled)

        editor.handleSaveAction()
        editor.handleDiscardAction()
        try XCTUnwrap(editor.dismissSaveAlert)()
        XCTAssertEqual(delegate.saveCount, 1)
        XCTAssertEqual(delegate.cancelCount, 0)
        XCTAssertFalse(editor.saveButton.isEnabled)
        XCTAssertEqual(provider.saveCount, 1)
        XCTAssertEqual(provider.reloadCount, 1)
        XCTAssertEqual(provider.session.stopCount, 1)
    }

    @MainActor
    private func makeEditor(manager: TunnelsManager, tunnel: TunnelContainer) -> TestEditor {
        _ = NSApplication.shared
        let editor = TestEditor(tunnelsManager: manager, tunnel: tunnel)
        _ = editor.view
        return editor
    }

    private func reopen(_ provider: TestProvider) throws -> TestProvider {
        let reopened = TestProvider()
        reopened.localizedDescription = provider.localizedDescription
        reopened.protocolConfiguration = try XCTUnwrap(provider.savedProtocol)
        return reopened
    }

    private func makeLegacyProfile() -> (NETunnelProviderProtocol, String) {
        var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
        peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]
        let config = TunnelConfiguration(name: "Test", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [peer])
        let legacy = config.asWgQuickConfig()
        let proto = NETunnelProviderProtocol()
        proto.providerConfiguration = ["WgQuickConfig": legacy, "UID": getuid()]
        proto.setBypassHostnames(["host.example"])
        proto.enforceRoutes = true
        return (proto, legacy)
    }

    private func makeReplacementEdit(keepLegacyFallback: Bool = true) throws -> ReplacementEdit {
        let store = TestConfigurationStore()
        let (provider, manager, tunnel) = try makeActiveTunnel(bypassConfigurationStore: store.operations)
        let original = try XCTUnwrap(provider.protocolConfiguration as? NETunnelProviderProtocol)
        let configuration = try XCTUnwrap(tunnel.tunnelConfiguration)
        original.passwordReference = store.oldReference
        if !keepLegacyFallback { original.providerConfiguration?["WgQuickConfig"] = nil }
        provider.savedProtocol = original.copy() as? NETunnelProviderProtocol
        var editedInterface = configuration.interface
        editedInterface.privateKey = PrivateKey()
        var peers = configuration.peers
        peers[0].endpoint = try XCTUnwrap(Endpoint(from: "192.0.2.25:51820"))
        let edited = TunnelConfiguration(name: configuration.name, interface: editedInterface, peers: peers)
        return ReplacementEdit(provider: provider, manager: manager, tunnel: tunnel,
                               original: original, configuration: edited, store: store)
    }

    private func makeActiveTunnel(additionalProfiles: [NETunnelProviderManager] = [],
                                  bypassConfigurationStore: TunnelsManager.BypassConfigurationStore = .init()) throws
        -> (TestProvider, TunnelsManager, TunnelContainer) {
        let provider = TestProvider()
        provider.localizedDescription = "Test"
        provider.protocolConfiguration = makeLegacyProfile().0
        provider.isEnabled = true
        let manager = TunnelsManager(tunnelProviders: [provider] + additionalProfiles, bypassConfigurationStore: bypassConfigurationStore)
        let tunnel = try XCTUnwrap(manager.tunnel(named: "Test"))
        tunnel.status = .active
        return (provider, manager, tunnel)
    }
}

private struct ReplacementEdit {
    let provider: TestProvider
    let manager: TunnelsManager
    let tunnel: TunnelContainer
    let original: NETunnelProviderProtocol
    let configuration: TunnelConfiguration
    let store: TestConfigurationStore

    func save(completion: @escaping (TunnelsManagerError?) -> Void) {
        manager.modify(tunnel: tunnel, tunnelConfiguration: configuration, onDemandOption: .off,
                       bypassHostnames: ["new.example"], completionHandler: completion)
    }
}

private final class TestConfigurationStore {
    let oldReference = Data([40])
    let newReference = Data([41])
    var isReadable = true
    var payload: String?
    var reads = [Data]()
    var deleted = [Data]()

    var operations: TunnelsManager.BypassConfigurationStore {
        .init(create: { configuration in
            self.payload = configuration.asWgQuickConfig()
            let proto = NETunnelProviderProtocol()
            proto.passwordReference = self.newReference
            proto.serverAddress = configuration.peers.first?.endpoint?.stringRepresentation
            return proto
        }, read: { reference in
            self.reads.append(reference)
            return self.isReadable && reference == self.newReference ? self.payload : nil
        }, delete: { self.deleted.append($0) })
    }
}

private final class TestProvider: NETunnelProviderManager {
    let session = TestSession()
    var pendingSave: ((Error?) -> Void)?
    var savedProtocol: NETunnelProviderProtocol?
    var saveCount = 0
    var reloadCount = 0
    var reloadError: Error?
    override var connection: NEVPNConnection { session }

    override func saveToPreferences(completionHandler: ((Error?) -> Void)? = nil) {
        saveCount += 1
        let profile = protocolConfiguration?.copy() as? NETunnelProviderProtocol
        pendingSave = { [weak self] error in
            if error == nil { self?.savedProtocol = profile }
            completionHandler?(error)
        }
    }

    override func loadFromPreferences(completionHandler: @escaping (Error?) -> Void) {
        reloadCount += 1
        completionHandler(reloadError)
    }
}

private final class TestSession: NETunnelProviderSession {
    var stopCount = 0
    override func stopTunnel() { stopCount += 1 }
}

private final class TestEditor: TunnelEditViewController {
    var saveAlert: TunnelsManagerError?
    var dismissSaveAlert: (() -> Void)?

    override func presentSaveAlert(_ error: TunnelsManagerError, onDismissal: (() -> Void)?) {
        saveAlert = error
        dismissSaveAlert = onDismissal
    }
}

private final class EditDelegate: TunnelEditViewControllerDelegate {
    var saveCount = 0
    var cancelCount = 0

    func tunnelSaved(tunnel: TunnelContainer) { saveCount += 1 }
    func tunnelEditingCancelled() { cancelCount += 1 }
}
