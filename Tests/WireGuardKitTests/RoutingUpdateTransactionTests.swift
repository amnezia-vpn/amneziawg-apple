import XCTest
@testable import WireGuardKit

final class RoutingUpdateTransactionTests: XCTestCase {
    private let failure = NSError(domain: "test", code: 1)

    private func run(peer: Bool = true, settings: NetworkSettingsApplication = .applied,
                     restoreSettings: NetworkSettingsApplication = .applied, restorePeer: Bool = true)
        -> (WireGuardRoutingUpdateResult, [String]) {
        var calls = [String]()
        let result = RoutingUpdateTransaction.apply(.init(
            updatePeer: { calls.append("peer"); return peer },
            applySettings: { calls.append("settings"); return settings },
            restoreSettings: { calls.append("restoreSettings"); return restoreSettings },
            restorePeer: { calls.append("restorePeer"); return restorePeer }
        ))
        return (result, calls)
    }

    func testSuccessPreparesPeerBeforeChangingRoutes() {
        let (result, calls) = run()
        XCTAssertEqual(result, .applied)
        XCTAssertEqual(calls, ["peer", "settings"])
    }

    func testFailedPeerIsRestoredWithoutChangingNetworkSettings() {
        let (result, calls) = run(peer: false)
        XCTAssertEqual(result, .notApplied)
        XCTAssertEqual(calls, ["peer", "restorePeer"])
    }

    func testFailedPeerRestorationIsUnknown() {
        XCTAssertEqual(run(peer: false, restorePeer: false).0, .stateUnknown)
    }

    func testRejectedNetworkSettingsRestoreBothLayers() {
        let (result, calls) = run(settings: .rejected(failure))
        XCTAssertEqual(result, .notApplied)
        XCTAssertEqual(calls, ["peer", "settings", "restoreSettings", "restorePeer"])
    }

    func testFailedNetworkRestorationStillRestoresPeerAndRemainsUnknown() {
        let (result, calls) = run(settings: .rejected(failure), restoreSettings: .rejected(failure))
        XCTAssertEqual(result, .stateUnknown)
        XCTAssertEqual(calls.last, "restorePeer")
    }

    func testTimedOutNetworkRestorationIsUnknown() {
        XCTAssertEqual(run(settings: .rejected(failure), restoreSettings: .stateUnknown).0, .stateUnknown)
    }

    func testFailedPeerRestorationAfterRouteRejectionIsUnknown() {
        XCTAssertEqual(run(settings: .rejected(failure), restorePeer: false).0, .stateUnknown)
    }

    func testMissingNetworkCompletionDoesNotSubmitACompetingRollback() {
        let (result, calls) = run(settings: .stateUnknown)
        XCTAssertEqual(result, .stateUnknown)
        XCTAssertEqual(calls, ["peer", "settings"])
    }

    func testImmediateCompletionIsNotLost() {
        let completion = NetworkSettingsCompletion()
        completion.complete(nil)
        guard case .applied = completion.wait(timeout: 0.1) else { return XCTFail("Expected confirmation") }
    }

    func testExplicitNetworkErrorIsPreserved() {
        let completion = NetworkSettingsCompletion()
        completion.complete(failure)
        guard case .rejected(let error) = completion.wait(timeout: 0.1) else { return XCTFail("Expected rejection") }
        XCTAssertEqual((error as NSError).code, failure.code)
    }

    func testMissingCallbackIsUnknown() {
        guard case .stateUnknown = NetworkSettingsCompletion().wait(timeout: 0.01) else {
            return XCTFail("Missing callback must not acknowledge settings")
        }
    }

    func testLateCompletionCannotChangeReturnedOutcome() {
        let completion = NetworkSettingsCompletion()
        let result = completion.wait(timeout: 0.01)
        completion.complete(nil)
        guard case .stateUnknown = result else { return XCTFail("Late callback must not acknowledge the old request") }
    }

    func testDuplicateCallbackCannotReplaceFirstOutcome() {
        let completion = NetworkSettingsCompletion()
        completion.complete(failure)
        completion.complete(nil)
        guard case .rejected = completion.wait(timeout: 0.1) else { return XCTFail("First result must be retained") }
    }

    func testCallbackFromAnotherThreadIsSynchronized() {
        let completion = NetworkSettingsCompletion()
        DispatchQueue.global().async { completion.complete(nil) }
        guard case .applied = completion.wait(timeout: 1) else { return XCTFail("Expected synchronized completion") }
    }
}
