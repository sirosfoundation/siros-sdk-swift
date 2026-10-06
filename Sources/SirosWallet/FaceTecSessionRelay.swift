// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// How a FaceTec session ended (FaceTec's `FaceTecSessionStatus`), kept free of
/// FaceTec types so ``sessionOutcome(status:relay:)`` can be tested without the
/// FaceTec SDK.
enum FaceTecSessionEnd: Sendable, Equatable {
    case sessionCompleted
    case requestAborted
    case userCancelledFaceScan
    case userCancelledIdScan
    case lockedOut
    case cameraError
    case cameraPermissionsDenied
    case unknownInternalError
}

/// The logic behind one session's `FaceTecSessionRequestProcessor`, free of
/// FaceTec types. ``FaceTecIDVProvider`` wraps it in the real protocol.
///
/// It relays each request blob to facetec-api and remembers what facetec-api
/// said about issuance, for ``sessionOutcome(status:relay:)`` once the session
/// has finished.
final class FaceTecSessionRelay: @unchecked Sendable {
    typealias Post = @Sendable (_ requestBlob: String, _ externalDatabaseRefID: String) async throws -> ProcessRequestResponse

    /// Identifies this session's Enrollment Record on FaceTec Server. It must
    /// stay the same for every request of one session (the liveness step files
    /// the record under it and the ID match step looks it up, and facetec-api
    /// refuses a final result whose session has no proven liveness step under
    /// this key), and differ between sessions, since a key can only be enrolled
    /// once. facetec-api cannot mint it: the requests of one session carry
    /// nothing that ties them together. One relay per session gives exactly
    /// that.
    let externalDatabaseRefID = "siros-sdk-ios-" + UUID().uuidString

    private let post: Post
    private let lock = NSLock()
    private var _credentialOfferURI: String?
    private var _transactionId: String?
    private var _credentialIssueErrorCode: String?
    private var _credentialIssueError: String?
    private var _transportError: Error?

    init(post: @escaping Post) {
        self.post = post
    }

    var credentialOfferURI: String? { locked { _credentialOfferURI } }
    var transactionId: String? { locked { _transactionId } }
    var credentialIssueErrorCode: String? { locked { _credentialIssueErrorCode } }
    var credentialIssueError: String? { locked { _credentialIssueError } }
    /// The failure that made the relay abort the session, if any.
    var transportError: Error? { locked { _transportError } }

    /// Relays one request. Returns the response blob for the FaceTec SDK, or
    /// `nil` when the session has to be aborted (`abortOnCatastrophicError`); the
    /// cause is in ``transportError``.
    func onSessionRequest(_ requestBlob: String) async -> String? {
        do {
            let response = try await post(requestBlob, externalDatabaseRefID)
            locked {
                if let offer = response.credentialOfferURI {
                    _credentialOfferURI = offer
                    _transactionId = response.transactionId
                }
                if let code = response.credentialIssueErrorCode {
                    _credentialIssueErrorCode = code
                    _credentialIssueError = response.credentialIssueError
                }
            }
            return response.responseBlob
        } catch {
            locked { _transportError = error }
            return nil
        }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// Turns a finished FaceTec session into the provider's result.
///
/// What facetec-api said wins over the session status: an issued credential is
/// returned even if the SDK reports the session oddly, and a refusal is
/// reported as such rather than as whatever status the session ended with.
///
/// - Parameter status: How the session ended, or `nil` if the SDK reported none.
func sessionOutcome(status: FaceTecSessionEnd?, relay: FaceTecSessionRelay) throws -> IDVResult {
    if let offer = relay.credentialOfferURI {
        return IDVResult(credentialOfferURI: offer, transactionId: relay.transactionId)
    }
    if let code = relay.credentialIssueErrorCode {
        throw IDVError(refusalCode: code, message: relay.credentialIssueError)
    }

    switch status {
    case .userCancelledFaceScan, .userCancelledIdScan:
        throw IDVError.cancelled
    case .cameraPermissionsDenied:
        throw IDVError.unavailable(reason: "camera permission denied")
    case .cameraError:
        throw IDVError.unavailable(reason: "the camera could not be used")
    case .lockedOut:
        throw IDVError.providerError(code: "locked_out", message: "Too many attempts; FaceTec has locked this device out for a while")
    case .requestAborted:
        if let transportError = relay.transportError { throw IDVError.networkError(underlying: transportError) }
        throw IDVError.providerError(code: "request_aborted", message: "The FaceTec session was aborted")
    case .sessionCompleted:
        throw IDVError.verificationFailed(message: "The scan completed, but no credential was issued")
    case .unknownInternalError:
        throw IDVError.providerError(code: "unknown_internal_error", message: "FaceTec session ended with an internal error")
    case nil:
        throw IDVError.providerError(code: "no_session_result", message: "FaceTec returned no session result")
    }
}

extension IDVError {
    /// Maps facetec-api's `credentialIssueErrorCode` (or a legacy `/v1` body's
    /// `error_code`) to an ``IDVError``. Same mapping as siros-sdk-kotlin's
    /// `refusalToException`, so both SDKs report the same `errorCode`.
    ///
    /// - `nfc_*`: the document's chip was not read and authenticated
    ///   (``documentChipNotVerified(reason:message:)``).
    /// - `chip_untrusted`, `document_expired`, `session_expired`:
    ///   ``chipUntrusted(message:)``, ``documentExpired(message:)``,
    ///   ``sessionExpired(message:)``.
    /// - `liveness_failed`: ``livenessFailed(message:)``.
    /// - `match_failed`, `policy_rejected`, `document_unreadable`:
    ///   ``verificationFailed(message:)``.
    /// - Anything else, e.g. `issuance_failed`, `internal_error` or a code a
    ///   newer facetec-api adds: ``providerError(code:message:)``, which keeps
    ///   the code (`errorCode` = `idv_provider_<code>`) so an app can still
    ///   explain it.
    init(refusalCode code: String, message: String?) {
        let text = message ?? "No credential was issued (\(code))"
        if let typed = IDVError(typedRefusalCode: code, message: text) {
            self = typed
            return
        }
        switch code {
        case "liveness_failed":
            self = .livenessFailed(message: text)
        case "match_failed", "policy_rejected", "document_unreadable":
            self = .verificationFailed(message: text)
        default:
            self = .providerError(code: code, message: text)
        }
    }
}
