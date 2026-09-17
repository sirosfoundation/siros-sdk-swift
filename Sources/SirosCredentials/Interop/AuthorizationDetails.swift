// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

/// OID4VCI `authorization_details` construction.
///
/// DIIP requires a Wallet to support both ways of asking an Issuer for a
/// specific credential type: `authorization_details` carrying a
/// `credential_configuration_id` (OID4VCI 1.0 §5.1.1), and the `scope`
/// parameter. `authorization_details` is the structured form and the one
/// Issuer Agents must support, so the wallet sends it whenever it knows which
/// configuration it wants.
///
/// This lives apart from any transport on purpose. These SDKs never build the
/// Authorization Request - go-wallet-backend's engine does, for every
/// transport - so the *decision* stays here, where DIIP puts it, and the
/// transport only forwards the result. wallet-frontend makes the same split
/// for the same reason (`lib/openid-flow/authorizationDetails.ts`), and the
/// two have to agree: they talk to the same engine and the same issuers.
///
/// ``AuthorizationDetail`` itself lives in `SirosTransport`, with the wire
/// messages that carry it - that module deliberately has no dependencies, so
/// the type cannot live here. The decision does.
public enum AuthorizationDetails {

    /// The only `authorization_details` type OID4VCI defines for issuance.
    public static let openidCredential = "openid_credential"

    /// Build the `authorization_details` for one credential configuration, or
    /// nil when the wallet should not send any.
    ///
    /// `advertisedTypes` is the Authorization Server's
    /// `authorization_details_types_supported`, and is optional because the
    /// wallet does not always hold it: on the engine-driven transports the
    /// Authorization Server is discovered server-side. When it is absent the
    /// details are built anyway and the engine, which does have the metadata,
    /// decides whether to use them - sending intent the Issuer may ignore is
    /// safe, whereas withholding it would fail the requirement outright. When
    /// it is present, an Authorization Server that advertises its supported
    /// types *without* `openid_credential` is taken at its word.
    public static func build(
        credentialConfigurationID: String?,
        advertisedTypes: [String]? = nil
    ) -> [AuthorizationDetail]? {
        guard let credentialConfigurationID,
              !credentialConfigurationID.trimmingCharacters(in: .whitespaces).isEmpty
        else { return nil }
        if let advertisedTypes, !advertisedTypes.contains(openidCredential) {
            return nil
        }
        return [AuthorizationDetail(credentialConfigurationID: credentialConfigurationID)]
    }
}
