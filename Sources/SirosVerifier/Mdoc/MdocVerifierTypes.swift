// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One requested mdoc data element.
public struct MdocRequestedElement: Sendable, Equatable {
    public let identifier: String
    public let intentToRetain: Bool

    public init(identifier: String, intentToRetain: Bool = false) {
        self.identifier = identifier
        self.intentToRetain = intentToRetain
    }
}

/// An ordered namespace and its ordered element requests.
public struct MdocRequestedNamespace: Sendable, Equatable {
    public let namespace: String
    public let elements: [MdocRequestedElement]

    public init(namespace: String, elements: [MdocRequestedElement]) {
        self.namespace = namespace
        self.elements = elements
    }
}

/// Signs the exact COSE input supplied by verifier-core with a dedicated P-256 reader key.
///
/// The closure must synchronously return a raw 64-byte ES256 `r || s` signature,
/// not a DER signature or compact JWS. It is deliberately synchronous: verifier-core
/// invokes it from inside request construction and cannot await a Swift task.
public typealias MdocReaderAuthSigner = @Sendable (_ data: [UInt8]) throws -> [UInt8]

/// Reader authentication using a dedicated verifier identity certificate chain.
public struct MdocReaderAuthentication: Sendable {
    /// DER certificates, leaf first.
    public let certificateChain: [[UInt8]]
    public let signer: MdocReaderAuthSigner

    public init(
        certificateChain: [[UInt8]],
        signer: @escaping MdocReaderAuthSigner
    ) {
        self.certificateChain = certificateChain
        self.signer = signer
    }
}

/// One ordered mdoc document request.
public struct MdocDocumentRequest: Sendable {
    public let docType: String
    public let namespaces: [MdocRequestedNamespace]
    public let readerAuth: MdocReaderAuthentication?

    public init(
        docType: String,
        namespaces: [MdocRequestedNamespace],
        readerAuth: MdocReaderAuthentication? = nil
    ) {
        self.docType = docType
        self.namespaces = namespaces
        self.readerAuth = readerAuth
    }
}

/// A cryptographically verified and policy-authorized mdoc element.
public struct VerifiedMdocElement: Sendable, Equatable {
    public let namespace: String
    public let identifier: String
    /// CBOR-encoded element value; the application decodes only the types it displays.
    public let valueCbor: [UInt8]

    internal init(namespace: String, identifier: String, valueCbor: [UInt8]) {
        self.namespace = namespace
        self.identifier = identifier
        self.valueCbor = valueCbor
    }
}

/// A document released after core verification, request-policy checks, and go-trust permit.
public struct VerifiedMdocDocument: Sendable, Equatable {
    public let docType: String
    public let elements: [VerifiedMdocElement]
    /// Authentic issuer DER certificates, leaf first; authorization was evaluated separately by go-trust.
    public let issuerX5c: [[UInt8]]
    public let validUntil: Int64

    internal init(
        docType: String,
        elements: [VerifiedMdocElement],
        issuerX5c: [[UInt8]],
        validUntil: Int64
    ) {
        self.docType = docType
        self.elements = elements
        self.issuerX5c = issuerX5c
        self.validUntil = validUntil
    }
}

/// A reader message that either completes verification or reports peer termination.
public enum MdocReaderInbound: Sendable, Equatable {
    /// Claims are available only after every document has an explicit go-trust permit.
    case verified(documents: [VerifiedMdocDocument])
    /// The wallet ended the session. Status 20 is normal termination.
    case sessionOver(status: UInt64)
}

/// A verifier-core rejection with its stable machine-readable class preserved.
public struct MdocVerifierException: Error, Sendable, Equatable {
    public let code: String
    public let detail: String

    public init(code: String, detail: String) {
        self.code = code
        self.detail = detail
    }
}

extension MdocVerifierException: CustomStringConvertible {
    public var description: String { "\(code): \(detail)" }
}

extension MdocVerifierException: LocalizedError {
    public var errorDescription: String? { description }
}

/// An operation attempted after its reader session was closed.
public enum MdocReaderSessionError: Error, Sendable, Equatable {
    case closed
}

extension MdocReaderSessionError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .closed:
            return "The reader session is closed"
        }
    }
}

extension MdocReaderSessionError: LocalizedError {
    public var errorDescription: String? { description }
}
