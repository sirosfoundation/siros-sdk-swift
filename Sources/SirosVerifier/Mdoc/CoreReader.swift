// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

internal struct CoreVerifiedDocument: Sendable {
    let docType: String
    let elements: [VerifiedMdocElement]
    let issuerX5c: [[UInt8]]
    let validUntil: Int64
    let authzenRequestJSON: String
}

/// Synchronous by design: MdocReaderSession moves every call off the cooperative pool.
internal protocol CoreReader: AnyObject, Sendable {
    func establishmentMessage(documents: [MdocDocumentRequest]) throws -> [UInt8]
    func dataMessage(documents: [MdocDocumentRequest]) throws -> [UInt8]
    func openResponse(
        sessionData: [UInt8],
        now: Int64,
        acceptedDocTypes: [String]
    ) throws -> [CoreVerifiedDocument]
    func terminationMessage() throws -> [UInt8]
    func close()
}

internal protocol CoreReaderFactory: Sendable {
    func start(
        deviceEngagement: [UInt8],
        handover: [UInt8],
        mdocIssuerRole: String
    ) throws -> any CoreReader
}

internal struct CoreSessionOverError: Error, Sendable {
    let status: UInt64
}

internal struct CoreRejectedError: Error, Sendable {
    let code: String
    let detail: String
}

internal struct CoreNativeUnavailableError: Error, Sendable {
    let detail: String
}

internal struct FfiCoreReaderFactory: CoreReaderFactory {
    func start(
        deviceEngagement: [UInt8],
        handover: [UInt8],
        mdocIssuerRole: String
    ) throws -> any CoreReader {
        #if os(iOS) && canImport(siros_verifier_core_ffiFFI)
        return try mapFfiErrors {
            FfiCoreReader(reader: try Reader.startWithRole(
                deviceEngagement: Data(deviceEngagement),
                handover: Data(handover),
                mdocIssuerRole: mdocIssuerRole
            ))
        }
        #else
        throw CoreNativeUnavailableError(
            detail: "SirosVerifierCore.xcframework is unavailable; set SIROS_VERIFIER_CORE_XCFRAMEWORK_PATH when building the iOS package"
        )
        #endif
    }
}

#if os(iOS) && canImport(siros_verifier_core_ffiFFI)
private final class FfiCoreReader: CoreReader, @unchecked Sendable {
    // Nil releases the UniFFI object and its native Reader deterministically.
    // Session serialization is the only synchronization needed for this property.
    private var reader: Reader?

    init(reader: Reader) {
        self.reader = reader
    }

    func establishmentMessage(documents: [MdocDocumentRequest]) throws -> [UInt8] {
        let reader = try requireReader()
        return try mapFfiErrors {
            [UInt8](try withNativeDocuments(documents) {
                try reader.establishmentMessageFromDocuments(documents: $0)
            })
        }
    }

    func dataMessage(documents: [MdocDocumentRequest]) throws -> [UInt8] {
        let reader = try requireReader()
        return try mapFfiErrors {
            [UInt8](try withNativeDocuments(documents) {
                try reader.dataMessageFromDocuments(documents: $0)
            })
        }
    }

    func openResponse(
        sessionData: [UInt8],
        now: Int64,
        acceptedDocTypes: [String]
    ) throws -> [CoreVerifiedDocument] {
        let reader = try requireReader()
        return try mapFfiErrors {
            try reader.openResponse(
                sessionData: Data(sessionData),
                now: now,
                acceptedDocTypes: acceptedDocTypes
            ).map(coreDocument)
        }
    }

    func terminationMessage() throws -> [UInt8] {
        let reader = try requireReader()
        return try mapFfiErrors { [UInt8](try reader.terminationMessage()) }
    }

    func close() {
        reader = nil
    }

    private func requireReader() throws -> Reader {
        guard let reader else {
            throw CoreRejectedError(code: "closed", detail: "The native reader is closed")
        }
        return reader
    }
}

private final class FfiReaderAuthSigner: ReaderAuthSigner, @unchecked Sendable {
    private let signer: MdocReaderAuthSigner

    init(signer: @escaping MdocReaderAuthSigner) {
        self.signer = signer
    }

    func signEs256(data: Data) throws -> Data {
        do {
            return Data(try signer([UInt8](data)))
        } catch let error as FfiError {
            throw error
        } catch {
            // UniFFI foreign callbacks must throw the generated error type. The
            // callback remains synchronous and never waits on a Swift executor.
            throw FfiError.Rejected(code: "crypto", detail: String(describing: error))
        }
    }
}

private func withNativeDocuments(
    _ documents: [MdocDocumentRequest],
    operation: ([RequestedDocument]) throws -> Data
) throws -> Data {
    // Keep each ReaderAuth and foreign signer alive through the complete native
    // call. RequestedDocument also retains its ReaderAuth while crossing UniFFI.
    var nativeAuthentications: [ReaderAuth] = []
    let nativeDocuments = documents.map { document in
        let readerAuth = document.readerAuth.map { authentication in
            ReaderAuth(
                x5cDer: authentication.certificateChain.map { Data($0) },
                signer: FfiReaderAuthSigner(signer: authentication.signer)
            )
        }
        if let readerAuth {
            nativeAuthentications.append(readerAuth)
        }
        return RequestedDocument(
            docType: document.docType,
            namespaces: document.namespaces.map { namespace in
                RequestedNamespace(
                    namespace: namespace.namespace,
                    elements: namespace.elements.map { element in
                        RequestedElement(
                            identifier: element.identifier,
                            intentToRetain: element.intentToRetain
                        )
                    }
                )
            },
            readerAuth: readerAuth
        )
    }
    return try withExtendedLifetime(nativeAuthentications) {
        try operation(nativeDocuments)
    }
}

private func coreDocument(_ document: VerifiedDocument) -> CoreVerifiedDocument {
    CoreVerifiedDocument(
        docType: document.docType,
        elements: document.elements.map { element in
            VerifiedMdocElement(
                namespace: element.namespace,
                identifier: element.identifier,
                valueCbor: [UInt8](element.valueCbor)
            )
        },
        issuerX5c: document.issuerX5c.map { [UInt8]($0) },
        validUntil: document.validUntil,
        authzenRequestJSON: document.authzenRequestJson
    )
}

private func mapFfiErrors<T>(_ operation: () throws -> T) throws -> T {
    do {
        return try operation()
    } catch FfiError.SessionOver(let status) {
        throw CoreSessionOverError(status: status)
    } catch FfiError.Rejected(let code, let detail) {
        throw CoreRejectedError(code: code, detail: detail)
    }
}
#endif
