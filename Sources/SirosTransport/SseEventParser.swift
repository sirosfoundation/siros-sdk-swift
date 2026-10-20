// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One dispatched Server-Sent Event.
public struct SseEvent: Sendable, Equatable {
    /// The event's `id` field, if it set one. Never contains NUL.
    public let id: String?
    /// The `event` field (the type), if any.
    public let event: String?
    /// The `data` lines joined with `\n`. May hold a delivered secret: never log it.
    public let data: String
}

extension SseEvent: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Redacted: a WMP frame can carry credentials, tokens and a delivered seed.
    public var description: String { "SseEvent(id: \(id ?? "nil"), <data redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [("id", id as Any)], displayStyle: .struct) }
}

/// An incremental parser for the `text/event-stream` format (WHATWG HTML section 9.2),
/// fed one line at a time (without its line terminator). Pure, so it is testable off
/// Apple platforms; the HTTP+SSE transport drives it.
///
/// Tracks the stream's `lastEventId` as the specification says: an `id` field (without NUL)
/// fills a buffer that is COMMITTED to `lastEventId` only when the block's terminating blank
/// line arrives, so an unfinished block never advances the resume cursor (a server resuming
/// after it could skip an event that was never delivered). It persists across events (an
/// event without an `id` does not reset it) and is what a reconnect sends as `Last-Event-ID`;
/// an empty `id` resets it to nil. Call ``beginResponse()`` at the start of each HTTP response.
public struct SseEventParser: Sendable {
    private var dataLines: [String] = []
    private var eventType: String?
    /// The `id` field of the block being read (nil when it has none).
    private var pendingId: String?
    private var atStartOfResponse = true
    /// The last COMMITTED event id of this stream, for `Last-Event-ID` on reconnect. Nil when none, or after
    /// an empty `id` reset it.
    public private(set) var lastEventId: String?

    public init() {}

    /// Starts a new HTTP response: discards a block the previous response left unfinished (its data, event
    /// type and pending id; joining it with the next response's data would corrupt both), and expects the
    /// response's one optional leading byte order mark. The committed ``lastEventId`` is kept.
    public mutating func beginResponse() {
        dataLines = []
        eventType = nil
        pendingId = nil
        atStartOfResponse = true
    }

    /// Feeds one line. Returns an event when the line is the blank line that dispatches one.
    public mutating func feed(line rawLine: String) -> SseEvent? {
        var rawLine = rawLine
        if atStartOfResponse {
            atStartOfResponse = false
            if rawLine.hasPrefix("\u{FEFF}") { rawLine.removeFirst() } // one BOM, at the start of the response only
        }
        let line = rawLine.hasSuffix("\r") ? String(rawLine.dropLast()) : rawLine
        if line.isEmpty { return dispatch() }
        if line.hasPrefix(":") { return nil } // comment / keep-alive
        let field: String
        var value: String
        if let colon = line.firstIndex(of: ":") {
            field = String(line[..<colon])
            value = String(line[line.index(after: colon)...])
            if value.hasPrefix(" ") { value.removeFirst() }
        } else {
            field = line
            value = ""
        }
        switch field {
        case "data": dataLines.append(value)
        case "event": eventType = value
        case "id":
            if !value.contains("\u{0}") { pendingId = value }
        default: break // retry and unknown fields are ignored
        }
        return nil
    }

    private mutating func dispatch() -> SseEvent? {
        defer { dataLines = []; eventType = nil; pendingId = nil }
        // The id is committed by the blank line, also for a block that carries no data; an empty id resets the cursor.
        if let pendingId { lastEventId = pendingId.isEmpty ? nil : pendingId }
        // An event with no data is not dispatched.
        guard !dataLines.isEmpty else { return nil }
        // An empty `id` is a cursor reset, not an identifier: it is never used to drop a later event.
        return SseEvent(id: pendingId.flatMap { $0.isEmpty ? nil : $0 }, event: eventType, data: dataLines.joined(separator: "\n"))
    }
}

/// Drops events whose `id` was already delivered, so a replay after a reconnect or resume
/// never hands the same completion to the wallet twice. Events without an id are never
/// treated as duplicates. Remembers only the most recent `capacity` ids.
public struct SseReplayFilter: Sendable {
    private var order: [String] = []
    private var seen: Set<String> = []
    private let capacity: Int

    public init(capacity: Int = 1024) {
        self.capacity = max(1, capacity)
    }

    /// True when `event` is new (deliver it); false for a replayed id.
    public mutating func admit(_ event: SseEvent) -> Bool {
        guard let id = event.id else { return true }
        if seen.contains(id) { return false }
        seen.insert(id)
        order.append(id)
        if order.count > capacity { seen.remove(order.removeFirst()) }
        return true
    }
}

/// Splits a byte stream into lines on LF, CRLF or a lone CR, KEEPING empty lines. SSE
/// dispatches an event on a blank line, and `URLSession.AsyncBytes.lines` omits empty
/// lines, so the transport splits the bytes itself.
public struct SseLineSplitter: Sendable {
    private var buffer: [UInt8] = []
    private var previousWasCR = false

    public init() {}

    /// Feeds one byte; returns a completed line (without its terminator) or nil.
    public mutating func feed(byte: UInt8) -> String? {
        if previousWasCR {
            previousWasCR = false
            if byte == 0x0A { return nil } // the LF of a CRLF: the line was already emitted at the CR
        }
        switch byte {
        case 0x0A:
            return takeLine()
        case 0x0D:
            previousWasCR = true
            return takeLine()
        default:
            buffer.append(byte)
            return nil
        }
    }

    private mutating func takeLine() -> String {
        defer { buffer.removeAll(keepingCapacity: true) }
        return String(decoding: buffer, as: UTF8.self)
    }
}
