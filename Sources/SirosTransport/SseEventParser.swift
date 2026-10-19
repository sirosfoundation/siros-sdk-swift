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
/// Tracks the stream's `lastEventId` as the specification says: it is set by an `id`
/// field that has no NUL, persists across events (an event without an `id` does not reset
/// it) and is what a reconnect sends as `Last-Event-ID`.
public struct SseEventParser: Sendable {
    private var dataLines: [String] = []
    private var eventType: String?
    private var pendingId: String?
    /// The last event id seen on this stream, for `Last-Event-ID` on reconnect.
    public private(set) var lastEventId: String?

    public init() {}

    /// Feeds one line. Returns an event when the line is the blank line that dispatches one.
    public mutating func feed(line rawLine: String) -> SseEvent? {
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
            if !value.contains("\u{0}") {
                pendingId = value
                lastEventId = value
            }
        default: break // retry and unknown fields are ignored
        }
        return nil
    }

    private mutating func dispatch() -> SseEvent? {
        defer { dataLines = []; eventType = nil; pendingId = nil }
        // An event with no data is not dispatched (an id alone only updates lastEventId).
        guard !dataLines.isEmpty else { return nil }
        return SseEvent(id: pendingId, event: eventType, data: dataLines.joined(separator: "\n"))
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
