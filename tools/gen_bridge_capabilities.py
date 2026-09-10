#!/usr/bin/env python3
"""Generate the bridge capability vocabulary for Kotlin, Swift and TypeScript.

Source of truth: spec/bridge-capabilities.json. The three generated files
carry the same ids, parameter shapes and descriptor structure, so the
wrapper apps (Kotlin/Swift, advertising) and the frontend's bridge contract
package (TypeScript, consuming) cannot drift from each other.

    tools/gen_bridge_capabilities.py                # write all outputs
    tools/gen_bridge_capabilities.py --check        # exit 1 if any output is stale
    tools/gen_bridge_capabilities.py --swift-out PATH  # (siros-sdk-swift) only Swift

Deterministic: same input, byte-identical output.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec" / "bridge-capabilities.json"
KOTLIN_OUT = ROOT / "sdk/transport/src/main/kotlin/org/siros/sdk/transport/bridge/BridgeCapabilities.kt"
TS_OUT = ROOT / "spec" / "generated" / "bridge-capabilities.ts"

HEADER = "GENERATED from spec/bridge-capabilities.json by tools/gen_bridge_capabilities.py - do not edit."

TYPES = {
    "string": ("String", "String", "string"),
    "string[]": ("List<String>", "[String]", "string[]"),
    "boolean": ("Boolean", "Bool", "boolean"),
    "integer": ("Int", "Int", "number"),
}


def pascal(ident: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[._]", ident))


def camel(ident: str) -> str:
    p = pascal(ident)
    return p[:1].lower() + p[1:]


def const(ident: str) -> str:
    return re.sub(r"[.]", "_", ident).upper()


def wrap(text: str, width: int, prefix: str) -> str:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return "\n".join(prefix + line for line in lines)


# --- Kotlin -----------------------------------------------------------------

def gen_kotlin(spec: dict) -> str:
    caps = spec["capabilities"]
    out = [f"// {HEADER}", "// Copyright 2026 SIROS Foundation. BSD 2-Clause License.", "", "package org.siros.sdk.transport.bridge", "",
           "import kotlinx.serialization.SerialName", "import kotlinx.serialization.Serializable", "import kotlinx.serialization.json.JsonObject", ""]
    out.append("/** Versions of the vocabulary and of the descriptor schema this SDK was generated from. */")
    out.append("public object BridgeVocabulary {")
    out.append(f"    public const val VERSION: Int = {spec['vocabulary_version']}")
    out.append("    public const val DESCRIPTOR_VERSION: Int = 1")
    out.append("}")
    out.append("")
    out.append("/** Capability ids. Stable once published; retired ids stay here with a [DEPRECATED] note. */")
    out.append("public object BridgeCapabilityId {")
    for c in caps:
        out.append(f"    /** {c['description']} */")
        out.append(f"    public const val {const(c['id'])}: String = \"{c['id']}\"")
    out.append("")
    out.append("    public val ALL: List<String> = listOf(" + ", ".join(const(c["id"]) for c in caps) + ")")
    dep = [c for c in caps if c.get("deprecated")]
    out.append("    /** Deprecated ids and why. */")
    out.append("    public val DEPRECATED: Map<String, String> = mapOf(")
    for c in dep:
        out.append(f"        {const(c['id'])} to \"{c['deprecated']}\",")
    out.append("    )")
    out.append("}")
    out.append("")
    for c in caps:
        name = f"{pascal(c['id'])}Capability"
        out.append("/**")
        out.append(wrap(c["description"], 76, " * "))
        out.append(f" *")
        out.append(f" * Stage: {c['stage']}." + (f" DEPRECATED: {c['deprecated']}" if c.get("deprecated") else ""))
        out.append(" */")
        out.append("@Serializable")
        if not c["params"]:
            out.append(f"public class {name}")
            out.append("")
            continue
        out.append(f"public data class {name}(")
        for pname, p in c["params"].items():
            kt = TYPES[p["type"]][0]
            ann = f"@SerialName(\"{pname}\") " if camel(pname) != pname else ""
            out.append(f"    /** {p['description']} */")
            out.append(f"    {ann}val {camel(pname)}: {kt}? = null,")
        out.append(")")
        out.append("")
    out.append("/** The host application advertising the bridge. */")
    out.append("@Serializable")
    out.append("public data class BridgeHost(")
    for fname, f in spec["descriptor"]["fields"]["host"]["fields"].items():
        ann = f"@SerialName(\"{fname}\") " if camel(fname) != fname else ""
        out.append(f"    /** {f['description']} */")
        out.append(f"    {ann}val {camel(fname)}: {TYPES[f['type']][0]},")
    out.append(")")
    out.append("")
    out.append("@Serializable")
    out.append("public data class BridgeMeta(val version: Int = BridgeVocabulary.DESCRIPTOR_VERSION)")
    out.append("")
    out.append("/**")
    out.append(wrap(spec["descriptor"]["$comment"], 76, " * "))
    out.append(" *")
    out.append(" * Build one with [BridgeDescriptorBuilder]; the page consumes the JSON form.")
    out.append(" */")
    out.append("@Serializable")
    out.append("public data class BridgeDescriptor(")
    out.append("    val bridge: BridgeMeta = BridgeMeta(),")
    out.append("    val vocabulary: Int = BridgeVocabulary.VERSION,")
    out.append("    /** `android` or `ios`. */")
    out.append("    val platform: String,")
    out.append("    val host: BridgeHost,")
    out.append("    /** Capability id to its parameters. Present means offered. */")
    out.append("    val capabilities: JsonObject,")
    out.append(")")
    out.append("")
    out.append("/** Typed, one method per capability; the descriptor's capability map is built from what was offered. */")
    out.append("public class BridgeDescriptorBuilder(private val platform: String, private val host: BridgeHost) {")
    out.append("    private val offered = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()")
    out.append("    // Defaults on (bridge/vocabulary versions must always appear), nulls off (unset parameters are omitted).")
    out.append("    private val json = kotlinx.serialization.json.Json { encodeDefaults = true; explicitNulls = false }")
    out.append("")
    for c in caps:
        name = f"{pascal(c['id'])}Capability"
        m = camel(c["id"])
        out.append(f"    public fun {m}(params: {name} = {name}()): BridgeDescriptorBuilder = apply {{")
        out.append(f"        offered[BridgeCapabilityId.{const(c['id'])}] = json.encodeToJsonElement({name}.serializer(), params)")
        out.append("    }")
    out.append("")
    out.append("    public fun build(): BridgeDescriptor = BridgeDescriptor(platform = platform, host = host, capabilities = JsonObject(offered))")
    out.append("")
    out.append("    /** The JSON the page receives. */")
    out.append("    public fun encode(): String = json.encodeToString(BridgeDescriptor.serializer(), build())")
    out.append("}")
    out.append("")
    return "\n".join(out)


# --- Swift ------------------------------------------------------------------

def gen_swift(spec: dict) -> str:
    caps = spec["capabilities"]
    out = [f"// {HEADER}", "// Copyright 2026 SIROS Foundation. BSD 2-Clause License.", "", "import Foundation", ""]
    out.append("/// Versions of the vocabulary and of the descriptor schema this SDK was generated from.")
    out.append("public enum BridgeVocabulary {")
    out.append(f"    public static let version = {spec['vocabulary_version']}")
    out.append("    public static let descriptorVersion = 1")
    out.append("}")
    out.append("")
    out.append("/// Capability ids. Stable once published; retired ids stay here with a `deprecated` note.")
    out.append("public enum BridgeCapabilityId {")
    for c in caps:
        out.append(f"    /// {c['description']}")
        out.append(f"    public static let {camel(c['id'])} = \"{c['id']}\"")
    out.append("")
    out.append("    public static let all: [String] = [" + ", ".join(camel(c["id"]) for c in caps) + "]")
    out.append("    /// Deprecated ids and why.")
    dep = [c for c in caps if c.get("deprecated")]
    if dep:
        out.append("    public static let deprecated: [String: String] = [")
        for c in dep:
            out.append(f"        {camel(c['id'])}: \"{c['deprecated']}\",")
        out.append("    ]")
    else:
        out.append("    public static let deprecated: [String: String] = [:]")
    out.append("}")
    out.append("")
    out.append("/// A capability's parameters, encodable into the descriptor's capability map.")
    out.append("public protocol BridgeCapabilityParams: Codable, Sendable {")
    out.append("    static var capabilityId: String { get }")
    out.append("}")
    out.append("")
    for c in caps:
        name = f"{pascal(c['id'])}Capability"
        out.append("/// " + c["description"])
        out.append("///")
        out.append(f"/// Stage: {c['stage']}." + (f" DEPRECATED: {c['deprecated']}" if c.get("deprecated") else ""))
        out.append(f"public struct {name}: BridgeCapabilityParams {{")
        out.append(f"    public static let capabilityId = BridgeCapabilityId.{camel(c['id'])}")
        for pname, p in c["params"].items():
            out.append(f"    /// {p['description']}")
            out.append(f"    public var {camel(pname)}: {TYPES[p['type']][1]}?")
        if c["params"]:
            args = ", ".join(f"{camel(pn)}: {TYPES[p['type']][1]}? = nil" for pn, p in c["params"].items())
            out.append(f"    public init({args}) {{")
            for pname in c["params"]:
                out.append(f"        self.{camel(pname)} = {camel(pname)}")
            out.append("    }")
            if any(camel(pn) != pn for pn in c["params"]):
                out.append("    enum CodingKeys: String, CodingKey {")
                for pname in c["params"]:
                    out.append(f"        case {camel(pname)}" + (f" = \"{pname}\"" if camel(pname) != pname else ""))
                out.append("    }")
        else:
            out.append("    public init() {}")
        out.append("}")
        out.append("")
    out.append("/// The host application advertising the bridge.")
    out.append("public struct BridgeHost: Codable, Sendable {")
    hf = spec["descriptor"]["fields"]["host"]["fields"]
    for fname, f in hf.items():
        out.append(f"    /// {f['description']}")
        out.append(f"    public var {camel(fname)}: {TYPES[f['type']][1]}")
    out.append("    public init(" + ", ".join(f"{camel(fn)}: {TYPES[f['type']][1]}" for fn, f in hf.items()) + ") {")
    for fname in hf:
        out.append(f"        self.{camel(fname)} = {camel(fname)}")
    out.append("    }")
    out.append("    enum CodingKeys: String, CodingKey {")
    for fname in hf:
        out.append(f"        case {camel(fname)}" + (f" = \"{fname}\"" if camel(fname) != fname else ""))
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("public struct BridgeMeta: Codable, Sendable {")
    out.append("    public var version: Int = BridgeVocabulary.descriptorVersion")
    out.append("    public init(version: Int = BridgeVocabulary.descriptorVersion) { self.version = version }")
    out.append("}")
    out.append("")
    out.append("/// " + spec["descriptor"]["$comment"])
    out.append("///")
    out.append("/// Build one with `BridgeDescriptorBuilder`; the page consumes the JSON form.")
    out.append("public struct BridgeDescriptor: Codable, Sendable {")
    out.append("    public var bridge: BridgeMeta = BridgeMeta()")
    out.append("    public var vocabulary: Int = BridgeVocabulary.version")
    out.append("    /// `android` or `ios`.")
    out.append("    public var platform: String")
    out.append("    public var host: BridgeHost")
    out.append("    /// Capability id to its parameters. Present means offered.")
    out.append("    public var capabilities: [String: AnyCodable]")
    out.append("    public init(platform: String, host: BridgeHost, capabilities: [String: AnyCodable]) {")
    out.append("        self.platform = platform")
    out.append("        self.host = host")
    out.append("        self.capabilities = capabilities")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("/// Typed, one method per capability; the descriptor's capability map is built from what was offered.")
    out.append("public final class BridgeDescriptorBuilder {")
    out.append("    private let platform: String")
    out.append("    private let host: BridgeHost")
    out.append("    private var offered: [String: AnyCodable] = [:]")
    out.append("")
    out.append("    public init(platform: String, host: BridgeHost) {")
    out.append("        self.platform = platform")
    out.append("        self.host = host")
    out.append("    }")
    out.append("")
    out.append("    private func offer<P: BridgeCapabilityParams>(_ params: P) throws {")
    out.append("        // Re-decode through the codec's own AnyCodable so the map holds")
    out.append("        // plain JSON values whatever the parameter struct's shape.")
    out.append("        let data = try JSONEncoder().encode(params)")
    out.append("        offered[P.capabilityId] = try JSONDecoder().decode(AnyCodable.self, from: data)")
    out.append("    }")
    out.append("")
    for c in caps:
        name = f"{pascal(c['id'])}Capability"
        out.append("    @discardableResult")
        out.append(f"    public func {camel(c['id'])}(_ params: {name} = {name}()) throws -> BridgeDescriptorBuilder {{")
        out.append("        try offer(params)")
        out.append("        return self")
        out.append("    }")
    out.append("")
    out.append("    public func build() -> BridgeDescriptor {")
    out.append("        BridgeDescriptor(platform: platform, host: host, capabilities: offered)")
    out.append("    }")
    out.append("")
    out.append("    /// The JSON the page receives.")
    out.append("    public func encode() throws -> String {")
    out.append("        let encoder = JSONEncoder()")
    out.append("        encoder.outputFormatting = [.sortedKeys]")
    out.append("        return String(decoding: try encoder.encode(build()), as: UTF8.self)")
    out.append("    }")
    out.append("}")
    out.append("")
    return "\n".join(out)


# --- TypeScript -------------------------------------------------------------

def gen_ts(spec: dict) -> str:
    caps = spec["capabilities"]
    out = [f"// {HEADER}", "// Copyright 2026 SIROS Foundation. BSD 2-Clause License.", ""]
    out.append("/** Version of the vocabulary these types were generated from. */")
    out.append(f"export const BRIDGE_VOCABULARY_VERSION = {spec['vocabulary_version']} as const;")
    out.append("/** Version of the descriptor schema. */")
    out.append("export const BRIDGE_DESCRIPTOR_VERSION = 1 as const;")
    out.append("")
    out.append("/** Capability ids. Stable once published; retired ids stay here and appear in DEPRECATED_CAPABILITIES. */")
    out.append("export const BRIDGE_CAPABILITY_IDS = [")
    for c in caps:
        out.append(f"  '{c['id']}',")
    out.append("] as const;")
    out.append("export type BridgeCapabilityId = (typeof BRIDGE_CAPABILITY_IDS)[number];")
    out.append("")
    out.append("/** Deprecated ids and why. */")
    out.append("export const DEPRECATED_CAPABILITIES: Partial<Record<BridgeCapabilityId, string>> = {")
    for c in caps:
        if c.get("deprecated"):
            out.append(f"  '{c['id']}': {json.dumps(c['deprecated'])},")
    out.append("};")
    out.append("")
    for c in caps:
        name = f"{pascal(c['id'])}Capability"
        out.append("/**")
        out.append(wrap(c["description"], 76, " * "))
        out.append(" *")
        out.append(f" * Stage: {c['stage']}." + (f" DEPRECATED: {c['deprecated']}" if c.get("deprecated") else ""))
        out.append(" */")
        out.append(f"export interface {name} {{")
        for pname, p in c["params"].items():
            out.append(f"  /** {p['description']} */")
            out.append(f"  {pname}?: {TYPES[p['type']][2]};")
        out.append("}")
        out.append("")
    out.append("/** Capability id to its parameters. Present means offered. */")
    out.append("export interface BridgeCapabilities {")
    for c in caps:
        key = c["id"] if re.fullmatch(r"[A-Za-z_]\w*", c["id"]) else f"'{c['id']}'"
        out.append(f"  {key}?: {pascal(c['id'])}Capability;")
    out.append("}")
    out.append("")
    out.append("/** The host application advertising the bridge. */")
    out.append("export interface BridgeHost {")
    for fname, f in spec["descriptor"]["fields"]["host"]["fields"].items():
        out.append(f"  /** {f['description']} */")
        out.append(f"  {fname}: {TYPES[f['type']][2]};")
    out.append("}")
    out.append("")
    out.append("/**")
    out.append(wrap(spec["descriptor"]["$comment"], 76, " * "))
    out.append(" */")
    out.append("export interface BridgeDescriptor {")
    out.append("  bridge: { version: number };")
    out.append("  /** The vocabulary_version this host was built against. */")
    out.append("  vocabulary: number;")
    out.append("  platform: 'android' | 'ios';")
    out.append("  host: BridgeHost;")
    out.append("  capabilities: BridgeCapabilities;")
    out.append("}")
    out.append("")
    out.append("/** True when the descriptor offers `id`. Unknown ids are simply not offered. */")
    out.append("export function offers<K extends BridgeCapabilityId>(descriptor: BridgeDescriptor, id: K): descriptor is BridgeDescriptor & { capabilities: Required<Pick<BridgeCapabilities, K>> } {")
    out.append("  return Object.prototype.hasOwnProperty.call(descriptor.capabilities, id);")
    out.append("}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if any output differs from what would be generated")
    ap.add_argument("--spec", type=Path, default=SPEC)
    ap.add_argument("--kotlin-out", type=Path, default=KOTLIN_OUT)
    ap.add_argument("--ts-out", type=Path, default=TS_OUT)
    ap.add_argument("--swift-out", type=Path, default=None, help="write Swift here (siros-sdk-swift checkout)")
    ap.add_argument("--only", choices=["kotlin", "swift", "ts"], nargs="*", default=None)
    args = ap.parse_args()

    spec = json.loads(args.spec.read_text())
    outputs: dict[Path, str] = {}
    want = set(args.only or ["kotlin", "swift", "ts"])
    if "kotlin" in want and args.kotlin_out:
        outputs[args.kotlin_out] = gen_kotlin(spec)
    if "ts" in want and args.ts_out:
        outputs[args.ts_out] = gen_ts(spec)
    if "swift" in want and args.swift_out:
        outputs[args.swift_out] = gen_swift(spec)

    stale = []
    for path, content in outputs.items():
        current = path.read_text() if path.exists() else None
        if current != content:
            stale.append(path)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                print(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    if args.check and stale:
        for p in stale:
            print(f"STALE: {p} - run tools/gen_bridge_capabilities.py", file=sys.stderr)
        return 1
    if args.check:
        print("bridge capability outputs are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
