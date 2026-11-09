#!/bin/bash
# Seeds SwiftPM's binary-target cache with curl, bypassing SwiftPM's own
# downloader (FoundationNetworking's libcurl crashes on some runner/network
# combinations — GitHub's ubuntu runners among them: Error 43, `try!` fatal —
# while curl on the same machine downloads the same zips fine).
#
# Writes .build/artifacts/<package>/<target>/<inner>.xcframework and a
# workspace-state.json whose artifact entries point at them, exactly the
# layout `swift package resolve` produces (schema version 7, SwiftPM 6.2).
# `swift build` then finds the artifacts present and never fetches.
#
# Usage: scripts/seed-swiftpm-artifacts.sh  (from the package root)
set -euo pipefail

fail() { echo "seed: $*" >&2; exit 1; }

command -v curl >/dev/null || fail "curl is required"
command -v python3 >/dev/null || fail "python3 is required"
[ -f Package.swift ] || fail "run from the package root"

ROOT=$(pwd)
ART="$ROOT/.build/artifacts"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$ART/repo" "$ART/extract/repo"

# The remote binary targets, parsed from Package.swift:
# target <tab> url <tab> sha256 <tab> inner-xcframework-name
python3 - > "$TMP/targets.tsv" <<'PYEOF'
import re
manifest = open('Package.swift').read()
for name, url, checksum in re.findall(
    r'\.binaryTarget\(\s*name:\s*"([^"]+)",\s*url:\s*"([^"]+)",\s*checksum:\s*"([0-9a-f]+)"',
    manifest,
):
    inner = url.rsplit('/', 1)[-1].replace('.xcframework.zip', '.xcframework')
    print(f"{name}\t{url}\t{checksum}\t{inner}")
PYEOF

[ -s "$TMP/targets.tsv" ] || fail "no binary targets parsed from Package.swift"

# Fetch and unzip each (skipping ones already seeded), recording the
# workspace-state entry.
: > "$TMP/entries.jsonl"
while IFS=$'\t' read -r target url checksum inner; do
  dest="$ART/repo/$target"
  if [ -d "$dest/$inner" ]; then
    echo "seed: $target already present"
  else
    echo "seed: fetching $inner"
    curl -fsSL -o "$TMP/a.zip" "$url" || fail "curl could not fetch $url"
    echo "$checksum  $TMP/a.zip" | sha256sum -c - >/dev/null \
      || fail "checksum mismatch for $inner"
    mkdir -p "$dest" "$ART/extract/repo/$target"
    unzip -oq "$TMP/a.zip" -d "$dest"
  fi
  python3 - "$target" "$url" "$checksum" "$dest/$inner" "$ROOT" >> "$TMP/entries.jsonl" <<'PYEOF'
import json, sys, os
target, url, checksum, path, root = sys.argv[1:6]
print(json.dumps({
    "kind": {"xcframework": {}},
    "packageRef": {
        "identity": os.path.basename(root),
        "kind": "root",
        "location": root,
        "name": os.path.basename(root),
    },
    "path": path,
    "source": {"checksum": checksum, "type": "remote", "url": url},
    "targetName": target,
}))
PYEOF
done < "$TMP/targets.tsv"

# The workspace state: the artifacts above, and nothing else. The
# source-control dependencies are SwiftPM's to fetch (git works fine on
# the runner — only the HTTP binary downloads crash).
python3 - "$ROOT" "$TMP/entries.jsonl" <<'PYEOF'
import json, sys
root, entries_path = sys.argv[1:3]
with open(entries_path) as f:
    entries = [json.loads(line) for line in f if line.strip()]
state = {
    "object": {
        "artifacts": entries,
        "dependencies": [],
        "prebuilts": [],
    },
    "version": 7,
}
with open(".build/workspace-state.json", "w") as f:
    json.dump(state, f, indent=2)
print(f"seed: {len(entries)} artifacts in the workspace state")
PYEOF