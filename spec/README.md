# Bridge capability vocabulary (Swift twin)

`bridge-capabilities.json` here is a copy of the source of truth in
[siros-sdk-kotlin/spec](https://github.com/sirosfoundation/siros-sdk-kotlin/tree/main/spec),
which also documents the descriptor and the rules for evolving it. CI fails
when this copy (or the generator) differs from that repository's `main`, or
when `Sources/SirosTransport/BridgeCapabilities.swift` is not what the
generator produces from it.

To take an upstream change:

```sh
curl -sSfL -o spec/bridge-capabilities.json \
  https://raw.githubusercontent.com/sirosfoundation/siros-sdk-kotlin/main/spec/bridge-capabilities.json
curl -sSfL -o tools/gen_bridge_capabilities.py \
  https://raw.githubusercontent.com/sirosfoundation/siros-sdk-kotlin/main/tools/gen_bridge_capabilities.py
python3 tools/gen_bridge_capabilities.py --spec spec/bridge-capabilities.json \
  --only swift --swift-out Sources/SirosTransport/BridgeCapabilities.swift
```

Building a descriptor:

```swift
let json = try BridgeDescriptorBuilder(platform: "ios", host: BridgeHost(name: bundleId, version: appVersion, sdkVersion: sdkVersion))
    .zk(ZkCapability(systems: zkSystems, circuitCache: true))
    .webauthn(WebauthnCapability(prf: true))
    .encode()   // the JSON the page receives
```
