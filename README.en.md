# Muxia / RenReader third-party source and relink materials

[简体中文](README.md)

This repository contains selected third-party/runtime sources, SDK-free adapters, changes, headers, notices and relink tools for RenReader 1.0.0 (Build 7). It is not the application's business-source repository and does not relicense the entire app under MIT or any other single license. No business Swift, novels, saves, account data or signing credentials are included.

Release-asset availability is recorded in `materials.json`, together with the file name, size, SHA-256 and version. Real download URLs are added after the asset is published.

The registered materials now match the hosted-download mechanism, and the App objects have passed relocated relink verification. Public Release availability and download-verification status are recorded in `materials.json`.

## Contents

`src/` preserves the selected runtime/Native/bridge changes and necessary producer scripts. Each runtime has its own `rr_host.py`; do not replace all variants with the canonical host. `headers/` contains public dependency headers; `licenses/` preserves original notices; `tools/` restores sources and replays App/Native links. `inventory.json` identifies the selected files and their origins. Historical QA/fixtures and machine-generated provenance remain outside this code selection.

The separate Release asset `Muxia-OpenSource-Materials.zip` contains the complete source archives, exact build inputs, App objects, static libraries, public framework providers and full inventory. Large archives and binaries are kept out of Git history. Cloning this repository alone does not provide every relink input.

The Release asset also includes verification source for the hosted-delivery mechanism in `HostedDelivery/Source/`: the two legal-page Swift files `ReleaseLegalManifest.swift` and `LegalNoticesView.swift`, plus the related generation/check scripts. No other App business Swift is included, and this selection does not expand the existing license scope.

Live2D is unsupported. No Live2D Core, Cubism Native Framework, models or Apple SDK bodies are supplied here. Compatibility names and SDK-free stubs do not enable that capability.

## Download, verify and restore

After an actual Release is published, download the asset listed in `materials.json`. Its URL is intentionally unset before publication. Verify before extracting:

```sh
python3 tools/verify_asset.py /downloads/Muxia-OpenSource-Materials.zip
python3 -m zipfile -e /downloads/Muxia-OpenSource-Materials.zip /fresh/materials
python3 tools/materialize_sources.py --source /fresh/materials/Sources --output /fresh/materialized-sources
```

The materializer checks and copies source files without executing them. Repeat `--prefix` to select logical subtrees. Its output must not exist, and its parent must already exist.

## Relink

Supply your own legally installed matching Xcode/iPhoneOS SDK. See the Chinese README for the complete App command; pass `--kit /fresh/materials/AppRelink/Kit`, `--manifest-sha 920bd2fbed5bb4237aceda1f45ce2eef0f3c5938fecc899016385ea77224aa9c`, and `--artifact-root /fresh/materials/NativeRelink/Providers` to `tools/replay_portable.py`.

For Native relinking, use `tools/replay_native.py --kit /fresh/materials/NativeRelink --sources /fresh/materials/Sources --providers /fresh/materials/NativeRelink/Providers`, plus the explicit SDK, clang and fresh-output parameters shown by `--help`. The source directory must contain the original `inventory.json` and `objects/`. Read the asset's component-specific build instructions and comparison limits. A successful link does not assert that all resulting binary bytes equal the supplied images.

To relink a component modified under its license, update input hashes/sizes and the portable-manifest SHA in your own kit, then use `--modified-components`. The Native tool supports `--replace LOGICAL_PATH=FILE`. Integrity pins identify inputs; they do not prohibit licensed modifications. Modified output is not represented as byte-identical to the baseline. Output is unsigned; use your own Apple credentials and installation settings.

## Licenses and limits

Each component retains its original copyright and license. No blanket MIT license is applied to the mixed repository. `APPLICATION-OBJECTS-PERMISSION.txt` preserves the existing permission to relink the supplied App objects with modified open-source components for your own use and to debug those changes; it does not publish the App's business Swift.

Source delivery is not an App Store approval, a license to imported stories, or a guarantee of compatibility with all works/devices. Users provide their own authorized works. No novels or work-download catalog are bundled.
