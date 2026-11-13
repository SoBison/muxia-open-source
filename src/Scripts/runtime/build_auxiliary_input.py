#!/usr/bin/env python3
"""Build/test an isolated SDL auxiliary-input candidate; never publish Artifacts.

Uses the already verified official SDL source and cached 8.5.3 iOS SDK. Native
input helpers intentionally use pinned SDL2.0.20 internals, not a public SDL ABI.
The macOS dummy probe checks state/queue semantics, not UIKit IME or hardware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import build_runtime
from build_sdl_gate import compile_gate
from prepare_sdl_gate import prepare

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "RuntimeKit"
SOURCE = KIT / ".cache/sdl-gate/SDL-release-2.0.20"
OUTPUT = KIT / "Validation/AuxiliaryInputCandidate"


def run(args, log, cwd=ROOT):
    with log.open("w") as file:
        subprocess.run(list(map(str, args)), cwd=cwd, stdout=file, stderr=subprocess.STDOUT, check=True)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def production_hashes():
    artifacts = KIT / "Artifacts"
    return {str(p.relative_to(artifacts)): sha(p) for name in ["RRPlatform.xcframework", "MetalANGLE.xcframework"]
            for p in (artifacts / name).rglob("*") if p.is_file() and p.name in ["RRPlatform", "MetalANGLE"]}


def offline_probes(output):
    patched, build = output / "patched", output / "macos-build"
    prepare(SOURCE, patched)
    build.mkdir(parents=True, exist_ok=True)
    if not (build / "Makefile").exists():
        run([patched / "configure", "--disable-shared", "--enable-static", "--disable-audio", "--disable-render",
             "--disable-haptic", "--disable-joystick", "--disable-power", "--disable-filesystem", "--disable-sensor",
             "--disable-hidapi", "--enable-video-cocoa", "--disable-video-opengl", "--disable-video-opengles", "--disable-video-metal",
             "CFLAGS=-O1 -g -I" + str(KIT / "Native")], build / "configure.log", build)
    # Upstream 2.0.20 makes old C declaration style a hard error, including in
    # its unmodified modern macOS HID backend. Keep warnings, not that policy.
    flags = re.search(r"^EXTRA_CFLAGS = (.*)$", (build / "Makefile").read_text(), re.M).group(1)
    flags = flags.replace("-Werror=declaration-after-statement", "").replace("-Wdeclaration-after-statement", "")
    run(["make", "-j4", "EXTRA_CFLAGS=" + flags], build / "build.log", build)
    common = ["xcrun", "clang", "-std=gnu11", "-O1", "-g", "-include", patched / "src/SDL_internal.h",
              "-I", build / "include", "-I", patched / "include", "-I", patched / "src", "-I", KIT / "Native",
              KIT / "Native/RRInputGate.c", KIT / "Native/RRAuxiliaryInput.c"]
    libraries = [build / "build/.libs/libSDL2.a", "-framework", "Foundation", "-framework", "Cocoa", "-framework", "IOKit",
                 "-framework", "CoreFoundation", "-framework", "CoreVideo", "-framework", "QuartzCore", "-framework", "Carbon", "-liconv", "-lm"]
    binary = output / "auxiliary-input-probe"
    run(common + ["-DRR_AUXILIARY_STANDALONE", KIT / "Tests/AuxiliaryInputProbe.m"] + libraries + ["-o", binary], output / "probe-build.log")
    with (output / "native-probe.json").open("w") as result, (output / "probe-stderr.log").open("w") as log:
        subprocess.run([binary], stdout=result, stderr=log, check=True)
    baseline = output / "baseline-main.m"
    baseline.write_text('''#import <Foundation/Foundation.h>
#include "RRInputGate.h"
#include "RRAuxiliaryInput.h"
extern char *RRPlatformRunInputProbe(void);
void RRPlatformEnd(void) { RRInputGateEnd(); RRAuxiliaryReset(); }
int main(void) { @autoreleasepool { char *json=RRPlatformRunInputProbe(); puts(json);
NSString *s=[NSString stringWithUTF8String:json]; free(json);
NSDictionary *v=[NSJSONSerialization JSONObjectWithData:[s dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
return [v[@"passed"] boolValue] ? 0 : 1; } }
''')
    baseline_binary = output / "keyboard-baseline-probe"
    run(common + [KIT / "Tests/InputGateProbe.m", baseline] + libraries + ["-o", baseline_binary], output / "baseline-build.log")
    with (output / "keyboard-baseline.json").open("w") as result, (output / "baseline-stderr.log").open("w") as log:
        subprocess.run([baseline_binary], stdout=result, stderr=log, check=True)
    return [json.loads((output / name).read_text()) for name in ["native-probe.json", "keyboard-baseline.json"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mac-only", action="store_true", help="Run CPU/dummy-window probes without building iOS slices")
    args = parser.parse_args()
    if not (SOURCE / "configure").is_file():
        raise RuntimeError("The verified SDL2.0.20 cache is required; this candidate does not download or accept SDK terms")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    before = production_hashes()
    probes = offline_probes(OUTPUT)
    frameworks = []
    if not args.mac_only:
        sdk = Path(json.loads((KIT / ".cache/official/8.5.3/paths.json").read_text())["sdk"])
        if not (sdk / "renios/prototype/prebuilt/release/libSDL2.a").is_file() or not (KIT / "Artifacts/MetalANGLE.xcframework").is_dir():
            raise RuntimeError("Cached SDK and existing ANGLE are required; no production packaging is performed")
        build_runtime.compile_gate = lambda archive, platform: compile_gate(archive, platform, OUTPUT / "ios-input-build")
        expected = {"_RRPlatformAuxiliary" + name for name in ["Begin", "SetGeometry", "Submit", "Cancel", "End", "StateJSON"]}
        for label, probe in [("Instrumented", KIT / "Tests/AuxiliaryInputProbe.m"), ("Clean", None)]:
            build_runtime.build_platform(sdk, destination=OUTPUT / label, probe_source=probe)
            for platform in ["iphoneos", "iphonesimulator"]:
                binary = OUTPUT / label / platform / "RRPlatform.framework/RRPlatform"
                symbols = set(subprocess.check_output(["nm", "-gU", binary], text=True).split())
                if not expected <= symbols:
                    raise RuntimeError("Candidate is missing its complete auxiliary ABI: " + platform)
                if ("_RRPlatformRunAuxiliaryInputProbe" in symbols) != (probe is not None):
                    raise RuntimeError("Incorrect test-probe inclusion: " + label + "/" + platform)
                object_root = OUTPUT / "ios-input-build" / platform
                objects = {name: sha(object_root / (name + ".o")) for name in ["SDL_keyboard", "SDL_events", "SDL_mouse", "SDL_video", "RRInputGate", "RRAuxiliaryInput"]}
                frameworks.append({"variant": label, "platform": platform, "sha256": sha(binary), "exportsVerified": sorted(expected), "testProbeIncluded": probe is not None, "inputObjectSHA256": objects})
        for platform in ["iphoneos", "iphonesimulator"]:
            paired = [entry["inputObjectSHA256"] for entry in frameworks if entry["platform"] == platform]
            if paired[0] != paired[1]:
                raise RuntimeError("Instrumented/Clean input objects differ: " + platform)
    after = production_hashes()
    if before != after:
        raise RuntimeError("Production platform/ANGLE changed during the candidate build; do not attribute this run to an isolated build")
    inputs = [KIT / "Native" / name for name in ["RRPlatform.m", "RRInputGate.c", "RRInputGate.h", "RRAuxiliaryInput.c", "RRAuxiliaryInput.h"]]
    inputs += [KIT / "Tests/AuxiliaryInputProbe.m", ROOT / "Scripts/runtime/prepare_sdl_gate.py", ROOT / "Scripts/runtime/build_sdl_gate.py", Path(__file__)]
    result = {"passed": all(p["passed"] for p in probes), "scope": "offline native state/queue; UIKit IME and hardware not tested",
              "SDLRelease": "2.0.20", "nativeChecks": len(probes[0]["checks"]), "baselineChecks": len(probes[1]["checks"]),
              "sourceSHA256": {str(p.relative_to(ROOT)): sha(p) for p in inputs}, "frameworks": frameworks,
              "productionUnchanged": True, "productionHashes": before}
    (OUTPUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "nativeChecks": result["nativeChecks"], "baselineChecks": result["baselineChecks"], "frameworks": len(frameworks), "result": str(OUTPUT / "result.json")}))


if __name__ == "__main__":
    main()
