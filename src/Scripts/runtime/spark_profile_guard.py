"""Independent acceptance contract for added exact patch versions.

Existing eleven-profile qualifications are still checked by their original
guards. This contract never grants overlays, translation updates or Live2D.
"""
import json
from pathlib import Path

VERSIONS = {"7.8.4", "8.3.4", "8.5.0", "8.5.2"}
CERTIFICATE = Path("RuntimeKit/Patches/spark-profiles-20261104.json")
CERTIFICATE_SHA256 = "a1c07ea106e83db2d07447eab5220434d930a8919f078455d64956c0db1dfdbc"


def verify(root, entries, *, built_app=None, platform=None):
    if any(entries.get(version, {}).get("scriptTranslationPagingSchemaVersion") == 1 for version in VERSIONS):
        if __package__:
            from .advanced_translation17_update import verify_added_profiles
        else:
            from advanced_translation17_update import verify_added_profiles
        return verify_added_profiles(root, entries, VERSIONS, built_app=built_app, platform=platform)
    if __package__:
        from .overlay_capability_guard import digest, tree_digest, packaged_source_identity, image_identity, framework_slice
    else:
        from overlay_capability_guard import digest, tree_digest, packaged_source_identity, image_identity, framework_slice
    path = root / CERTIFICATE
    if digest(path) != CERTIFICATE_SHA256:
        raise ValueError("New patch-version certificate is missing or changed")
    certificate = json.loads(path.read_bytes())
    if certificate.get("schemaVersion") != 1 or certificate.get("status") != "simulatorWarmColdPassed" or set(certificate.get("runtimes", {})) != VERSIONS:
        raise ValueError("New patch versions lack warm/cold acceptance")
    evidence = certificate.get("evidence", {})
    if set(evidence) != {"warm", "cold"}:
        raise ValueError("New patch-version evidence is incomplete")
    processes = []
    for phase, item in evidence.items():
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or digest(root / relative) != item["sha256"]:
            raise ValueError("New patch-version execution evidence changed")
        rows = [json.loads(line) for line in (root / relative).read_text().splitlines() if line]
        ready = [r for r in rows if r.get("type") == "ready"]
        passed = [r for r in rows if r.get("type") == "smokePassed"]
        if len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 5 or len(ready) != 5:
            raise ValueError("New patch-version sessions did not pass")
        if {r.get("runtimeVersion") for r in ready} != VERSIONS or any(r.get("capabilities", {}).get("live2D") is not False for r in ready):
            raise ValueError("New patch versions advertised an unqualified capability")
        process = passed[0].get("processID")
        if type(process) is not int or process <= 0:
            raise ValueError("New patch-version process identity missing")
        processes.append(process)
        if any(r.get("type") in {"error", "gameError", "smokeFailed", "saveFailed", "commandRejected"} for r in rows):
            raise ValueError("New patch-version run contains a failure")
    if len(set(processes)) != 2:
        raise ValueError("New patch-version cold validation reused its warm process")
    for version in VERSIONS:
        name = "RenPy" + version.replace(".", "") + ".bundle"
        bundle = root / "RuntimeKit/Artifacts" / name
        profile = json.loads((bundle / "runtime-profile.json").read_bytes())
        expected = certificate["runtimes"][version]
        if digest(bundle / "runtime-profile.json") != expected["profileSHA256"] or tree_digest(bundle) != expected["bundle"]:
            raise ValueError("New patch-version resources changed: " + version)
        if profile.get("runtimeID") != version or profile.get("live2D", {}).get("available") is not False or any(k in profile for k in ("engineOverlaySchemaVersion", "advancedTranslationSchemaVersion")):
            raise ValueError("New patch version has an unqualified capability flag")
        if any(entries[version].get(k) != v for k, v in profile.items()):
            raise ValueError("New patch-version catalog differs from its profile")
        framework = "RRRuntime" + version.replace(".", "")
        for target in ("iphoneos", "iphonesimulator"):
            binary = framework_slice(root, framework, target) / framework
            if packaged_source_identity(root, binary, target) != expected["native"][target]:
                raise ValueError("New patch-version native image changed")
        if built_app is not None:
            if tree_digest(built_app / name) != expected["bundle"] or image_identity(root, built_app / "Frameworks" / (framework + ".framework") / framework) != expected["native"][platform]:
                raise ValueError("Built patch version differs from its accepted stage")
