#!/usr/bin/env python3
"""Exact audit-only successor for Xcode's existing device bitcode-copy step.

The3d65 runtime/native qualification and every proof remain unchanged. Only
the source side of the final built-image comparator uses the already-qualified
packaged_source_identity function, which executes bitcode_strip -r on a copy.
"""
import argparse
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1] if HERE.name == "runtime" else HERE.parents[3]
CERTIFICATE = Path("RuntimeKit/Patches/legacy-packaging-20261110.json")
CERTIFICATE_SHA256 = "d09254dfccbeb6905a2f430dc9c0679895e190f1421709d205c388244152f998"
PARENT_GUARD = "Scripts/runtime/legacy_compatibility_guard.py"
PARENT_GUARD_SHA256 = "437e5e9fc68a4a1f405c425d04c60ebb6b61c081bf2ea6335824a1f1a2613325"
PARENT_CERTIFICATE_SHA256 = "3d6556fca6b9934127e44f25d3a1c91c674ce98bb6d71a28eef67c7fde46b2d6"
BEFORE = "parent.image_identity(root, original / name)"
AFTER = "parent.previous.old.packaged_source_identity(root, original / name, platform)"


def sha(path):
    path = Path(path).absolute()
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Only regular, unlinked audit inputs are accepted")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parent(root):
    path = root / PARENT_GUARD
    if sha(path) != PARENT_GUARD_SHA256:
        raise ValueError("The exact immutable3d65 parent guard changed")
    spec = importlib.util.spec_from_file_location("immutable_3d65_native_parent", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.CERTIFICATE_SHA256 != PARENT_CERTIFICATE_SHA256:
        raise ValueError("The3d65 parent qualification changed")
    return module


def derive(module):
    source = inspect.getsource(module.check_built_app)
    if source.count(BEFORE) != 1 or AFTER in source:
        raise ValueError("Unexpected parent built-image comparator")
    updated = source.replace(BEFORE, AFTER)
    namespace = dict(module.__dict__)
    # This is only the exact SHA-pinned parent function, with one named call
    # replaced. Its verify() remains the original full3d65 verifier.
    exec(compile(updated, str(module.__file__) + "::device-packaging", "exec", dont_inherit=True, optimize=0), namespace)
    return namespace["check_built_app"], updated


def normalized(path):
    source = Path(path).read_bytes()
    pattern = rb'^CERTIFICATE_SHA256 = [^\n]+$'
    if len(re.findall(pattern, source, re.M)) != 1:
        raise ValueError("Unexpected audit certificate declaration")
    return re.sub(pattern, b"CERTIFICATE_SHA256 = None", source, flags=re.M)


def verify_certificate(root, value):
    module = parent(root)
    if (type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1 or value.get("kind") != "exactDevicePackagingAudit" or
            value.get("passed") is not True or value.get("runtimeOrNativeChanged") is not False or value.get("appSwiftChanged") is not False or
            value.get("newRuntimeExecutionQualified") is not False or value.get("oldOSExecutionQualified") is not False or
            value.get("parentGuardSHA256") != PARENT_GUARD_SHA256 or value.get("parentCertificateSHA256") != PARENT_CERTIFICATE_SHA256 or
            value.get("before") != BEFORE or value.get("after") != AFTER or
            value.get("wrapperTemplateSHA256") != hashlib.sha256(normalized(__file__)).hexdigest()):
        raise ValueError("The exact audit-only scope changed")
    _, source = derive(module)
    if hashlib.sha256(source.encode()).hexdigest() != value.get("derivedCheckSHA256"):
        raise ValueError("The built-App comparator exceeds the one named packaging call")
    old = module.load_parent(root)
    for ref in value["evidence"].values():
        old.previous.ref(root, ref)
    inventory = root / value["evidence"]["1"]["path"]
    if sha(inventory) != value["actualProductInventorySHA256"] or old.filemap(old.previous.safe_root(root / value["actualReleaseProduct"])) != json.loads(inventory.read_bytes()):
        raise ValueError("The preserved actual failed Release product changed")
    helper = old.previous.old.packaged_source_identity
    if hashlib.sha256(inspect.getsource(helper).encode()).hexdigest() != value.get("existingPackagingHelperSHA256"):
        raise ValueError("The previous exact packaging transform changed")
    tool = Path(subprocess.check_output(["xcrun", "--find", "bitcode_strip"], text=True).strip()).resolve(strict=True)
    if str(tool) != value["bitcodeTool"]["path"] or sha(tool) != value["bitcodeTool"]["sha256"]:
        raise ValueError("The actual Xcode bitcode-copy tool changed")
    return module


def certificate(root):
    if CERTIFICATE_SHA256 is None or sha(root / CERTIFICATE) != CERTIFICATE_SHA256:
        raise ValueError("The exact device-packaging audit is not accepted or changed")
    value = json.loads((root / CERTIFICATE).read_bytes())
    return verify_certificate(root, value), value


def verify(root, **kwargs):
    module, _ = certificate(root)
    return module.verify(root, **kwargs)


def image_identity(root, path):
    # The general inspection API stays raw: no implicit relaxation of probes,
    # source qualification, evidence verification or arbitrary binary checks.
    return parent(root).image_identity(root, path)


def check(root, contract):
    module, _ = certificate(root)
    return module.check(root, contract)


def check_built_app(root, contract, app, platform, configuration):
    module, _ = certificate(root)
    function, _ = derive(module)
    return function(root, contract, app, platform, configuration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--built-app", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--configuration")
    args = parser.parse_args()
    contract = json.loads(args.contract.read_bytes())
    if args.built_app:
        check_built_app(args.root, contract, args.built_app, args.platform, args.configuration)
    else:
        check(args.root, contract)
    print(parent(args.root).load_parent(args.root).previous.MARKER)
