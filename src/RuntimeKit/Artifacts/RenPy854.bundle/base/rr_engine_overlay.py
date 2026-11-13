"""Select one verified Python engine tree before this image imports Ren'Py.

The native host verifies the complete materialized tree. These checks bind the
frozen launch identity and compare host-controlled sources with stock bytes.
They do not sandbox Python supplied by an explicitly trusted author or user.
"""
from __future__ import absolute_import

import hashlib
import json
import os
import stat
import sys

try:
    _texts = (str, unicode)
except NameError:
    _texts = (str,)

_pinned = None
_protected = {
    "renpy": "renpy/__init__.py",
    "renpy.bootstrap": "renpy/bootstrap.py",
    "renpy.main": "renpy/main.py",
    "renpy.script": "renpy/script.py",
    "renpy.display.core": "renpy/display/core.py",
    "renpy.gl2.live2d": "renpy/gl2/live2d.py",
}


class EngineOverlayFailure(BaseException):
    """A rejected engine identity must not become a recoverable game error."""


def _fail(message):
    raise EngineOverlayFailure(message)


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _digest(value):
    return type(value) in _texts and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _directory(path):
    if type(path) not in _texts or not os.path.isabs(path) or "\0" in path:
        _fail("The engine base must be an absolute directory")
    if not stat.S_ISDIR(os.lstat(path).st_mode):
        _fail("The engine base cannot be a link or special file")
    return os.path.realpath(path)


def _read(root, relative, maximum):
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        if not part or part in (".", "..") or "\\" in part:
            _fail("Invalid engine metadata path")
        current = os.path.join(current, part)
        mode = os.lstat(current).st_mode
        if index < len(parts) - 1:
            if not stat.S_ISDIR(mode):
                _fail("An engine metadata ancestor is not a directory")
        elif not stat.S_ISREG(mode):
            _fail("An engine source must be a regular file")
    with open(current, "rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        _fail("Engine metadata or protected source exceeds its limit")
    return data


def assert_stock_module(module, stock_base, filename):
    actual = getattr(module, "__file__", None)
    # .pyc/.pyo may be an already bundled source cache in a stock image.
    if type(actual) in _texts and actual.endswith((".pyc", ".pyo")):
        actual = actual[:-1]
    if type(actual) not in _texts or os.path.realpath(actual) != os.path.join(os.path.realpath(stock_base), filename):
        _fail("A host module was replaced outside the trusted stock base")


def select(stock_base, session):
    """Pin stock/overlay identity for this interpreter and return its base path."""
    global _pinned
    try:
        stock = _directory(stock_base)
        bundle = os.path.dirname(stock)
        profile = json.loads(_read(bundle, "runtime-profile.json", 256 * 1024).decode("utf-8"))
        provenance_bytes = _read(bundle, "provenance.json", 4 * 1024 * 1024)
        provenance = json.loads(provenance_bytes.decode("utf-8"))
        runtime = session.get("runtimeID")
        if type(runtime) not in _texts or runtime != profile.get("runtimeID") or runtime != provenance.get("runtimeID"):
            _fail("The Python engine does not match the exact native runtime")
        digest = session.get("engineOverlaySHA256")
        requested = session.get("engineBaseDirectory")
        if (digest is None) != (requested is None):
            _fail("The engine overlay identity and directory must be selected together")
        engine = stock
        if digest is not None:
            if not _digest(digest):
                _fail("Invalid engine overlay digest")
            engine = _directory(requested)
            if engine == stock or os.path.basename(engine) != "base":
                _fail("An engine overlay requires a private materialized base")
            record = json.loads(_read(os.path.dirname(engine), "materialization.json", 16 * 1024).decode("utf-8"))
            if (record.get("schemaVersion") != 1 or record.get("runtimeID") != "renpy-" + runtime or
                    record.get("manifestSHA256") != digest or
                    record.get("runtimeProvenanceSHA256") != _hash(provenance_bytes) or
                    not _digest(record.get("bundledBaseFingerprint")) or
                    not _digest(record.get("materializedBaseFingerprint"))):
                _fail("The engine materialization does not match this launch")
            for relative in _protected.values():
                original = _read(stock, relative, 8 * 1024 * 1024)
                if _read(engine, relative, 8 * 1024 * 1024) != original:
                    _fail("A protected engine source differs from stock")
        identity = (runtime, digest, stock, engine)
        if _pinned is not None and _pinned != identity:
            _fail("This interpreter already owns another engine; restart the app to change it")
        if _pinned is None:
            if "renpy" in sys.modules:
                _fail("The engine must be selected before the first Ren'Py import")
            _pinned = identity
        elif "renpy" in sys.modules:
            assert_stock_module(sys.modules["renpy"], engine, "renpy/__init__.py")
        if digest is not None:
            # Keep the selected tree first even when main.py just inserted the
            # stock host directory or a prior session restored sys.path.
            sys.path[:] = [engine, stock] + [item for item in sys.path if item not in (engine, stock)]
        return engine if digest is not None else stock_base
    except EngineOverlayFailure:
        raise
    except Exception as error:
        _fail("Cannot select the verified engine: " + str(error))


def selection():
    if _pinned is None:
        _fail("No Python engine has been selected")
    return {"runtimeID": _pinned[0], "engineOverlaySHA256": _pinned[1], "engineBaseDirectory": _pinned[3]}
