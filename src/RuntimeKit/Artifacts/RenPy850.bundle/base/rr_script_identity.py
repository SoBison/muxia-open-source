"""Synchronously preserve compiler output before loaded script code can execute.

Compatible with the bundled Python 2.7 and Python 3 runtimes. This module never
opens or unpickles scripts; the host owns the single file/manifest implementation.
"""
from functools import wraps
import os

try:
    _text_type = unicode
except NameError:
    _text_type = str

_failure = None


class ScriptIdentityCaptureFailure(BaseException):
    """Do not continue a title with a falsely acknowledged durable identity."""


def _failure_text(value):
    try:
        return _text_type(value)[:2000]
    except Exception:
        return _text_type(type(value).__name__)


def begin_session():
    global _failure
    _failure = None


def raise_if_failed():
    if _failure is not None:
        raise ScriptIdentityCaptureFailure(_failure)


def _abort(value):
    global _failure
    if _failure is None:
        _failure = u"Compiled script identity capture failed: " + _failure_text(value)
    raise_if_failed()


def _function(method):
    return getattr(method, "im_func", method)


def _wrap(original, capture, phase):
    @wraps(original)
    def wrapped(self, *args, **kwargs):
        raise_if_failed()
        # An original exception propagates unchanged and never acknowledges a capture.
        result = original(self, *args, **kwargs)
        try:
            required = sorted(getattr(self, "_rr_identity_loaded", set()))
            error = wrapped._rr_identity_capture(required, phase)
        except Exception as failure:
            _abort(failure)
        if error:
            _abort(error)
        return result
    wrapped._rr_identity_capture = capture
    wrapped._rr_identity_wrapper = True
    wrapped._rr_identity_original = _function(original)
    return wrapped


def _path_text(path):
    return path.decode("utf-8") if isinstance(path, bytes) else _text_type(path)


def _wrap_file(original, game_directory):
    @wraps(original)
    def loaded(self, directory, filename, *args, **kwargs):
        raise_if_failed()
        result = original(self, directory, filename, *args, **kwargs)
        # Official load_file returns (metadata, statements); None metadata means
        # that the caller will fall back to another source. Archives create no new IDs.
        if directory is None or not result or result[0] is None:
            return result
        try:
            filename = _path_text(filename)
            if filename.endswith((".rpy", ".rpym")):
                compiled = filename + "c"
            elif filename.endswith("_ren.py"):
                compiled = filename[:-7] + ".rpyc"
            elif filename.endswith((".rpyc", ".rpymc")):
                compiled = filename
            else:
                return result
            relative = os.path.relpath(os.path.abspath(os.path.join(_path_text(directory), compiled)), loaded._rr_identity_game_directory)
            if relative == os.pardir or relative.startswith(os.pardir + os.sep) or os.path.isabs(relative):
                return result  # SDK common scripts are immutable runtime resources.
            paths = getattr(self, "_rr_identity_loaded", None)
            if paths is None:
                paths = set()
                self._rr_identity_loaded = paths
            paths.add(relative)
            if len(paths) > 10000:
                _abort("Loaded compiler identity exceeds its file limit")
        except Exception as failure:
            _abort(failure)
        return result
    loaded._rr_identity_game_directory = os.path.abspath(_path_text(game_directory))
    loaded._rr_identity_file_wrapper = True
    loaded._rr_identity_original = _function(original)
    return loaded


def install(script_type, capture, game_directory):
    """Install after engine import, before main; repeated calls update the callback.

    load_script/load_module return only after their compiled-file handles close.
    The callback stays on that same engine stack and must not pump a run loop.
    """
    if not callable(capture):
        raise TypeError("A synchronous compiler-identity callback is required")
    original = getattr(script_type, "load_file")
    function = _function(original)
    if getattr(function, "_rr_identity_file_wrapper", False):
        function._rr_identity_game_directory = os.path.abspath(_path_text(game_directory))
    else:
        setattr(script_type, "load_file", _wrap_file(original, game_directory))
    for name, phase in (("load_script", "script"), ("load_module", "module")):
        original = getattr(script_type, name)
        function = _function(original)
        if getattr(function, "_rr_identity_wrapper", False):
            function._rr_identity_capture = capture
        else:
            setattr(script_type, name, _wrap(original, capture, phase))


def uninstall(script_type):
    """Explicit opt-out sessions must not inherit a prior session's callback."""
    for name in ("load_script", "load_module", "load_file"):
        function = _function(getattr(script_type, name))
        if getattr(function, "_rr_identity_wrapper", False) or getattr(function, "_rr_identity_file_wrapper", False):
            setattr(script_type, name, function._rr_identity_original)
