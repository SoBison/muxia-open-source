"""Fail-closed MultiPersistent I/O using the exact runtime's own serializer.

Python 2.7/3 compatible. This module does not deserialize data independently.
Temporary guards affect only renpy.persistent's globals, never builtins or os.
"""
import os
import errno
import stat
import tempfile
import threading

try:
    import builtins
    _text = str
except ImportError:
    import __builtin__ as builtins
    _text = unicode

_state = None
_failure = None
_missing = object()


class SeriesStateFailure(BaseException):
    """Bypasses official fallback-to-empty catch blocks; the host must abort."""


def _abort(message):
    global _failure
    if _failure is None:
        try:
            _failure = u"MultiPersistent: " + _text(message)[:1500]
        except Exception:
            _failure = u"MultiPersistent I/O failed"
    raise_if_failed()


def raise_if_failed():
    if _failure is not None:
        raise SeriesStateFailure(_failure)


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except Exception as error:
        _abort(error)


def _path(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return _text(value)


def _name(value):
    value = _path(value)
    if (not value or value in (u".", u"..") or len(value.encode("utf-8")) > 251
            or any(part in value for part in (u"/", u"\\", u"\0", u":"))):
        _abort("unsafe MultiPersistent filename")
    return value


def _owner():
    raise_if_failed()
    if _state is None:
        _abort("no active series session")
    if threading.current_thread().ident != _state["owner"]:
        _abort("MultiPersistent called outside the engine owner thread")


def _check_file(name):
    directory = _state["directory"]
    configured = os.environ.get("RENPY_MULTIPERSISTENT")
    if configured is None or os.path.abspath(_path(configured)) != directory:
        _abort("managed MultiPersistent environment changed")
    filename = os.path.join(directory, name)
    if os.path.islink(filename) or os.path.islink(filename + u".new"):
        _abort("MultiPersistent file is a symbolic link")


def _migrate_legacy(name):
    legacy = _state["legacy"]
    if legacy is None:
        return
    destination = os.path.join(_state["directory"], name)
    if os.path.lexists(destination):
        if not stat.S_ISREG(os.lstat(destination).st_mode):
            _abort("MultiPersistent destination is not a regular file")
        return
    source = os.path.join(legacy, name)
    try:
        before = os.lstat(source)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return
        _abort(error)
    if not stat.S_ISREG(before.st_mode) or before.st_size > 64 * 1024 * 1024:
        _abort("legacy MultiPersistent source is a link, special file, or exceeds 64 MiB")
    reader = None
    writer = None
    temporary = None
    try:
        reader = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        opened = os.fstat(reader)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev):
            _abort("legacy MultiPersistent source changed during open")
        writer, temporary = tempfile.mkstemp(prefix=".rr-legacy-", dir=_state["directory"])
        total = 0
        while True:
            data = os.read(reader, 64 * 1024)
            if not data:
                break
            total += len(data)
            if total > 64 * 1024 * 1024:
                _abort("legacy MultiPersistent source exceeds 64 MiB")
            offset = 0
            while offset < len(data):
                count = os.write(writer, data[offset:])
                if count <= 0:
                    _abort("legacy MultiPersistent copy did not advance")
                offset += count
        after = os.fstat(reader)
        if total != before.st_size or after.st_size != before.st_size or after.st_mtime != before.st_mtime:
            _abort("legacy MultiPersistent source changed during copy")
        os.fsync(writer)
        os.close(writer)
        writer = None
        try:
            # Atomic, no-replace publication of a newly copied inode. Never link
            # to the original file or leave a writable alias to the legacy source.
            os.link(temporary, destination)
        except OSError as error:
            if error.errno != errno.EEXIST:
                _abort(error)
            _check_file(name)
            if not stat.S_ISREG(os.lstat(destination).st_mode):
                _abort("MultiPersistent destination changed during legacy copy")
    except Exception as error:
        _abort(error)
    finally:
        if reader is not None:
            os.close(reader)
        if writer is not None:
            os.close(writer)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


class _File:
    def __init__(self, file):
        self._file = file

    def __getattr__(self, name):
        value = getattr(self._file, name)
        if callable(value):
            return lambda *a, **k: _call(value, *a, **k)
        return value

    def __enter__(self):
        _call(self._file.__enter__)
        return self

    def __exit__(self, *args):
        return _call(self._file.__exit__, *args)


class _OS:
    def __init__(self, original):
        self._original = original

    def __getattr__(self, name):
        return getattr(self._original, name)

    def rename(self, source, destination):
        # No destructive unlink fallback after a failed rename on the same volume.
        _call(self._original.rename, source, destination)
        _state["writes"] += 1

    def unlink(self, path):
        # Older releases catch BaseException around rename. Their fallback must
        # never unlink the old file after our first failure has been latched.
        raise_if_failed()
        return _call(self._original.unlink, path)


def _guarded(function, *args, **kwargs):
    _owner()
    module = _state["module"]
    saved = {}
    for name in ("open", "os", "loads", "dump", "dumps"):
        saved[name] = module.__dict__.get(name, _missing)
    def guarded_open(*a, **k):
        return _File(_call(builtins.open, *a, **k))
    try:
        module.open = guarded_open
        module.os = _OS(saved["os"] if saved["os"] is not _missing else os)
        for name in ("loads", "dump", "dumps"):
            original = saved[name]
            if original is not _missing:
                # Bind each serializer separately; no closure over the loop variable.
                def make_guard(original):
                    return lambda *a, **k: _call(original, *a, **k)
                setattr(module, name, make_guard(original))
        result = _call(function, *args, **kwargs)
        raise_if_failed()  # Older SDKs have a bare except around loads().
        return result
    finally:
        for name, value in saved.items():
            if value is _missing:
                module.__dict__.pop(name, None)
            else:
                setattr(module, name, value)


def install(persistent_module, directory, aliases=(), legacy_directory=None):
    """Call on the engine thread after importing persistent, before game init.

    Pass existing renpy.defaultstore/renpy.store/renpy.loadsave modules in aliases
    to replace their exported MultiPersistent aliases when they equal the original.
    The host sets RENPY_MULTIPERSISTENT to this explicit, managed directory.
    """
    global _state, _failure
    uninstall()
    _failure = None
    directory = os.path.abspath(_path(directory))
    if not os.path.isdir(directory) or os.path.islink(directory):
        _abort("managed MultiPersistent directory is missing or is a link")
    if legacy_directory is not None:
        legacy_directory = os.path.abspath(_path(legacy_directory))
        if (directory != os.path.join(legacy_directory, "MultiPersistent")
                or not os.path.isdir(legacy_directory) or os.path.islink(legacy_directory)):
            _abort("legacy migration is only allowed inside the same unbound save profile")
    original = persistent_module.MultiPersistent
    save = getattr(persistent_module._MultiPersistent.save, "im_func", persistent_module._MultiPersistent.save)
    _state = {"module": persistent_module, "class": persistent_module._MultiPersistent, "owner": threading.current_thread().ident,
              "directory": directory, "factory": original, "save": save,
              "aliases": [], "names": set(), "loads": 0, "writes": 0, "legacy": legacy_directory}

    def factory(name, save_on_quit=False):
        _owner()
        safe = _call(_name, name)
        _check_file(safe)
        _migrate_legacy(safe)
        names = _state["names"]
        if safe + u".new" in names or (safe.endswith(u".new") and safe[:-4] in names):
            _abort("MultiPersistent filename collides with another object's temporary file")
        names.add(safe)
        result = _guarded(original, name, save_on_quit=save_on_quit)
        filename = os.path.abspath(_path(result._filename))
        if os.path.dirname(filename) != directory or os.path.basename(filename) != safe:
            _abort("official MultiPersistent path differs from the managed directory")
        _state["loads"] += 1
        return result

    def save_wrapper(self):
        _owner()
        filename = os.path.abspath(_path(self._filename))
        if os.path.dirname(filename) != directory:
            _abort("MultiPersistent write escaped its managed directory")
        _check_file(_name(os.path.basename(filename)))
        before = _state["writes"]
        result = _guarded(save, self)
        if _state["writes"] == before:
            _abort("official MultiPersistent save returned without committing a file")
        return result

    persistent_module.MultiPersistent = factory
    persistent_module._MultiPersistent.save = save_wrapper
    _state["wrapper"] = factory
    _state["save_wrapper"] = save_wrapper
    factory._rr_series_original = original
    for module in aliases:
        candidate = getattr(module, "MultiPersistent", None) if module is not None else None
        if module is not None and (candidate is original or getattr(candidate, "_rr_series_original", None) is original):
            module.MultiPersistent = factory
            _state["aliases"].append(module)


def save_on_quit():
    """Run before UtterRestart/reset while the engine can still serialize classes."""
    _owner()
    module = _state["module"]
    function = getattr(module, "save_on_quit_MP", None)
    if function is None:
        # 7.4/7.5/8.0 save_MP only contains instances with save_on_quit=True.
        function = module.save_MP
    _call(function)
    raise_if_failed()


def diagnostics():
    return {"healthy": _failure is None, "failure": _failure,
            "loads": _state["loads"] if _state else 0,
            "writes": _state["writes"] if _state else 0}


def uninstall():
    global _state
    if _state is None:
        return
    module = _state["module"]
    if getattr(module, "MultiPersistent", None) is _state.get("wrapper"):
        module.MultiPersistent = _state["factory"]
    klass = _state["class"]
    current_save = getattr(klass.save, "im_func", klass.save)
    if current_save is _state["save_wrapper"]:
        klass.save = _state["save"]
    # defaultstore can be imported after installation and acquire the wrapped
    # factory then. Clear those late aliases as well before the next session.
    aliases = list(_state["aliases"])
    renpy = getattr(module, "renpy", None)
    if renpy is not None:
        aliases += [getattr(renpy, name, None) for name in ("defaultstore", "store", "loadsave")]
    for alias in aliases:
        if alias is None:
            continue
        if getattr(alias, "MultiPersistent", None) is _state.get("wrapper"):
            alias.MultiPersistent = _state["factory"]
    _state = None
