"""Per-session writable common resources; no game/save-directory relocation."""
from __future__ import absolute_import
import os
import stat
import sys
import tempfile
import uuid

try:
    _texts = (basestring,)
    _ints = (int, long)
except NameError:
    _texts = (str,)
    _ints = (int,)

MAX_FILES = 8192
MAX_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024


def _identity(path, directory):
    value = os.lstat(path)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(value.st_mode):
        raise RuntimeError("Common cache requires regular, nonlinked nodes")
    return value.st_dev, value.st_ino


def _directory(path):
    if not isinstance(path, _texts) or not os.path.isabs(path) or "\0" in path:
        raise RuntimeError("Common cache requires an absolute directory")
    path = os.path.abspath(path)
    if os.path.realpath(path) != path:
        raise RuntimeError("Common cache directory is not canonical")
    _identity(path, True)
    return path


def _tree(root):
    directories = {"": _identity(root, True)}
    files = {}
    total = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in sorted(dirs):
            path = os.path.join(parent, name)
            directories[os.path.relpath(path, root)] = _identity(path, True)
        for name in sorted(names):
            path = os.path.join(parent, name)
            identity = _identity(path, False)
            size = os.lstat(path).st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_BYTES or len(files) >= MAX_FILES:
                raise RuntimeError("Common cache copy exceeds its bounded budget")
            files[os.path.relpath(path, root)] = identity
    return directories, files, total


class CommonCache(object):
    def __init__(self, engine_base, private_tmp, owner, epoch):
        if not isinstance(owner, _texts) or str(uuid.UUID(owner)).lower() != owner.lower():
            raise RuntimeError("Invalid common-cache owner")
        if type(epoch) not in _ints or not 0 <= epoch < 2 ** 64:
            raise RuntimeError("Invalid common-cache epoch")
        self.source = _directory(os.path.join(_directory(engine_base), "renpy", "common"))
        self.private_tmp = _directory(private_tmp)
        self.owner, self.epoch = owner, epoch
        self.root = tempfile.mkdtemp(prefix="rr-common-" + owner.lower() + "-", dir=self.private_tmp)
        self.identity = _identity(self.root, True)
        self.path = os.path.join(self.root, "renpy", "common")
        os.makedirs(self.path)
        dirs, files, self.byte_count = _tree(self.source)
        for relative in sorted(dirs, key=lambda value: (value.count(os.sep), value)):
            if relative:
                os.mkdir(os.path.join(self.path, relative), 0o700)
        self.source_files = set(files)
        self.allowed_files = set(files)
        for relative in files:
            if relative.endswith((".rpy", ".rpym")):
                self.allowed_files.add(relative + "c")
            elif relative.endswith("_ren.py"):
                self.allowed_files.add(relative[:-7] + ".rpyc")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise RuntimeError("Common cache requires no-follow file opening")
        for relative in sorted(files):
            source = os.path.join(self.source, relative)
            descriptor = os.open(source, os.O_RDONLY | nofollow | os.O_NONBLOCK)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != files[relative]:
                    raise RuntimeError("Common source changed while copying")
                output = os.open(os.path.join(self.path, relative), os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
                with os.fdopen(output, "wb") as target:
                    copied = 0
                    while True:
                        block = os.read(descriptor, 1024 * 1024)
                        if not block:
                            break
                        copied += len(block)
                        if copied > MAX_FILE_BYTES:
                            raise RuntimeError("Common source grew beyond its budget")
                        target.write(block)
                if os.fstat(descriptor).st_size != copied or _identity(source, False) != files[relative]:
                    raise RuntimeError("Common source changed during copying")
            finally:
                os.close(descriptor)
        if _tree(self.source)[:2] != (dirs, files):
            raise RuntimeError("Common source tree changed during copying")
        self.allowed_dirs = set(dirs)
        self.directory_identities = _tree(self.path)[0]
        self.renpy_identity = _identity(os.path.dirname(self.path), True)
        self.bindings = []
        self.entry = None
        self.entry_original = None
        self.entry_hook = None
        self.closed = False

    def info(self):
        return dict(owner=self.owner, epoch=self.epoch, sourceCommon=self.source,
                    privateRoot=self.private_tmp, ownedRoot=self.root, effectiveCommon=self.path,
                    device=self.identity[0], inode=self.identity[1], copiedFileCount=len(self.source_files),
                    copiedBytes=self.byte_count)

    def bind(self, entry):
        self.entry, self.entry_original = entry, entry.path_to_common
        def common_path(renpy_base):
            if self.closed:
                raise RuntimeError("Expired common-cache hook")
            self._bind_virtual_names()
            return self.path
        self.entry_hook = common_path
        entry.path_to_common = common_path

    def _bind_virtual_names(self):
        import renpy
        for module in [getattr(renpy, "parser", None), getattr(renpy, "lexer", None)]:
            if module is None or not hasattr(module, "elide_filename"):
                continue
            original = module.elide_filename
            if any(original is binding[2] for binding in self.bindings):
                continue
            def elide(filename, _original=original):
                if isinstance(filename, _texts):
                    normalized = filename.replace("\\", "/")
                    prefix = self.path.replace("\\", "/") + "/"
                    if normalized.startswith(prefix):
                        filename = self.source.replace("\\", "/") + "/" + normalized[len(prefix):]
                return _original(filename)
            module.elide_filename = elide
            self.bindings.append((module, original, elide))

    def close(self):
        # Only the caller's successful quiescent reset may invoke close().
        if self.closed or _identity(self.root, True) != self.identity:
            raise RuntimeError("Common cache owner directory changed; retain it")
        dirs, files, total = _tree(self.path)
        if dirs != self.directory_identities or _identity(os.path.dirname(self.path), True) != self.renpy_identity:
            raise RuntimeError("Common-cache directory ownership changed; retain it")
        if set(dirs) - self.allowed_dirs or set(files) - self.allowed_files:
            raise RuntimeError("Unknown common-cache contents; retain them")
        # Restore only our actual bindings, never another owner's replacements.
        for module, original, installed in reversed(self.bindings):
            if getattr(module, "elide_filename", None) is installed:
                module.elide_filename = original
        self.bindings[:] = []
        for module in [self.entry, sys.modules.get("__main__"), getattr(sys.modules.get("renpy"), "__main__", None)]:
            if module is not None and getattr(module, "path_to_common", None) is self.entry_hook:
                module.path_to_common = self.entry_original
        # Unlink only the exact nodes just observed inside the uniquely owned tree.
        for relative, identity in files.items():
            if _identity(self.root, True) != self.identity:
                raise RuntimeError("Common cache owner changed during cleanup")
            path = os.path.join(self.path, relative)
            if _identity(path, False) != identity:
                raise RuntimeError("Common-cache file changed during cleanup")
            os.unlink(path)
        for relative in sorted(dirs, key=lambda value: (value.count(os.sep), value), reverse=True):
            path = os.path.join(self.path, relative)
            if _identity(path, True) != dirs[relative]:
                raise RuntimeError("Common-cache directory changed during cleanup")
            os.rmdir(path)
        os.rmdir(os.path.dirname(self.path))
        if _identity(self.root, True) != self.identity:
            raise RuntimeError("Common cache owner changed before final removal")
        os.rmdir(self.root)
        self.closed = True
        self.entry = self.entry_original = self.entry_hook = None
        return dict(owner=self.owner, epoch=self.epoch, ownedRoot=self.root, removed=True,
                    originalSourceCommon=self.source)


class Session(object):
    """Observe the real session audit/reset boundary without rewriting rr_host."""
    def __init__(self, session, host):
        self.host = host
        self.owner, self.epoch = session["sessionID"], session["epoch"]
        self.audit_ok = False
        self.reset_seen = False
        self.failed = False
        self.finished = False
        self.original_emit = host.emit
        self.lease = None
        def observe(kind, request_id=None, **payload):
            current = getattr(host, "_session", None)
            owned = ((type(current) is dict and current.get("sessionID") == self.owner
                      and current.get("epoch") == self.epoch)
                     or (payload.get("sessionID") == self.owner and payload.get("epoch") == self.epoch))
            if owned:
                if kind == "threadAudit":
                    self.audit_ok = type(payload.get("remaining")) is list and not payload["remaining"]
                elif kind == "didReset":
                    self.reset_seen = True
                elif kind in ("error", "gameError", "quarantined"):
                    self.failed = True
            return self.original_emit(kind, request_id=request_id, **payload)
        self.observer = observe
        host.emit = observe

    def install(self, entry, engine_base):
        if self.lease is not None:
            raise RuntimeError("Common cache already installed")
        host = self.host
        manager = host._inline_objc_value(host.autoclass("NSFileManager"), "defaultManager")
        temporary = host._inline_objc_value(manager, "temporaryDirectory")
        private_tmp = os.path.realpath(host._text(host._inline_objc_value(temporary, "path")))
        self.lease = CommonCache(engine_base, private_tmp, self.owner, self.epoch)
        self.lease.bind(entry)
        self._publish("commonCachePrepared", self.lease.info())

    def _publish(self, kind, fields):
        values = dict(fields)
        values.update(sessionID=self.owner, epoch=self.epoch)
        self.original_emit(kind, **values)

    def finish(self):
        if self.finished:
            raise RuntimeError("Common cache session already finished")
        self.finished = True
        owns_emit = self.host.emit is self.observer
        if owns_emit:
            self.host.emit = self.original_emit
        if self.lease is None:
            raise RuntimeError("Common cache was never installed")
        if self.failed or not self.audit_ok or not self.reset_seen:
            self._publish("commonCacheRetained", dict(self.lease.info(), reason="sessionNotQuiescent"))
            return
        if not owns_emit:
            self._publish("commonCacheRetained", dict(self.lease.info(), reason="emitOwnershipNotRestored"))
            raise RuntimeError("Common-cache emit ownership was not restored")
        try:
            result = self.lease.close()
        except BaseException:
            self._publish("commonCacheRetained", dict(self.lease.info(), reason="cleanupFailure"))
            raise
        self._publish("commonCacheClosed", dict(result, successfulQuiescentReset=True))
        self.observer = self.original_emit = self.host = None
