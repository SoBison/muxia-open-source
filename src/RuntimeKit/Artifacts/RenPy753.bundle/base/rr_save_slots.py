# -*- coding: utf-8 -*-
"""Session-owned extension of live load names; no aliases or pickle handling.

Explicit extended loads read the chosen regular file twice, in bounded chunks.
The final recheck and the stock engine's eventual open are not atomic.
"""
import errno
import hashlib
import os
import stat

try:
    _texts, _ints, _unicode = (str, unicode), (int, long), unicode
except NameError:
    _texts, _ints, _unicode = (str,), (int,), str

MAX_SAVE_BYTES = 512 * 1024 * 1024  # SaveFileService snapshot per-file ceiling.
_active = None
_retained = None


class SaveSlotError(ValueError):
    pass


def _utf8(value):
    if type(value) not in _texts:
        raise SaveSlotError("A save slot must be text")
    if not isinstance(value, _unicode):
        value = value.decode("utf-8")
    # Python 2 narrow builds expose valid astral characters as surrogate pairs.
    # Pair them explicitly; reject lone surrogates on both Python generations.
    index = 0
    while index < len(value):
        code = ord(value[index])
        index += 1
        if 0xD800 <= code <= 0xDBFF:
            if index == len(value) or not 0xDC00 <= ord(value[index]) <= 0xDFFF:
                raise SaveSlotError("Unpaired Unicode surrogate in save name")
            index += 1
        elif 0xDC00 <= code <= 0xDFFF:
            raise SaveSlotError("Unpaired Unicode surrogate in save name")
    # The native encoder handles paired surrogates on narrow Python 2; do not
    # call unichr(astral), which exceeds that build's sys.maxunicode.
    encoded = value.encode("utf-8")
    if encoded.decode("utf-8") != value:
        raise SaveSlotError("Noncanonical Unicode text representation")
    return value, encoded


def _identity(info):
    # Py2 has no nanosecond stat fields: their absence is explicit. SHA256,
    # never rounded timestamps alone, proves the two observed contents agree.
    return (info.st_dev, info.st_ino, getattr(info, "st_gen", None), info.st_size,
            info.st_mtime, getattr(info, "st_mtime_ns", None),
            info.st_ctime, getattr(info, "st_ctime_ns", None), info.st_mode)


def _regular(path):
    value = os.lstat(path)
    if not stat.S_ISREG(value.st_mode) or value.st_size <= 0 or value.st_size > MAX_SAVE_BYTES:
        raise SaveSlotError("The selected save is not a bounded regular file")
    return _identity(value)


def _directory(path):
    value = os.lstat(path)
    if not stat.S_ISDIR(value.st_mode):
        raise SaveSlotError("The save directory is not a regular directory")
    return (value.st_dev, value.st_ino, getattr(value, "st_gen", None))


def _digest(descriptor, path, expected):
    if _identity(os.fstat(descriptor)) != expected or _regular(path) != expected:
        raise SaveSlotError("The selected save changed before inspection")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest, count = hashlib.sha256(), 0
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        count += len(block)
        if count > MAX_SAVE_BYTES:
            raise SaveSlotError("The selected save exceeds the file limit")
        digest.update(block)
    if count != expected[3] or _identity(os.fstat(descriptor)) != expected or _regular(path) != expected:
        raise SaveSlotError("The selected save changed during inspection")
    return digest.digest()


# Stable top-level callbacks remain picklable during Ren'Py Backup/import.
def _dispatch(request):
    owner = _active
    if owner is None:
        raise SaveSlotError("No save-slot session owns this callback")
    payload = request.get("payload") if type(request) is dict else None
    slot = payload.get("slot") if type(payload) is dict else None
    if (type(request) is dict and request.get("type") == "load" and type(slot) in _texts
            and not owner.host._matches(r"[A-Za-z0-9_-]{1,80}", slot)):
        return owner.load(request)
    return owner.original_dispatch(request)


def _capabilities():
    owner = _active
    if owner is None:
        return {"unicodeSaveSlotsV1": False}
    result = dict(owner.original_capabilities())
    result["unicodeSaveSlotsV1"] = bool(owner.owns() and owner.host.enhancements_enabled()
                                         and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"))
    return result


def _emit(kind, *args, **kwargs):
    owner = _active
    if owner is None:
        raise SaveSlotError("No save-slot session owns this callback")
    if kind == "didReset":
        owner.safe_reset = owner.owns()
    elif kind in ("quarantined", "error"):
        owner.quarantined = True
    return owner.original_emit(kind, *args, **kwargs)


class Session(object):
    def __init__(self, session, host):
        global _active
        if (type(session) is not dict or _active is not None or _retained is not None or host._session is not session
                or type(session.get("epoch")) not in _ints or not 0 <= session["epoch"] < 2 ** 64
                or type(session.get("sessionID")) not in _texts or not session["sessionID"]
                or type(session.get("saveDirectory")) not in _texts or not session["saveDirectory"]
                or session.get("launchMode", "enhanced") not in ("enhanced", "minimal", "nativeCompatibility")):
            raise SaveSlotError("A previous save-slot owner has not reset")
        self.host, self.session = host, session
        self.session_id, self.epoch = session["sessionID"], session["epoch"]
        self.save_directory, self.mode = session["saveDirectory"], session.get("launchMode", "enhanced")
        self.save_root = os.path.realpath(self.save_directory)
        self.root_identity = _directory(self.save_root)
        # Keep the original directory open so its inode cannot be recycled
        # while this owner is alive, including an uncertain/quarantined exit.
        self.root_descriptor = os.open(self.save_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self._root()
        except Exception:
            os.close(self.root_descriptor)
            raise
        self.safe_reset = self.quarantined = self.closed = False
        self.original_dispatch = host._dispatch
        self.original_capabilities = host.session_capabilities
        self.original_emit = host.emit
        _active = self
        host._dispatch, host.session_capabilities, host.emit = _dispatch, _capabilities, _emit
        self._event("unicodeSaveSlotsInstalled", "installed" if host.enhancements_enabled() else "bypassed",
                    unicodeSaveSlotsV1=bool(host.enhancements_enabled() and hasattr(os, "O_NOFOLLOW")
                                           and hasattr(os, "O_NONBLOCK")), maximumFileBytes=MAX_SAVE_BYTES)

    def _event(self, kind, state, **fields):
        fields.update(schemaVersion=1, sessionID=self.session_id, epoch=self.epoch, state=state)
        self.original_emit(kind, **fields)

    def _root(self):
        opened = os.fstat(self.root_descriptor)
        if (os.path.islink(self.save_directory) or os.path.realpath(self.save_directory) != self.save_root
                or os.path.realpath(self.save_root) != self.save_root
                or _directory(self.save_root) != self.root_identity or not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino, getattr(opened, "st_gen", None)) != self.root_identity):
            raise SaveSlotError("The session's original save root was replaced or redirected")
        return self.save_root

    def owns(self):
        return (_active is self and not self.closed and not self.quarantined and self.host._session is self.session
                and self.session.get("sessionID") == self.session_id
                and self.session.get("epoch") == self.epoch
                and self.session.get("saveDirectory") == self.save_directory
                and self.session.get("launchMode", "enhanced") == self.mode)

    def _request(self, request):
        if not self.owns() or not self.host.enhancements_enabled() or self.mode == "nativeCompatibility":
            raise SaveSlotError("This save-slot request has no active enhanced owner")
        if (type(request) is not dict or set(request) != {"schemaVersion", "sessionID", "epoch", "requestID", "type", "payload"}
                or type(request["schemaVersion"]) not in _ints or request["schemaVersion"] != 1
                or type(request["epoch"]) not in _ints or request["epoch"] != self.epoch
                or type(request["sessionID"]) not in _texts or request["sessionID"] != self.session_id or request["type"] != "load"
                or type(request["requestID"]) not in _texts or not request["requestID"]
                or len(request["requestID"].encode("utf-8")) > 128
                or type(request["payload"]) is not dict or set(request["payload"]) != {"slot"}):
            raise SaveSlotError("An extended load requires one current-session slot payload")
        slot, encoded = _utf8(request["payload"]["slot"])
        if not self.host._valid_host_slot(slot):
            raise SaveSlotError("Unsupported extended save slot name")
        return slot, encoded

    def _locations(self, renpy, slot):
        location, suffix = renpy.loadsave.location, renpy.savegame_suffix
        suffix, suffix_bytes = _utf8(suffix)
        if (type(location) is not renpy.savelocation.MultiLocation or not getattr(renpy.config, "save", True)
                or not suffix_bytes or len(_utf8(slot)[1] + suffix_bytes) > 255
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in ("/", "\\") for c in suffix)):
            raise SaveSlotError("The title has an unsupported save location or suffix")
        root = self._root()
        root_identity = _directory(root)
        parts = tuple(location.locations)
        activity = tuple(bool(part.active) for part in parts)
        active, seen, files = [], set(), []
        for part in parts:
            if not part.active:
                continue
            if type(part) is not renpy.savelocation.FileLocation:
                raise SaveSlotError("The title uses a nonstandard active save location")
            original_directory = self.host._resume_path_text(part.directory)
            if os.path.islink(original_directory):
                raise SaveSlotError("An active save directory is linked")
            directory = os.path.realpath(original_directory)
            if directory not in (root, os.path.join(root, "sync")) or directory in seen:
                raise SaveSlotError("An active save directory escapes the current Saves root")
            seen.add(directory)
            active.append((part, directory, _directory(directory)))
            leaf = self.host._resume_path_text(renpy.exports.fsencode(slot + suffix))
            filename = os.path.join(directory, leaf)
            expected = os.path.join(original_directory, leaf)
            if os.path.normpath(self.host._resume_path_text(part.filename(slot))) != os.path.normpath(expected):
                raise SaveSlotError("The title remapped the selected save filename")
            try:
                identity = _regular(filename)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    continue
                raise
            files.append((part, filename, identity))
        if not files:
            raise SaveSlotError("The requested save is missing")
        return location, suffix, parts, activity, root, root_identity, tuple(active), tuple(files)

    def _recheck(self, renpy, slot, original):
        self._request_owner()
        current = self._locations(renpy, slot)
        if (current[0] is not original[0] or current[1] != original[1] or len(current[2]) != len(original[2])
                or any(a is not b for a, b in zip(current[2], original[2])) or current[3:] != original[3:]):
            raise SaveSlotError("The physical save selection changed while checking load")

    def _request_owner(self):
        if not self.owns() or not self.host.enhancements_enabled() or self.mode == "nativeCompatibility":
            raise SaveSlotError("The extended load owner changed")

    def load(self, request):
        slot, unused = self._request(request)
        import renpy
        selected = self._locations(renpy, slot)
        opened = []
        try:
            before = []
            for part, filename, identity in selected[-1]:
                descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                opened.append((descriptor, filename, identity))
                before.append(_digest(descriptor, filename, identity))
            if len(set(before)) != 1:
                raise SaveSlotError("The standard save locations contain different copies of this slot")
            for current, directory, marker in selected[-2]:
                current.scan()
            renpy.loadsave.get_cache(slot).clear()
            self._recheck(renpy, slot, selected)
            chosen = selected[0].newest(slot)
            if not any(chosen is part for part, filename, identity in selected[-1]) or not renpy.exports.can_load(slot):
                raise SaveSlotError("This slot cannot be loaded")
            self._recheck(renpy, slot, selected)
            after = [_digest(descriptor, filename, identity) for descriptor, filename, identity in opened]
            if selected[0].newest(slot) is not chosen or after != before:
                raise SaveSlotError("The selected save contents changed while checking load")
            self._recheck(renpy, slot, selected)
            if selected[0].newest(slot) is not chosen:
                raise SaveSlotError("The selected standard save location changed")
            self.host._ack(request, status="accepted")
            # Keep the stock load and its signatures/pickle/CONTROL_EXCEPTIONS.
            # No claim of atomicity across this final check and the stock open.
            return renpy.exports.load(slot)
        finally:
            for descriptor, filename, identity in opened:
                os.close(descriptor)

    def finish(self):
        global _active, _retained
        if self.closed:
            return
        if not self.safe_reset or self.quarantined:
            _retained = self
            self._event("unicodeSaveSlotsClosed", "retained")
            return
        for name, replacement, original in (("_dispatch", _dispatch, self.original_dispatch),
                                             ("session_capabilities", _capabilities, self.original_capabilities),
                                             ("emit", _emit, self.original_emit)):
            if getattr(self.host, name) is replacement:
                setattr(self.host, name, original)
        self.closed = True
        os.close(self.root_descriptor)
        self._event("unicodeSaveSlotsClosed", "closed")
        _active = None
