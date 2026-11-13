# -*- coding: utf-8 -*-
"""Typed launch-only preferences on the existing engine-owned Python stack.

This is not a Python sandbox. Network control covers the standard socket API;
custom native networking and direct _socket calls remain outside its scope.
"""
import errno
import hashlib
import json
import os
import stat
import sys
import uuid

try:
    _texts, _ints = (str, unicode), (int, long)
except NameError:
    _texts, _ints = (str,), (int,)

_flags = ("developerMode", "consoleEnabled", "overrideSkipping", "forceSkipUnseen",
          "overrideRollback100", "transparentTextboxes", "useLessMemory", "lessScreenUpdates",
          "allowNetwork", "chineseFontFallback", "overrideDeviceVariant")
_variants = frozenset(("pc", "large", "medium", "small", "touch", "mobile", "tablet", "phone"))
_missing = object()
_retained = None
_active = None
_network_baseline = {}


class EnginePreferencesError(RuntimeError):
    pass


# Ren'Py Backup pickles exported callbacks during import. These must remain
# stable module-level functions; session-local closures cannot enter its tables.
def _owner():
    if _active is None:
        raise EnginePreferencesError("No engine-preference session owns this callback")
    return _active


def _next_base(*args, **kwargs):
    owner = _owner()
    result = owner.original_base(*args, **kwargs)
    always = kwargs.get("always", args[1] if len(args) > 1 else False)
    if not always:
        if owner.active:
            owner._before_init()
        else:
            owner._event("enginePreferencesApplied", state=owner._bypass_state(), results={})
    return result


def _capabilities():
    result = dict(_owner().original_capabilities())
    result.update(enginePreferencesV1=True, unicodeSaveSlotsV1=False)
    return result


def _emit(kind, *args, **kwargs):
    owner = _owner()
    if kind == "didReset":
        owner.safe_reset = True
    elif kind in ("quarantined", "error"):
        owner.quarantined = True
    return owner.original_emit(kind, *args, **kwargs)


def _context_run(context, *args, **kwargs):
    owner = _owner()
    if context.init_phase:
        owner._configuration()
    try:
        return owner.original_run(context, *args, **kwargs)
    finally:
        if context.init_phase:
            owner._configuration()


def _preferences_getattribute(preferences, name):
    owner = _owner()
    return True if name == "skip_unseen" else owner.original_preference_get(preferences, name)


def _post_init():
    return _owner()._post_init()


def _interaction():
    return _owner()._interaction()


def _network_denied(*args, **kwargs):
    import socket
    raise socket.error(errno.EACCES, "Standard Python networking is disabled for this session")


def _socket_call(name, sock, args, kwargs):
    owner = _active
    if owner is not None and owner.active and not owner.prefs["allowNetwork"] and sock.family in owner.internet:
        return _network_denied()
    return _network_baseline[name](sock, *args, **kwargs)


def _dns_call(name, args, kwargs):
    owner = _active
    if owner is not None and owner.active and not owner.prefs["allowNetwork"]:
        return _network_denied()
    return _network_baseline[name](*args, **kwargs)


def _connect(sock, *args, **kwargs): return _socket_call("connect", sock, args, kwargs)
def _connect_ex(sock, *args, **kwargs): return _socket_call("connect_ex", sock, args, kwargs)
def _send(sock, *args, **kwargs): return _socket_call("send", sock, args, kwargs)
def _sendall(sock, *args, **kwargs): return _socket_call("sendall", sock, args, kwargs)
def _sendto(sock, *args, **kwargs): return _socket_call("sendto", sock, args, kwargs)
def _recv(sock, *args, **kwargs): return _socket_call("recv", sock, args, kwargs)
def _recvfrom(sock, *args, **kwargs): return _socket_call("recvfrom", sock, args, kwargs)
def _recv_into(sock, *args, **kwargs): return _socket_call("recv_into", sock, args, kwargs)
def _recvfrom_into(sock, *args, **kwargs): return _socket_call("recvfrom_into", sock, args, kwargs)
def _getaddrinfo(*args, **kwargs): return _dns_call("getaddrinfo", args, kwargs)
def _gethostbyname(*args, **kwargs): return _dns_call("gethostbyname", args, kwargs)
def _gethostbyname_ex(*args, **kwargs): return _dns_call("gethostbyname_ex", args, kwargs)
def _gethostbyaddr(*args, **kwargs): return _dns_call("gethostbyaddr", args, kwargs)
def _create_connection(*args, **kwargs): return _dns_call("create_connection", args, kwargs)

_socket_methods = dict(connect=_connect, connect_ex=_connect_ex, send=_send, sendall=_sendall, sendto=_sendto,
                       recv=_recv, recvfrom=_recvfrom, recv_into=_recv_into, recvfrom_into=_recvfrom_into)
_dns_methods = dict(getaddrinfo=_getaddrinfo, gethostbyname=_gethostbyname, gethostbyname_ex=_gethostbyname_ex,
                    gethostbyaddr=_gethostbyaddr, create_connection=_create_connection)


def _read(session):
    owner = session["sessionID"]
    if type(owner) not in _texts or str(uuid.UUID(owner)).lower() != owner.lower():
        raise EnginePreferencesError("Invalid engine-preference session owner")
    epoch = session["epoch"]
    if type(epoch) not in _ints or not 0 <= epoch < 2 ** 64:
        raise EnginePreferencesError("Invalid engine-preference epoch")
    directory = os.path.join(os.path.dirname(session["saveDirectory"]), "Logs")
    if os.path.realpath(directory) != os.path.abspath(directory):
        raise EnginePreferencesError("Linked engine-preference directory")
    path = os.path.join(directory, "engine-preferences-%s-%s.json" % (owner, epoch))
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return None, None
        raise EnginePreferencesError("Engine-preference file cannot be opened safely")
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or not 1 <= info.st_size <= 16 * 1024):
            raise EnginePreferencesError("Invalid engine-preference file size or type")
        data = source.read(16 * 1024 + 1)
    if len(data) != info.st_size or not 1 <= len(data) <= 16 * 1024:
        raise EnginePreferencesError("Engine preferences exceed 16 KiB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EnginePreferencesError("Duplicate engine-preference key")
            result[key] = value
        return result
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != set(("schemaVersion", "sessionID", "epoch", "runtimeID", "prefs"))
            or type(value["schemaVersion"]) not in _ints or value["schemaVersion"] != 1
            or value["sessionID"] != owner or type(value["epoch"]) not in _ints or value["epoch"] != epoch
            or value["runtimeID"] != session["runtimeID"]):
        raise EnginePreferencesError("Engine preferences belong to a different session or schema")
    prefs = value["prefs"]
    if type(prefs) is not dict or set(prefs) != set(_flags + ("variants",)):
        raise EnginePreferencesError("Unknown or missing engine-preference field")
    if any(type(prefs[name]) is not bool for name in _flags):
        raise EnginePreferencesError("Engine-preference flags must be Boolean")
    variants = prefs["variants"]
    if (type(variants) is not list or len(variants) > 8
            or any(type(item) not in _texts or item not in _variants for item in variants)
            or len(set(variants)) != len(variants) or (prefs["overrideDeviceVariant"] and not variants)):
        raise EnginePreferencesError("Invalid engine-preference variants")
    return prefs, hashlib.sha256(data).hexdigest()


class Session(object):
    def __init__(self, session, host):
        global _active
        if _retained is not None or (_active is not None and not _active.closed):
            raise EnginePreferencesError("A quarantined engine-preference owner requires a fresh process")
        self.session = dict(session)
        self.host = host
        self.prefs, self.digest = _read(session)
        self.active = self.prefs is not None and session.get("launchMode", "enhanced") != "nativeCompatibility"
        self.patches = []
        self.engine_patches = []
        self.environment = {}
        self.renpy = None
        self.fonts = None
        self.results = {}
        self.configuration = {}
        self.store_values = {}
        self.font_replacements = []
        self.textbox = None
        self.safe_reset = False
        self.quarantined = False
        self.closed = False
        self.post_init_callback = None
        self.interact_callback = None
        self.original_emit = host.emit
        self.original_capabilities = host.session_capabilities
        self.original_base = host._next_base
        _active = self
        self._patch(host, "session_capabilities", _capabilities)
        self._patch(host, "emit", _emit)
        self._event("enginePreferencesLoaded", state="loaded" if self.active else self._bypass_state())
        if self.active:
            self._environment()
            if not self.prefs["allowNetwork"]:
                self._network()
        self._patch(host, "_next_base", _next_base)

    def _bypass_state(self):
        return "bypassed" if self.prefs is not None else "legacy"

    def _event(self, kind, **fields):
        fields.update(schemaVersion=1, sidecarSHA256=self.digest, sidecarPresent=self.prefs is not None,
                      sessionID=self.session["sessionID"], epoch=self.session["epoch"])
        self.original_emit(kind, **fields)

    def _patch(self, owner, name, value, engine=False):
        target = self.engine_patches if engine else self.patches
        target.append((owner, name, owner.__dict__.get(name, _missing), value))
        setattr(owner, name, value)

    def _environment(self):
        values = {"RENPY_LESS_MEMORY": "1" if self.prefs["useLessMemory"] else None,
                  "RENPY_LESS_UPDATES": "1" if self.prefs["lessScreenUpdates"] else None,
                  "RENPY_VARIANT": " ".join(self.prefs["variants"]) if self.prefs["overrideDeviceVariant"] else None}
        for name, value in values.items():
            if value is None:
                continue
            self.environment[name] = os.environ.get(name)
            os.environ[name] = value

    def _network(self):
        import socket
        self.internet = (socket.AF_INET, socket.AF_INET6)
        for name in _socket_methods:
            original = getattr(socket.socket, name, None)
            if original is None:
                continue
            _network_baseline.setdefault(name, original)
            self._patch(socket.socket, name, _socket_methods[name])
        for name in _dns_methods:
            if hasattr(socket, name):
                _network_baseline.setdefault(name, getattr(socket, name))
                self._patch(socket, name, _dns_methods[name])

    def _before_init(self):
        import renpy
        self._clear_engine()
        self.renpy = renpy
        self.store_values = {name: getattr(renpy.store, name) for name in ("_skipping", "_rollback")}
        for name in ("developer", "console", "allow_skipping", "rollback_enabled", "rollback_length", "hard_rollback_limit"):
            if name not in self.configuration:
                self.configuration[name] = getattr(renpy.config, name, _missing)
        self._configuration()
        self.original_run = renpy.execution.Context.run
        self._patch(renpy.execution.Context, "run", _context_run, engine=True)
        if self.prefs["forceSkipUnseen"]:
            preference_type = renpy.preferences.Preferences
            self.original_preference_get = preference_type.__getattribute__
            self._patch(preference_type, "__getattribute__", _preferences_getattribute, engine=True)
        self.post_init_callback = _post_init
        renpy.game.post_init.append(self.post_init_callback)

    def _configuration(self):
        config = self.renpy.config
        if self.prefs["developerMode"]:
            config.developer = True
        if self.prefs["consoleEnabled"]:
            config.console = True
        if self.prefs["overrideSkipping"]:
            config.allow_skipping = True
        if self.prefs["overrideRollback100"]:
            config.rollback_enabled = True
            config.rollback_length = config.hard_rollback_limit = 100

    def _post_init(self):
        renpy = self.renpy
        self._configuration()
        self.interact_callback = _interaction
        renpy.config.interact_callbacks.append(self.interact_callback)
        for name in _flags:
            self.results[name] = dict(status="applied" if self.prefs[name] else "inactive", scope="stock-engine-launch")
        self.results["allowNetwork"] = dict(status="inactive" if self.prefs["allowNetwork"] else "partial",
            scope="standard-Python-socket-API; not OS isolation; direct _socket and native networking excluded")
        self.results["variants"] = dict(status="applied" if self.prefs["overrideDeviceVariant"] else "inactive", scope="stock-screen-variants")
        if self.prefs["transparentTextboxes"]:
            try:
                style = renpy.store.style.say_window
                background = style.background
                if background is None:
                    raise ValueError("No standard say-window background")
                style.background = renpy.store.Transform(background, alpha=0.5)
                self.textbox = (renpy.store.style, style, background, style.background)
                self.results["transparentTextboxes"] = dict(status="partial", scope="standard say_window background only; custom/inline backgrounds excluded")
            except Exception:
                self.results["transparentTextboxes"] = dict(status="unsupported", scope="no standard say_window background")
        if self.prefs["chineseFontFallback"]:
            self._chinese_font()
        self._interaction()
        partial = any(value["status"] in ("partial", "unsupported") for value in self.results.values())
        self._event("enginePreferencesApplied", state="partial" if partial else "applied", results=self.results)

    def _interaction(self):
        if self.prefs["overrideSkipping"]:
            self.renpy.store._skipping = True
        if self.prefs["overrideRollback100"]:
            self.renpy.store._rollback = True

    def _chinese_font(self):
        try:
            from pyobjus import autoclass
            bundle = self.host._inline_objc_value(autoclass("NSBundle"), "mainBundle")
            path = self.host._inline_objc_value(bundle, "resourcePath")
            path = path if type(path) in _texts else self.host._text(path)
            root = os.path.join(os.path.realpath(path), "TranslationFonts")
            self.fonts = self.host._inline_style_module.Fonts(root, "d0c613d211ebe54d6d596c643c6cf1bde8eb55fed8eac0732bba7d1ca4ee301d")
            alias = next(name for name, ranges in self.fonts.entries if name.endswith("notosanscjksc-regular.otf"))
            self.fonts.font(self.renpy, u"中文")  # Installs only the verified private loader callback.
            for filename in ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf"):
                for bold in (False, True):
                    for italic in (False, True):
                        key = (filename, bold, italic)
                        mapping = self.renpy.config.font_replacement_map
                        replacement = (alias, bold, italic)
                        self.font_replacements.append((key, mapping.get(key, _missing), replacement))
                        mapping[key] = replacement
            self.results["chineseFontFallback"] = dict(status="partial", scope="engine-default DejaVu fonts only; custom fonts unchanged")
        except Exception as error:
            if self.fonts is not None:
                self.fonts.close(); self.fonts = None
            self.results["chineseFontFallback"] = dict(status="unsupported", scope="verified CJK font unavailable", reason=str(error)[:300])

    def _clear_engine(self, reset_complete=False):
        if self.fonts is not None:
            self.fonts.close(); self.fonts = None
        if self.renpy is not None:
            for name, original in self.store_values.items():
                setattr(self.renpy.store, name, original)
            for name, original in self.configuration.items():
                if original is _missing:
                    self.renpy.config.__dict__.pop(name, None)
                else:
                    setattr(self.renpy.config, name, original)
            for key, original, replacement in self.font_replacements:
                mapping = self.renpy.config.font_replacement_map
                if mapping.get(key, _missing) == replacement:
                    if original is _missing:
                        mapping.pop(key, None)
                    else:
                        mapping[key] = original
            if self.textbox is not None and not reset_complete:
                manager, style, original, replacement = self.textbox
                if self.renpy.store.style is manager and style.background is replacement:
                    style.background = original
            for registry, callback in ((self.renpy.game.post_init, self.post_init_callback),
                                       (self.renpy.config.interact_callbacks, self.interact_callback)):
                if callback in registry:
                    registry.remove(callback)
        self._restore(self.engine_patches)
        self.engine_patches = []
        self.configuration = {}
        self.store_values = {}
        self.font_replacements = []
        self.textbox = None
        self.post_init_callback = self.interact_callback = None

    def _restore(self, patches):
        for owner, name, original, replacement in reversed(patches):
            if owner.__dict__.get(name, _missing) is replacement:
                if original is _missing:
                    delattr(owner, name)
                else:
                    setattr(owner, name, original)

    def finish(self):
        global _retained, _active
        if self.closed:
            return
        if not self.safe_reset or self.quarantined:
            _retained = self
            self._event("enginePreferencesRetained", state="quarantined", reason="engine has not acknowledged a quiescent reset")
            return
        # didReset acknowledges the official reload, which has already retired
        # native Style objects. Drop old references without reading their fields.
        self._clear_engine(reset_complete=True)
        self._restore(self.patches)
        for name, original in self.environment.items():
            if original is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = original
        self.closed = True
        self._event("enginePreferencesClosed", state="closed")
        _active = None
