"""Candidate host wiring; SDL public state queries only, no input injection."""
from __future__ import unicode_literals
import ctypes
import json
import os
import rr_gamepad_input

_mapping = None
_host = None
_sdl = None
_last_published = None
_baseline_controller = None
_baseline_entries = None
_owner = None


def begin_session(session):
    global _owner
    if _owner is not None:
        raise RuntimeError("The previous gamepad session did not close")
    _owner = (session["sessionID"], session["epoch"])


def capture_baseline(controller):
    global _baseline_controller, _baseline_entries
    if _baseline_entries is None:
        _baseline_controller = controller
        _baseline_entries = (controller.event, controller.post_event)
    elif controller is not _baseline_controller:
        raise RuntimeError("The engine controller module identity changed")


class PhysicalButtons(object):
    def __init__(self, base):
        path = os.path.normpath(os.path.join(base, "..", "..", "Frameworks", "RRPlatform.framework", "RRPlatform"))
        self.library = ctypes.CDLL(path)
        signatures = {
            "SDL_NumJoysticks": (ctypes.c_int, []),
            "SDL_JoystickGetDeviceInstanceID": (ctypes.c_int32, [ctypes.c_int]),
            "SDL_GameControllerFromInstanceID": (ctypes.c_void_p, [ctypes.c_int32]),
            "SDL_GameControllerGetAttached": (ctypes.c_int, [ctypes.c_void_p]),
            "SDL_GameControllerGetButtonFromString": (ctypes.c_int, [ctypes.c_char_p]),
            "SDL_GameControllerGetButton": (ctypes.c_uint8, [ctypes.c_void_p, ctypes.c_int]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.library, name)
            function.restype = result
            function.argtypes = arguments
        self.buttons = {}
        for name in rr_gamepad_input.BUTTONS:
            button = self.library.SDL_GameControllerGetButtonFromString(name.encode("ascii"))
            if button < 0:
                raise RuntimeError("The pinned SDL button API is unavailable")
            self.buttons[name] = button

    def __call__(self):
        result = {}
        count = self.library.SDL_NumJoysticks()
        if count < 0 or count > 64:
            raise RuntimeError("The connected controller count is unavailable")
        for index in range(count):
            instance = self.library.SDL_JoystickGetDeviceInstanceID(index)
            handle = self.library.SDL_GameControllerFromInstanceID(instance)
            if not handle or not self.library.SDL_GameControllerGetAttached(handle):
                continue
            result[instance] = set(name for name, button in self.buttons.items()
                                   if self.library.SDL_GameControllerGetButton(handle, button))
        return result


def install(host):
    global _mapping, _host, _sdl
    session = host._session
    if _owner != (session["sessionID"], session["epoch"]):
        raise RuntimeError("The gamepad session owner is unavailable")
    if _mapping is not None:
        if _mapping.session_id != session["sessionID"] or _mapping.epoch != session["epoch"]:
            raise RuntimeError("The previous gamepad mapping owner did not close")
        return
    _host = host
    if not host.enhancements_enabled():
        return
    import renpy
    import pygame
    if _sdl is None:
        _sdl = PhysicalButtons(host._base)
    def allowed():
        if host._session is not session or host._stopping or host._suspended:
            return False
        gate = json.loads(host._text(host._bridge.keyboardInputStateJSON()))
        blocked = gate.get("blocked", True)
        return type(blocked) in (bool,) + host._integer_types and blocked == 0 and bool(host._bridge.isApplicationActive())
    def gate_generation():
        gate = json.loads(host._text(host._bridge.keyboardInputStateJSON()))
        generation = gate.get("generation")
        return generation if type(generation) in host._integer_types and generation >= 0 else None
    def dispatch(action, button, generation):
        # Swift applies its current modal/session gate before a standard action.
        host.emit("hostAction", source="gamepad", action=action, button=button, gateGeneration=generation)
    if gate_generation() is None:
        return
    _mapping = rr_gamepad_input.GamepadMapping(renpy.display.controller, pygame,
        renpy.display.core.EVENTNAME, session["sessionID"], session["epoch"], session["launchMode"],
        _sdl, allowed, dispatch, input_generation=gate_generation)


def capable():
    return _mapping is not None and not _mapping.closed


def configure(bindings):
    if _mapping is None:
        raise ValueError("Gamepad mapping is disabled for this session")
    _mapping.configure(_host._session["sessionID"], _host._session["epoch"], bindings)


def state():
    return _mapping.state() if _mapping is not None else {"schemaVersion": 1, "bindings": None, "pending": False}


def _public_state():
    value = state()
    return {key: value[key] for key in ("schemaVersion", "bindings", "pending")}


def readback():
    global _last_published
    _last_published = _public_state()
    return _last_published


def publish_changes():
    if _mapping is not None and _public_state() != _last_published:
        _host._reading_preferences()


def close(session_id, epoch, quiescent=False):
    global _mapping, _host, _last_published, _owner
    if not quiescent:
        raise RuntimeError("Gamepad cleanup requires the quiescent session boundary")
    if _owner != (session_id, epoch):
        raise RuntimeError("A different session owns gamepad cleanup")
    if _host is not None and (_host._session["sessionID"] != session_id or _host._session["epoch"] != epoch):
        raise RuntimeError("A different session owns gamepad cleanup")
    if _mapping is not None and (_mapping.session_id != session_id or _mapping.epoch != epoch):
        raise RuntimeError("A different mapping owner cannot be released")
    if _mapping is not None:
        if _mapping.controller is not _baseline_controller or _baseline_entries is None:
            raise RuntimeError("The engine controller baseline is unavailable")
        _mapping.close()
        # Only session_did_reset calls this after the official unwind/reload.
        # A title's later replacement belongs to that ended session as well.
    if _baseline_controller is not None:
        _baseline_controller.event = _baseline_entries[0]
        _baseline_controller.post_event = _baseline_entries[1]
    restored = True
    if _host is not None:
        _host.emit("gamepadMappingClosed", restored=restored)
    _mapping = None
    _host = None
    _last_published = None
    _owner = None
