# -*- coding: utf-8 -*-
"""Exact-version host adapter. Only this bundled module touches Ren'Py state."""
import json
import math
import os
import re
import sys
import threading
import base64
import types
import gc

from pyobjus import autoclass
from rr_objc_string import utf8_string as _objc_string, BridgePoller as _BridgePoller

try:
    _string_types = (str, unicode)
    _integer_types = (int, long)
except NameError:
    _string_types = (str,)
    _integer_types = (int,)


def _finite(value):
    return not math.isnan(value) and not math.isinf(value)


def _matches(pattern, value):
    return re.match("(?:" + pattern + ")\\Z", value)


def _is_text(value):
    return type(value) in _string_types

_bridge = autoclass("RRRuntimeBridge").shared()
_bridge_poll = _BridgePoller()
_NSString = autoclass("NSString")
_session = None
_base = None
_revision = 0
_variables = {}
_allowed_keys = set()
_interaction = 0
_last_dialogue = None
_last_dialogue_progress = None
_last_reading_state = None
_stopping = False
_in_pump = False
_ready_sent = False
_engine_keys = set()
_returned = False
_initial_path = None
_engine_imported = False
_sdl_cleanup = None
_module_baseline = {}
_module_loader_types = ()
_importer_baseline = ()
_module_spec_type = None
_frame_sent = False
_suspended = False
_thread_baseline = None
_exception_hook = None
_legacy_defaults_hook = None
_save_trust_original = None
_save_trust_wrapper = None
_save_trust_token = None
_save_trust_layout = None
_save_trust_prompt = None
_gesture_bindings = None
_gesture_original = None
_gesture_actions = {"rollback", "toggleAuto", "toggleSkip", "history", "hideInterface", "saveQuick", "showTools", "gameMenu"}
_gesture_directions = {"n", "ne", "e", "se", "s", "sw", "w", "nw"}


def load_live2d():
    raise RuntimeError("Live2D is not included in this version of Muxia")


def live2d_support():
    return {"available": False, "reason": "notIncluded"}


def guarded_live2d_model(filename, model_json=None, base=""):
    load_live2d()


def _install_exception_handler():
    global _exception_hook
    import renpy
    original = renpy.config.exception_handler
    if _exception_hook is not None and original is _exception_hook:
        return
    def report_unhandled(*args, **kwargs):
        result = original(*args, **kwargs) if original is not None else None
        if not result:
            error = sys.exc_info()[1]
            emit("gameError", errorType=type(error).__name__ if error is not None else "GameExecutionError", message=(str(error) if error is not None else "The title raised an unhandled execution error")[:2000])
        return result
    if original is not None:
        # New SDKs inspect the handler signature to choose te vs. the legacy
        # three strings. Preserve that dispatch, not just the returned value.
        report_unhandled.__wrapped__ = original
    _exception_hook = report_unhandled
    renpy.config.exception_handler = report_unhandled


def _thread_snapshot():
    return [{"name": thread.name, "ident": thread.ident, "daemon": bool(thread.daemon)} for thread in threading.enumerate()]


def _capture_script_identity(required_paths, phase):
    if _session is None:
        return "No active session owns the compiler identity"
    encoded = json.dumps({"sessionID": _session["sessionID"], "epoch": _session["epoch"], "requiredCompiledPaths": required_paths, "phase": phase}).encode("utf-8")
    return _text(_bridge.captureScriptIdentityJSON_(_objc_string(encoded)))


def ensure_engine_imported():
    global _engine_imported, _sdl_cleanup, _module_baseline, _module_loader_types, _module_spec_type, _legacy_defaults_hook, _importer_baseline
    if not _engine_imported:
        renpy = __import__("renpy")
        renpy.import_all()
        __import__("rr_gamepad_runtime").capture_baseline(renpy.display.controller)
        __import__("rr_menu_translation").install(renpy, enhancements_enabled, emit)
        if not hasattr(renpy.config, "after_default_callbacks"):
            # Backup restores functions by their current global name, so a
            # per-title wrapper would retain the preceding wrapper in a chain.
            original_defaults = renpy.exports.execute_default_statement
            def hosted_defaults(*args, **kwargs):
                result = original_defaults(*args, **kwargs)
                _session_started()
                return result
            _legacy_defaults_hook = hosted_defaults
            renpy.exports.execute_default_statement = hosted_defaults
        original_style_reset = renpy.style.reset
        original_style_unbuild = renpy.style.unbuild_style
        style_namespace = renpy.style.__dict__
        def reset_styles():
            if _session is not None:
                # These raw native caches own references invisible to Python GC.
                # Read the current registry: Backup may have rebound its dict.
                for style in list(dict.values(style_namespace["styles"])):
                    original_style_unbuild(style)
            return original_style_reset()
        renpy.style.reset = reset_styles
        # These official importers load per-session Python dependencies from
        # game/common/python-packages resources, including archive members.
        # Preserve the actual pre-title module objects, not merely their names.
        loader_types = []
        for module_name in ("renpy.loader", "renpy.importer"):
            module = sys.modules.get(module_name)
            if type(module) is types.ModuleType:
                loader_type = module.__dict__.get("RenpyImporter")
                if loader_type is not None:
                    loader_types.append(loader_type)
        if not loader_types:
            raise RuntimeError("The bundled official Python resource importer is unavailable")
        _module_loader_types = tuple(loader_types)
        _importer_baseline = tuple(sys.meta_path)
        frozen_importlib = sys.modules.get("_frozen_importlib")
        _module_spec_type = (frozen_importlib.__dict__.get("ModuleSpec")
                             if type(frozen_importlib) is types.ModuleType else None)
        _module_baseline = dict(sys.modules)
        original_poll = renpy.display.core.Interface.event_poll
        def poll_host_commands(interface):
            # Busy redraws can delay PERIODIC dispatch. This is the same
            # interact-loop boundary before retrieving the next SDL event.
            if _session is not None and not _suspended and _bridge_poll.is_application_active():
                pump()
            return original_poll(interface)
        renpy.display.core.Interface.event_poll = poll_host_commands
        original = renpy.display.core.Interface.after_first_frame
        def first_frame(interface):
            global _frame_sent
            original(interface)
            _bridge.attachRuntimeSurface()
            if _bridge.consumeSurfaceRedraw():
                interface.force_redraw = True
            if not _frame_sent:
                _frame_sent = True
                emit("firstFrameDrawn", width=renpy.config.screen_width, height=renpy.config.screen_height)
        renpy.display.core.Interface.after_first_frame = first_frame
        original_suspend = renpy.display.core.Interface.check_suspend
        def check_suspend(interface, event):
            global _suspended
            import pygame
            if event.type != pygame.APP_WILLENTERBACKGROUND:
                return original_suspend(interface, event)
            _suspended = True
            emit("suspended")
            try:
                return original_suspend(interface, event)
            finally:
                _suspended = False
                emit("resumed")
        renpy.display.core.Interface.check_suspend = check_suspend
        import pygame
        _sdl_cleanup = (pygame.time.set_timer, pygame.event.get, pygame.event.EventType, pygame.__dict__, pygame.init_functions, tuple(pygame.init_functions), pygame.quit_functions, tuple(pygame.quit_functions))
        original_wait = pygame.event.wait
        def wait_for_event(*args, **kwargs):
            if _suspended:
                drain_background_saves()
            return original_wait(*args, **kwargs)
        pygame.event.wait = wait_for_event
        _engine_imported = True
    import renpy.script
    import rr_script_identity
    if _session.get("preserveScriptIdentity"):
        rr_script_identity.install(renpy.script.Script, _capture_script_identity, _session["gameDirectory"])
    else:
        rr_script_identity.uninstall(renpy.script.Script)


def begin_session():
    global _session, _stopping, _revision, _variables, _interaction
    global _last_reading_state, _ready_sent, _returned, _initial_path, _in_pump, _frame_sent, _suspended, _thread_baseline
    global _gesture_bindings, _gesture_original, _last_dialogue, _last_dialogue_progress, _allowed_keys
    _session = json.loads(_text(_bridge.waitForLaunchJSON()))
    mode = _session.setdefault("launchMode", "enhanced")
    if mode not in ("enhanced", "minimal", "nativeCompatibility"):
        raise ValueError("Unknown reader launch mode")
    directory = _session.get("multiPersistentDirectory") or os.path.join(_session["saveDirectory"], "MultiPersistent")
    if not _is_text(directory) or not os.path.isabs(directory) or not os.path.isdir(directory):
        raise ValueError("The isolated MultiPersistent directory is unavailable")
    os.environ["RENPY_MULTIPERSISTENT"] = directory
    __import__("rr_script_identity").begin_session()
    # Load host modules before RenPyImporter is installed. Its first search can
    # cache game_files before the next title has indexed its external .py files.
    __import__("rr_series_state")
    __import__("rr_gamepad_runtime").begin_session(_session)
    _stopping = False
    _revision = 0
    _variables = {}
    _interaction = 0
    _last_dialogue = None
    _last_dialogue_progress = None
    _allowed_keys = set()
    _last_reading_state = None
    _ready_sent = False
    _returned = False
    _in_pump = False
    _frame_sent = False
    _suspended = False
    _gesture_bindings = None
    _gesture_original = None
    _initial_path = list(sys.path)
    if _thread_baseline is None:
        _thread_baseline = _thread_snapshot()
    emit("threadBaseline", threads=_thread_baseline)
    return _session


def should_return_to_host():
    return _stopping


def host_returned():
    return _returned


def _drain_session_events(stage, known_timers_cancelled=True):
    if _sdl_cleanup is None:
        raise RuntimeError("No engine event owner was captured")
    get_events = _sdl_cleanup[1]
    total = 0
    for batch in range(16):
        pending = get_events()
        try:
            if type(pending) is not list:
                raise RuntimeError("The engine event queue returned an invalid batch")
            if not pending:
                emit("eventQueueAudit", stage=stage, drainedCount=total,
                     drainRounds=batch + 1,
                     drainedUnderOwner=True, knownTimersCancelled=known_timers_cancelled)
                return
            # get() has already converted queued values under the old owner.
            # Do not inspect Event subclasses or their arbitrary .type values;
            # this teardown boundary owns references, not event API validation.
            total += len(pending)
            if total > 65536:
                raise RuntimeError("Engine event drain exceeded its bounded budget")
        finally:
            # No temporary Event reference may survive into the next get().
            del pending
    raise RuntimeError("Engine event drain exceeded its bounded budget")


def _release_session_events():
    import renpy.display.core
    if _sdl_cleanup is None:
        raise RuntimeError("No engine event owner was captured")
    set_timer, get_events, event_class, namespace, init_registry, official_init, quit_registry, official_quit = _sdl_cleanup
    failures = []
    quit_audit = []

    def failure(stage, index=-1):
        failures.append({"stage": stage, "index": index})

    for name in ("PERIODIC", "REDRAW", "TIMEEVENT"):
        try:
            set_timer(getattr(renpy.display.core, name), 0)
        except BaseException:
            failure("timer:" + name)
    timers_cancelled = not failures

    def drain(stage):
        try:
            _drain_session_events(stage, timers_cancelled)
        except BaseException:
            failure(stage)

    drain("beforeQuit")
    pairs = (("init_functions", init_registry, official_init),
             ("quit_functions", quit_registry, official_quit))
    snapshots = {}
    for name, registry, official in pairs:
        current = namespace.get(name)
        valid = (current is registry and type(current) is list and len(current) >= len(official)
                 and all(current[index] is callback for index, callback in enumerate(official)))
        if valid:
            snapshots[name] = tuple(current)
        else:
            failure(name + ":registry")
            snapshots[name] = None
    quitters = snapshots["quit_functions"]
    if quitters is None:
        current = namespace.get("quit_functions")
        extra = tuple(current) if type(current) is list else ()
        quitters = official_quit + tuple(callback for callback in extra
            if not any(callback is required for required in official_quit))
    for index, callback in enumerate(quitters):
        kind = "function" if type(callback) is types.FunctionType else "builtin" if type(callback) is types.BuiltinFunctionType else "callable"
        record = {"index": index, "kind": kind, "succeeded": False}
        try:
            callback()
            record["succeeded"] = True
        except BaseException:
            failure("quit", index)
        quit_audit.append(record)
    for name, registry, official in pairs:
        current = namespace.get(name)
        snapshot = snapshots[name]
        if (snapshot is None or current is not registry or type(current) is not list
                or len(current) != len(snapshot)
                or any(actual is not expected for actual, expected in zip(current, snapshot))):
            failure(name + ":changedDuringCleanup")
        try:
            # Keep the original public list identities, but never let a title's
            # callbacks become callbacks of the next title in this image.
            registry[:] = official
            namespace[name] = registry
        except BaseException:
            failure(name + ":restore")
    # Drop all suffix/loop references under this owner's GIL before the drain.
    snapshots = quitters = callback = current = extra = snapshot = None
    drain("afterQuit")
    restored = False
    try:
        _verify_session_registries()
        restored = True
    except BaseException:
        failure("registryRestoreVerification")
    emit("eventQueueCleanupSummary", succeeded=not failures,
         quitFunctions=quit_audit, errors=failures, publicRegistriesRestored=restored)
    if failures:
        raise RuntimeError("Engine event cleanup failed; reopen the app before reading another title")


def _verify_session_registries():
    namespace = _sdl_cleanup[3]
    for name, registry, official in (("init_functions", _sdl_cleanup[4], _sdl_cleanup[5]),
                                    ("quit_functions", _sdl_cleanup[6], _sdl_cleanup[7])):
        current = namespace.get(name)
        if (current is not registry or type(current) is not list or len(current) != len(official)
                or any(actual is not expected for actual, expected in zip(current, official))):
            raise RuntimeError("Public engine callbacks changed during cleanup")


def _retire_session_importers():
    # reload_all installs resource importers for an immediate F5 restart.
    # At the host shelf, a subsequent bootstrap will install them again.
    # Retire only post-baseline exact SDK importers: never restore the whole
    # meta_path from meta_backup, which would discard unrelated late entries.
    if type(sys.meta_path) is not list:
        raise RuntimeError("The engine importer registry changed during cleanup")
    keep = []
    for entry in sys.meta_path:
        preexisting = any(entry is original for original in _importer_baseline)
        official = any(type(entry) is owner for owner in _module_loader_types)
        if preexisting or not official:
            keep.append(entry)
    sys.meta_path[:] = keep

def _prune_title_modules(game):
    # A separate frame drops the iteration's module references before GC and
    # the final owner drain. Late official-importer modules are session
    # dependencies, even when their __file__ is relative or names an archive.
    for name, module in list(sys.modules.items()):
        if not issubclass(type(module), types.ModuleType) or _module_baseline.get(name) is module:
            continue
        namespace = types.ModuleType.__dict__["__dict__"].__get__(module, types.ModuleType)
        filename = namespace.get("__file__")
        loader = namespace.get("__loader__")
        if not any(type(loader) is official for official in _module_loader_types):
            spec = namespace.get("__spec__")
            if _module_spec_type is not None and type(spec) is _module_spec_type:
                loader = spec.__dict__.get("loader")
        dependency = any(type(loader) is official for official in _module_loader_types)
        from_game = _is_text(filename) and os.path.realpath(filename).startswith(game)
        if (dependency or from_game) and sys.modules.get(name) is module:
            del sys.modules[name]


def session_did_reset():
    global _session, _returned, _in_pump, _exception_hook
    import renpy
    _restore_save_trust_check()
    __import__("rr_series_state").uninstall()
    __import__("rr_menu_translation").reset_session()
    _set_gesture_bindings(None)
    __import__("rr_gamepad_runtime").close(_session["sessionID"], _session["epoch"], quiescent=True)
    # reload_all intentionally creates a fresh cache/preloader for an immediate
    # F5 restart. At the native shelf, stop that exact SDK worker as well.
    renpy.display.im.cache.quit()
    # Renderer reload alone preserves pygame's SDL window for F5. A different
    # ABI owns a different pygame module, so release that window at the shelf.
    import pygame
    _release_session_events()
    # Authors may replace this field within their title. Restore the exact
    # pre-title host hook before pruning; the next title must not inherit it.
    if _legacy_defaults_hook is not None:
        renpy.exports.execute_default_statement = _legacy_defaults_hook
    _exception_hook = None
    _retire_session_importers()
    game = os.path.realpath(_session["gameDirectory"]) + os.sep
    _prune_title_modules(game)
    sys.path[:] = _initial_path
    gc.collect()
    _drain_session_events("afterModulePrune")
    _verify_session_registries()
    _returned = True
    _in_pump = False
    emit("didStop")
    baseline_ids = {thread["ident"] for thread in _thread_baseline}
    threads = _thread_snapshot()
    remaining = [thread for thread in threads if thread["ident"] not in baseline_ids]
    emit("threadAudit", baseline=_thread_baseline, remaining=remaining)
    if remaining:
        emit("quarantined", message="A title left Python threads running after engine cleanup; reopen the app before reading another title.", threads=remaining)
        _session = None
        return
    emit("didReset")
    _session = None


def _text(value):
    if value is None:
        return None
    result = value.UTF8String()
    return result.decode("utf-8") if isinstance(result, bytes) else result


def emit(kind, request_id=None, **payload):
    event = dict(payload, type=kind)
    if _session:
        event.update(sessionID=_session["sessionID"], epoch=_session["epoch"])
    if request_id:
        event["requestID"] = request_id
    encoded = json.dumps(event, ensure_ascii=False, allow_nan=False).encode("utf-8")
    _bridge.emitEventJSON_(_objc_string(encoded))


def _ack(request, status="completed", **payload):
    emit("ack", request.get("requestID"), status=status, **payload)


def _scalar(value):
    if type(value) in _integer_types:
        return -(2 ** 63) <= value <= 2 ** 63 - 1
    if type(value) in (type(None), bool) + _string_types:
        return True
    return type(value) is float and _finite(value)


def _value_type(value):
    if _is_text(value):
        return "string"
    if type(value) in _integer_types:
        return "integer"
    return {type(None): "null", bool: "boolean", float: "float"}[type(value)]


def has_embedded_session():
    # Display geometry is a host contract in every mode, including native.
    return _session is not None


def enhancements_enabled():
    return bool(_session) and _session.get("launchMode", "enhanced") != "nativeCompatibility"


def session_capabilities():
    enabled = enhancements_enabled()
    import renpy
    language_selection = enabled and callable(getattr(renpy.exports, "known_languages", None)) and callable(getattr(renpy.exports, "change_language", None))
    dialogue_progress = enabled and callable(getattr(renpy.exports, "count_dialogue_blocks", None)) and callable(getattr(renpy.exports, "count_seen_dialogue_blocks", None))
    return {"hostControl": True, "readingTools": enabled, "variables": enabled,
            "dialogue": enabled, "dialogueProgress": dialogue_progress, "preferences": enabled, "gestures": enabled,
            "titlePatches": False, "languageSelection": language_selection,
            "controllerMapping": enabled and __import__("rr_gamepad_runtime").capable()}


def _language_name(value):
    # Python 2 runtimes may return either unicode or UTF-8 byte strings.
    # Decode before validating/sorting; implicit ASCII conversion loses names.
    try:
        if type(value) is bytes:
            value = value.decode("utf-8")
        if not _is_text(value) or not value or len(value.encode("utf-8")) > 256:
            return None
        if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
            return None
        return value
    except (TypeError, UnicodeError):
        return None


def _known_language_map():
    import renpy
    values = renpy.exports.known_languages()
    if not isinstance(values, (set, frozenset, list, tuple)) or len(values) > 256:
        raise ValueError("Unsupported language list")
    result = {}
    ambiguous = set()
    for value in values:
        name = _language_name(value)
        if name is None or name in ambiguous:
            continue
        if name in result:
            # Two distinct runtime keys must not silently select one language.
            del result[name]
            ambiguous.add(name)
        else:
            result[name] = value
    return result


def _publish_languages(request_id):
    import renpy
    languages = sorted(_known_language_map())
    current = renpy.game.preferences.language
    if current is not None:
        current = _language_name(current)
        if current is None:
            raise ValueError("The current language cannot be safely listed")
    emit("gameLanguages", request_id, languages=languages, current=current)


def _refresh_variables():
    global _revision, _variables, _allowed_keys
    if not enhancements_enabled():
        return []
    import renpy
    values = {}
    # Read the module dictionary, never an attribute expression or arbitrary getter.
    for key, value in renpy.store.__dict__.items():
        if _is_text(key) and _matches(r"[A-Za-z][A-Za-z0-9_]{0,127}", key) and _scalar(value):
            if key not in _engine_keys and key not in {"True", "False", "None", "main_menu", "menu", "nvl_mode"}:
                values[key] = value
    if values != _variables:
        _revision += 1
        _variables = values
    _allowed_keys = set(values)
    return [{"path": ["store", key], "name": key, "type": _value_type(value), "value": value, "revision": _revision} for key, value in sorted(values.items())]


def _reading_state():
    global _last_reading_state
    if not enhancements_enabled():
        return
    import renpy
    current = {"auto": bool(renpy.game.preferences.afm_enable), "skip": bool(renpy.config.skipping)}
    if current != _last_reading_state:
        _last_reading_state = current
        emit("readingState", **current)


def _reading_preferences(request_id=None):
    if not enhancements_enabled():
        return
    import renpy
    preferences = renpy.game.preferences
    values = {key: preferences.get_volume(mixer) for key, mixer in
              [("musicVolume", "music"), ("soundVolume", "sfx"), ("voiceVolume", "voice")]}
    values.update(textSpeed=preferences.text_cps, autoForwardTime=preferences.afm_time)
    unavailable = [key for key, value in values.items()
                   if type(value) not in _integer_types + (float,) or not _finite(value)]
    for key in unavailable:
        values[key] = None
    emit("readingPreferences", request_id, controllerMapping=__import__("rr_gamepad_runtime").readback(), gestureBindings=dict(_gesture_bindings) if _gesture_bindings is not None else None, unavailableFields=sorted(unavailable), **values)


def _validated_gestures(value):
    if value is None or value is False:
        return None
    if type(value) is not dict or len(value) > 8 or any(not _is_text(direction) or direction not in _gesture_directions or not _is_text(action) or action not in _gesture_actions for direction, action in value.items()):
        raise ValueError("Gesture bindings require eight-direction names and supported reader actions")
    return dict(value)


def _sync_gesture_hook():
    global _gesture_original
    if not enhancements_enabled():
        return
    import renpy
    if _gesture_bindings is not None and renpy.config.dispatch_gesture is not _dispatch_gesture:
        _gesture_original = renpy.config.dispatch_gesture
        renpy.config.dispatch_gesture = _dispatch_gesture


def _set_gesture_bindings(value):
    global _gesture_bindings, _gesture_original
    import renpy
    if value is None:
        if renpy.config.dispatch_gesture is _dispatch_gesture:
            renpy.config.dispatch_gesture = _gesture_original
        _gesture_original = None
    _gesture_bindings = value
    _sync_gesture_hook()


def _dispatch_gesture(direction):
    import renpy
    action = _gesture_bindings.get(direction) if _gesture_bindings is not None else None
    if action is None:
        original = _gesture_original if _gesture_original is not None else renpy.display.gesture.dispatch_gesture
        return original(direction)
    emit("gestureDispatched", direction=direction, action=action, recognizer="RenPy.GestureRecognizer")
    kind = "save" if action == "saveQuick" else action
    payload = {"slot": "quick-1"} if action == "saveQuick" else {}
    try:
        _dispatch({"type": kind, "payload": payload})
    except renpy.display.core.IgnoreEvent:
        raise
    except renpy.game.CONTROL_EXCEPTIONS:
        raise
    except Exception as error:
        emit("commandRejected", message=str(error) or type(error).__name__, source="gesture", direction=direction)
    raise renpy.display.core.IgnoreEvent()


def _dialogue(event, **kwargs):
    global _interaction, _last_dialogue
    if not enhancements_enabled() or event != "show_done":
        return
    import renpy
    what = kwargs.get("what")
    if not _is_text(what):
        what = renpy.store.__dict__.get("_last_say_what")
    if not _is_text(what):
        return
    # Displayed character names are already resolved in the shown screen.
    speaker = ""
    try:
        widget = renpy.exports.get_widget("say", "who")
        text = widget.text if widget is not None else None
        if _is_text(text):
            speaker = text
        elif type(text) is list and text and _is_text(text[0]):
            speaker = text[0]
    except Exception:
        pass
    _interaction += 1
    _last_dialogue = (speaker, what)
    progress = {}
    try:
        seen = renpy.exports.count_seen_dialogue_blocks()
        total = renpy.exports.count_dialogue_blocks()
        if type(seen) in _integer_types and type(total) in _integer_types and 0 <= seen <= total and total > 0:
            progress = {"seenDialogueBlocks": seen, "totalDialogueBlocks": total}
    except Exception:
        pass
    emit("dialogue", speaker=speaker, text=what, interactionID=str(_interaction), **progress)


def _publish_dialogue_progress():
    global _last_dialogue_progress
    if not enhancements_enabled():
        return
    try:
        import renpy
        seen = renpy.exports.count_seen_dialogue_blocks()
        total = renpy.exports.count_dialogue_blocks()
        if type(seen) not in _integer_types or type(total) not in _integer_types or not (0 <= seen <= total and total > 0):
            raise ValueError("invalid dialogue counts")
        current = (seen, total)
    except Exception:
        current = None
    if current != _last_dialogue_progress:
        _last_dialogue_progress = current
        if current is None:
            emit("dialogueProgress", available=False)
        else:
            emit("dialogueProgress", available=True, seenDialogueBlocks=current[0], totalDialogueBlocks=current[1])


def _save(slot, request):
    __import__("rr_script_identity").raise_if_failed()
    __import__("rr_series_state").raise_if_failed()
    import renpy
    if not _is_text(slot) or not _matches(r"[A-Za-z0-9_-]{1,80}", slot):
        raise ValueError("Unsupported save slot name")
    if not getattr(renpy.config, "save", True):
        raise ValueError("This title has disabled saving")
    if bool(getattr(renpy.store, "main_menu", False)):
        raise ValueError("Start the story before saving. Retry, or exit without saving.")
    log = getattr(renpy.game, "log", None)
    if log is None or not any(renpy.game.script.has_label(point.context.current) for point in reversed(log.log)):
        raise ValueError("No restorable story position is available. Retry, or exit without saving.")
    capacity = os.statvfs(_session["saveDirectory"])
    if capacity.f_bavail * capacity.f_frsize < 8 * 1024 * 1024:
        raise OSError("Not enough free storage to write a game save")
    active = bool(_bridge_poll.is_application_active()) and not _suspended
    if active:
        renpy.exports.take_screenshot()
        renpy.exports.save(slot)
    else:
        # Older save APIs always ask get_screenshot(), which otherwise performs
        # GPU readback. Background saves use only an already captured thumbnail
        # (or none), preserving the save data without submitting background GPU.
        interface = renpy.game.interface
        previous = interface.__dict__.get("get_screenshot")
        had_override = "get_screenshot" in interface.__dict__
        interface.__dict__["get_screenshot"] = lambda: interface.screenshot
        try:
            renpy.exports.save(slot)
        finally:
            if had_override:
                interface.__dict__["get_screenshot"] = previous
            else:
                del interface.__dict__["get_screenshot"]
    renpy.exports.save_persistent()
    __import__("rr_series_state").raise_if_failed()
    emit("saveCommitted", request.get("requestID"), slot=slot)


def _dispatch(request):
    global _stopping
    import renpy
    kind = request.get("type")
    payload = request.get("payload") or {}
    reserved_save = kind == "save" and payload.get("slot") == "rr_background"
    if not enhancements_enabled() and kind != "stop" and not reserved_save:
        raise ValueError("Reader enhancements are disabled for this session")
    if kind == "getVariables":
        values = _refresh_variables()
        emit("variables", request.get("requestID"), variables=values, revision=_revision)
    elif kind == "setVariable":
        _refresh_variables()
        path = payload.get("path")
        value = payload.get("value")
        if type(path) is not list or len(path) != 2 or path[0] != "store" or path[1] not in _allowed_keys:
            raise ValueError("Only whitelisted scalar store keys can be edited")
        if type(payload.get("expectedRevision")) not in _integer_types or payload["expectedRevision"] != _revision:
            raise ValueError("Variables changed; refresh the editor before writing")
        declared = payload.get("valueType") or payload.get("type")
        if type(value) is dict and "value" in value:
            declared = value.get("type")
            value = value["value"]
        # JSON encoders may serialize a Double(1.0) as 1. Preserve the explicit
        # wire type without treating booleans or strings as numeric values.
        if declared == "float" and type(value) in _integer_types:
            value = float(value)
        if not _scalar(value) or declared != _value_type(value):
            raise ValueError("A plain scalar of the declared type is required")
        # Loading restarts the current Ren'Py statement. Preserve a tool edit
        # made inside its interaction when that statement is replayed on load.
        renpy.exports.retain_after_load()
        renpy.store.__dict__[path[1]] = value
        values = _refresh_variables()
        emit("variables", request.get("requestID"), variables=values, revision=_revision)
    elif kind == "getGameLanguages":
        _publish_languages(request.get("requestID"))
    elif kind == "setGameLanguage":
        if set(payload) != {"language"}:
            raise ValueError("A single language selection is required")
        language = payload["language"]
        if language is not None:
            name = _language_name(language)
            choices = _known_language_map()
            if not _is_text(language) or name is None or name not in choices:
                raise ValueError("The requested language is unavailable")
            language = choices[name]
        renpy.exports.change_language(language)
        _publish_languages(request.get("requestID"))
    elif kind == "toggleAuto":
        renpy.game.preferences.afm_enable = not renpy.game.preferences.afm_enable
        renpy.exports.restart_interaction()
    elif kind == "toggleSkip":
        renpy.config.skipping = None if renpy.config.skipping else "slow"
        renpy.exports.restart_interaction()
    elif kind == "getPreferences":
        _reading_preferences(request.get("requestID"))
    elif kind == "setPreferences":
        unsupported = set(payload) - {"musicVolume", "soundVolume", "voiceVolume", "textSpeed", "autoForwardTime", "gestureBindings", "controllerBindings"}
        if unsupported:
            raise ValueError("Unsupported runtime preferences: " + ", ".join(sorted(unsupported)))
        for key, maximum in [("musicVolume", 1.0), ("soundVolume", 1.0), ("voiceVolume", 1.0), ("textSpeed", 200.0), ("autoForwardTime", 30.0)]:
            if key in payload:
                value = payload[key]
                if type(value) not in _integer_types + (float,) or not _finite(value) or not 0.0 <= value <= maximum:
                    raise ValueError(key + " must be a finite number between zero and " + str(maximum))
        gestures = _validated_gestures(payload["gestureBindings"]) if "gestureBindings" in payload else _gesture_bindings
        for key, mixer in [("musicVolume", "music"), ("soundVolume", "sfx"), ("voiceVolume", "voice")]:
            if key in payload:
                renpy.game.preferences.set_volume(mixer, payload[key])
        for key, attribute in [("textSpeed", "text_cps"), ("autoForwardTime", "afm_time")]:
            if key in payload:
                setattr(renpy.game.preferences, attribute, payload[key])
        if "gestureBindings" in payload:
            _set_gesture_bindings(gestures)
        if "controllerBindings" in payload:
            __import__("rr_gamepad_runtime").configure(payload["controllerBindings"])
        renpy.exports.restart_interaction()
        _reading_preferences(request.get("requestID"))
    elif kind == "save":
        _save(payload.get("slot", "rr_manual"), request)
    elif kind == "load":
        slot = payload.get("slot", "rr_manual")
        if not _is_text(slot) or not _matches(r"[A-Za-z0-9_-]{1,80}", slot):
            raise ValueError("Unsupported save slot name")
        if not renpy.exports.can_load(slot):
            raise ValueError("This slot cannot be loaded")
        _ack(request, status="accepted")
        renpy.exports.load(slot)
        return
    elif kind == "rollback":
        if not renpy.exports.can_rollback():
            raise ValueError("Rollback is unavailable at this interaction")
        _ack(request, status="accepted")
        renpy.exports.rollback()
        return
    elif kind == "history":
        if not renpy.exports.has_screen("history"):
            raise ValueError("This title does not expose a history screen")
        _ack(request, status="accepted")
        renpy.exports.run(renpy.store.ShowMenu("history"))
        return
    elif kind == "hideInterface":
        _ack(request, status="accepted")
        renpy.exports.run(renpy.store.HideInterface())
        return
    elif kind == "showTools":
        emit("hostAction", action="toggleTools")
    elif kind == "gameMenu":
        action = renpy.store.ShowMenu()
        if not action.get_sensitive():
            raise ValueError("The title's game menu is unavailable")
        _ack(request, status="accepted")
        renpy.exports.run(action)
        return
    elif kind == "stop":
        if payload.get("save", False):
            try:
                _save("rr_suspend", request)
            except Exception as error:
                emit("saveFailed", request.get("requestID"), message=str(error))
                return
        # Each exact SDK flushes its save_on_quit instances in main's finally
        # while unwinding UtterRestart. Keep that order and avoid serializing twice.
        _stopping = True
        _ack(request)
        emit("willStop")
        raise renpy.game.UtterRestartException()
    else:
        raise ValueError("This runtime does not support command: " + str(kind))
    _reading_state()
    _ack(request)


def pump():
    __import__("rr_script_identity").raise_if_failed()
    __import__("rr_series_state").raise_if_failed()
    global _in_pump
    if _in_pump or not _session:
        return
    import renpy
    _in_pump = True
    try:
        _install_exception_handler()
        _sync_gesture_hook()
        _bridge.attachRuntimeSurface()
        if renpy.display.interface is not None and _bridge.consumeSurfaceRedraw():
            renpy.display.interface.force_redraw = True
        for _ in range(8):
            command = _bridge_poll.take_command_json()
            if not command:
                break
            request = json.loads(command)
            if request.get("sessionID") != _session["sessionID"] or request.get("epoch") != _session["epoch"]:
                continue
            try:
                _dispatch(request)
            except renpy.game.CONTROL_EXCEPTIONS:
                raise
            except Exception as error:
                emit("commandRejected", request.get("requestID"), message=str(error) or type(error).__name__)
        __import__("rr_gamepad_runtime").publish_changes()
        _reading_state()
        _publish_dialogue_progress()
    finally:
        _in_pump = False


def drain_background_saves():
    # Official suspend loops disable periodic callbacks. The host posts a
    # dedicated SDL user event on admission so a later save wakes event.wait.
    # Only the reserved CPU save is consumed here; all other tools wait for
    # foreground and retain their original session/epoch validation.
    for _ in range(8):
        encoded = _bridge_poll.take_background_save_json()
        if not encoded:
            break
        request = json.loads(encoded)
        if request.get("sessionID") != _session["sessionID"] or request.get("epoch") != _session["epoch"]:
            continue
        try:
            _save("rr_background", request)
            _ack(request)
        except Exception as error:
            emit("commandRejected", request.get("requestID"), message=str(error) or type(error).__name__)


def _valid_host_slot(value):
    if not _is_text(value) or not value or value in (".", ".."):
        return False
    try:
        encoded = value.encode("utf-8")
        if len(encoded) > 255:
            return False
        return not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in ("/", "\\") for c in value)
    except (TypeError, UnicodeError):
        return False


def _resume_path_text(value):
    if isinstance(value, bytes):
        return value.decode(sys.getfilesystemencoding() or "utf-8")
    return value


def _checkpoint_from_engine():
    # Candidate is intentionally limited to the official file locations under
    # this session's Saves root. Unknown/custom locations are left to the title.
    import renpy
    location = renpy.loadsave.location
    if not getattr(renpy.config, "save", True):
        return None
    if type(location) is not renpy.savelocation.MultiLocation:
        raise RuntimeError("The title uses an unsupported save location.")
    suffix = renpy.savegame_suffix
    if not _is_text(suffix) or not suffix or len(suffix.encode("utf-8")) > 255:
        raise RuntimeError("The title's save suffix cannot be safely inspected.")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in ("/", "\\") for c in suffix):
        raise RuntimeError("The title's save suffix contains path characters.")
    root = os.path.realpath(_resume_path_text(_session["saveDirectory"]))
    allowed = {root: "", os.path.join(root, "sync"): "sync/"}
    parts = tuple(location.locations)
    prefixes = {}
    directories = {}
    active = []
    activity = tuple(bool(part.active) for part in parts)
    for part in parts:
        if not part.active:
            continue
        if type(part) is not renpy.savelocation.FileLocation or os.path.islink(part.directory):
            raise RuntimeError("The title uses an unsupported active save location.")
        path = os.path.realpath(_resume_path_text(part.directory))
        if path not in allowed or path in prefixes:
            raise RuntimeError("The title uses an unsupported save directory.")
        prefixes[path] = allowed[path]
        directories[id(part)] = path
        active.append(part)
    # Scan only validated active locations. MultiLocation.scan also calls
    # arbitrary inactive locations, including title-provided custom objects.
    for part in active:
        part.scan()
    current = tuple(location.locations)
    if renpy.loadsave.location is not location or not getattr(renpy.config, "save", True):
        raise RuntimeError("The active save location changed while preparing resume.")
    if len(current) != len(parts) or any(a is not b for a, b in zip(parts, current)):
        raise RuntimeError("The title's save locations changed while preparing resume.")
    if renpy.savegame_suffix != suffix or tuple(bool(p.active) for p in parts) != activity:
        raise RuntimeError("The title's save configuration changed while preparing resume.")
    if any(os.path.islink(p.directory) or os.path.realpath(_resume_path_text(p.directory)) != directories[id(p)] for p in active):
        raise RuntimeError("The title's save directories changed while preparing resume.")
    # A replacement with identical mtime can otherwise keep a stale cache.
    for name in ("rr_suspend", "rr_background"):
        renpy.loadsave.get_cache(name).clear()
    entries = []
    selected_parts = {}
    for name in ("rr_suspend", "rr_background"):
        part = location.newest(name)
        if part is None:
            continue
        if not any(part is item for item in active):
            raise RuntimeError("The selected save location changed while preparing resume.")
        path = os.path.realpath(_resume_path_text(part.directory))
        if path not in prefixes:
            raise RuntimeError("The selected save directory is not supported.")
        if len((name + suffix).encode("utf-8")) > 255:
            raise RuntimeError("The selected checkpoint filename is too long.")
        expected = os.path.join(_resume_path_text(part.directory), _resume_path_text(renpy.exports.fsencode(name + suffix)))
        if os.path.normpath(_resume_path_text(part.filename(name))) != os.path.normpath(expected):
            raise RuntimeError("The selected save filename is not supported.")
        entries.append({"slot": name, "path": prefixes[path] + name + suffix})
        selected_parts[name] = part
    if not entries:
        return None
    request = {"sessionID": _session["sessionID"], "epoch": _session["epoch"],
               "suffix": suffix, "entries": entries}
    encoded = json.dumps(request, ensure_ascii=True).encode("utf-8")
    selected = _text(_bridge.chooseResumeCheckpointJSON_(_objc_string(encoded)))
    if selected not in selected_parts:
        raise RuntimeError("The reader could not validate the resume checkpoints.")
    current = tuple(location.locations)
    if (renpy.loadsave.location is not location or not getattr(renpy.config, "save", True)
            or len(current) != len(parts) or any(a is not b for a, b in zip(parts, current))
            or tuple(bool(p.active) for p in parts) != activity
            or renpy.savegame_suffix != suffix
            or any(location.newest(name) is not selected_parts.get(name) for name in ("rr_suspend", "rr_background"))):
        raise RuntimeError("The title's save configuration changed while checking the checkpoint.")
    if any(os.path.islink(p.directory) or os.path.realpath(_resume_path_text(p.directory)) != directories[id(p)] for p in active):
        raise RuntimeError("The save directories changed while checking the checkpoints.")
    for name, part in selected_parts.items():
        expected = os.path.join(_resume_path_text(part.directory), _resume_path_text(renpy.exports.fsencode(name + suffix)))
        if os.path.normpath(_resume_path_text(part.filename(name))) != os.path.normpath(expected):
            raise RuntimeError("The save filename changed while checking the checkpoint.")
    return selected


def _stop_manual_resume(code, message):
    global _stopping
    import renpy
    emit("error", code=code, message=message)
    _stopping = True
    emit("willStop")
    raise renpy.game.UtterRestartException()


def _prepare_host_startup():
    import renpy
    if not _ready_sent:
        slot = _session.get("startupSaveSlot")
        explicit = slot is not None
        if explicit:
            suffix = getattr(renpy, "savegame_suffix", None)
            try:
                valid = (_valid_host_slot(slot) and _is_text(suffix)
                    and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in ("/", "\\") for c in suffix)
                    and len((slot + suffix).encode("utf-8")) <= 255)
            except (TypeError, UnicodeError):
                valid = False
            if not valid:
                _stop_manual_resume("manualResumeInvalid", "The requested save slot or runtime suffix is invalid.")
        elif _session.get("resumeAutomatically") is True:
            try:
                slot = _checkpoint_from_engine()
            except renpy.game.CONTROL_EXCEPTIONS:
                raise
            except Exception as error:
                # A metadata/scan problem must not prevent normal entry into the title.
                emit("autoResumeUnavailable", message="Checkpoint selection failed: " + type(error).__name__)
        if slot is not None:
            # Official _start prefers this process variable to config.auto_load.
            # Preserve it, but never claim a conflicting host choice succeeded.
            environment_slot = os.environ.get("RENPY_AUTO_LOAD")
            if environment_slot is not None:
                try:
                    conflict = _resume_path_text(environment_slot) != _resume_path_text(slot)
                except (TypeError, UnicodeError):
                    conflict = True
                if conflict:
                    if explicit:
                        # An ordinary exception can be swallowed by an author's
                        # exception handler. Use the host's normal return path.
                        _stop_manual_resume("manualResumeEnvironmentConflict",
                                            "The selected save conflicts with RENPY_AUTO_LOAD.")
                    emit("autoResumeUnavailable", message="The selected checkpoint conflicts with RENPY_AUTO_LOAD.")
                    return
            try:
                available = bool(renpy.exports.can_load(slot))
            except renpy.game.CONTROL_EXCEPTIONS:
                raise
            except Exception as error:
                if explicit:
                    _stop_manual_resume("manualResumeInvalid", "The runtime could not check the requested save.")
                emit("autoResumeUnavailable", message="Checkpoint verification failed: " + type(error).__name__)
                return
            if not available:
                # Keep a manual request authoritative even if the engine cannot
                # currently confirm it; otherwise the author's auto_load could
                # silently open a different progress point.
                if explicit:
                    renpy.config.auto_load = slot
                emit("manualResumeUnavailable" if explicit else "autoResumeUnavailable",
                     message="The runtime did not confirm the requested save slot.")
                return
            renpy.config.auto_load = slot
            emit("resumeState", slot=slot, available=True)


def _restore_save_trust_check():
    global _save_trust_original, _save_trust_wrapper, _save_trust_token, _save_trust_layout, _save_trust_prompt
    token = _save_trust_token
    if token is not None and _save_trust_wrapper is not None and getattr(token, "check_load", None) is _save_trust_wrapper:
        token.check_load = _save_trust_original
    if _save_trust_layout is not None and _save_trust_prompt is not None:
        # reload_all clears game.log before this hook; RevertableObject's
        # __delattr__ needs that log. Remove only our exact instance entry.
        namespace = getattr(_save_trust_layout, "__dict__", None)
        if namespace is not None and namespace.get("yesno_prompt") is _save_trust_prompt:
            del namespace["yesno_prompt"]
    _save_trust_original = None
    _save_trust_wrapper = None
    _save_trust_token = None
    _save_trust_layout = None
    _save_trust_prompt = None


def _trust_prompt_font(renpy):
    # Game search paths can shadow common resources. Only use the host font if
    # the loader resolves the exact bundled bytes; otherwise retain English.
    import hashlib
    name = "renreader-trust-7e42.ttf"
    try:
        try:
            source = renpy.loader.load(name, directory="fonts")
        except TypeError:
            source = renpy.loader.load(name)
        try:
            data = source.read(256 * 1024 + 1)
        finally:
            source.close()
        if hashlib.sha256(data).hexdigest() == "fefb02aee876d50f36fd84fc0e3780e6f7441a9ca26a0c913fd63a278d61da78":
            return name
    except Exception:
        pass
    return None


def _ensure_save_trust_prompt():
    global _save_trust_original, _save_trust_wrapper, _save_trust_token, _save_trust_layout, _save_trust_prompt
    # Some minimal games never install Ren'Py's optional layout modules. Keep
    # savetoken.check_load's existing two explicit decisions in that case.
    import renpy
    layout = getattr(getattr(renpy, "store", None), "layout", None)
    token = getattr(renpy, "savetoken", None)
    if token is None or layout is None or hasattr(layout, "yesno_prompt"):
        return

    # Initialize only after upstream's upgrade pass: unsigned existing saves
    # must still go through the normal trust prompt, not be silently signed.
    if getattr(renpy.config, "save_directory", None) is None and token.token_dir is None and _session:
        directory = _session.get("tokenDirectory")
        if directory and os.path.isfile(os.path.join(directory, "security_keys.txt")):
            previous_upgrade = token.should_upgrade
            try:
                token.signing_keys = []
                token.verifying_keys = []
                # Older engines have init_tokens but no standalone load_tokens.
                renpy.config.save_directory = "RenReader-host-token-init"
                token.init_tokens()
                if token.token_dir != directory or not token.signing_keys:
                    raise ValueError("Host save trust did not initialize")
            except Exception:
                token.token_dir = None
                token.signing_keys = []
                token.verifying_keys = []
            finally:
                renpy.config.save_directory = None
                token.should_upgrade = previous_upgrade

    def yesno_prompt(_screen, message):
        ui = renpy.ui
        font = _trust_prompt_font(renpy)
        ui.window(style="frame", xalign=0.5, yalign=0.5, xmaximum=int(renpy.config.screen_width * 0.9))
        ui.vbox(spacing=24)
        gui = getattr(renpy.store, "gui", None)
        if gui is not None and message == getattr(gui, "TRUST_TOKEN", None):
            if font:
                ui.text(u"信任此设备后，此密钥签名的存档以后将不再提示。", font=font, substitute=False)
            else:
                ui.text(u"Trusting this device allows future saves signed by its key without another prompt.", substitute=False)
        if gui is not None and message == getattr(gui, "UNKNOWN_TOKEN", None):
            if font:
                ui.text(u"安全提示：来自未知来源的存档可能执行代码。只有信任来源时才继续。", font=font, substitute=False)
            else:
                ui.text(u"Security warning: an untrusted save may execute code. Continue only if you trust its source.", substitute=False)
        ui.text(message, substitute=False)
        ui.hbox(spacing=40)
        if font:
            ui.textbutton(u"拒绝", text_font=font, clicked=ui.returns(False))
            ui.textbutton(u"同意", text_font=font, clicked=ui.returns(True))
        else:
            ui.textbutton(u"No", clicked=ui.returns(False))
            ui.textbutton(u"Yes", clicked=ui.returns(True))
        ui.close()
        ui.close()
        # Only the affirmative button's exact result can grant consent.
        return ui.interact() is True

    layout.yesno_prompt = yesno_prompt
    _save_trust_layout = layout
    _save_trust_prompt = yesno_prompt

    original_check = token.check_load

    def reject_save(message, chinese):
        def notice():
            ui = renpy.ui
            font = _trust_prompt_font(renpy)
            ui.window(style="frame", xalign=0.5, yalign=0.5, xmaximum=int(renpy.config.screen_width * 0.9))
            ui.vbox(spacing=24)
            if font:
                ui.text(chinese, font=font, substitute=False)
                ui.textbutton(u"知道了", text_font=font, clicked=ui.returns(False))
            else:
                ui.text(message, substitute=False)
                ui.textbutton(u"OK", clicked=ui.returns(False))
            ui.close()
            ui.interact()
        renpy.exports.invoke_in_new_context(notice)
        return False

    def checked_load(log, signatures):
        # In the fallback path the engine must not silently allow a save when
        # its trust store failed to initialize.
        if token.token_dir is None or not token.signing_keys:
            return reject_save(u"Save trust is unavailable. The save was not loaded and no key was trusted.",
                               u"存档信任不可用，未读取存档，也没有信任任何密钥。")
        if signatures and not token.verify_data(log, signatures):
            # The upstream prompt can add every key before verifying the log.
            # Verify each key it could add, not merely any signature in a set.
            for line in signatures.splitlines():
                kind, key, _signature = token.decode_line(line)
                if kind == "signature" and key not in token.verifying_keys:
                    if not key or not token.verify_data(log, line, False):
                        return reject_save(u"Invalid save signature. The save was not loaded and no key was trusted.",
                                           u"存档签名无效，未读取存档，也没有信任任何密钥。")
            if not token.verify_data(log, signatures, False):
                return reject_save(u"Invalid save signature. The save was not loaded and no key was trusted.",
                                   u"存档签名无效，未读取存档，也没有信任任何密钥。")
        return original_check(log, signatures)

    _save_trust_original = original_check
    _save_trust_wrapper = checked_load
    _save_trust_token = token
    token.check_load = checked_load


def _session_started():
    __import__("rr_script_identity").raise_if_failed()
    __import__("rr_series_state").raise_if_failed()
    global _ready_sent
    import renpy
    _install_exception_handler()
    __import__("rr_gamepad_runtime").install(sys.modules[__name__])
    _ensure_save_trust_prompt()
    # The native host owns durable checkpoints and never quits for lifecycle.
    renpy.config.save_on_mobile_background = False
    renpy.config.quit_on_mobile_background = False
    _prepare_host_startup()
    if pump not in renpy.config.periodic_callbacks:
        renpy.config.periodic_callbacks.append(pump)
    if enhancements_enabled() and _dialogue not in renpy.config.all_character_callbacks:
        renpy.config.all_character_callbacks.append(_dialogue)
    elif not enhancements_enabled() and _dialogue in renpy.config.all_character_callbacks:
        renpy.config.all_character_callbacks.remove(_dialogue)
    if not _ready_sent:
        _ready_sent = True
        live2d = live2d_support()
        dimensions = (renpy.config.screen_width, renpy.config.screen_height)
        if any(type(value) not in _integer_types + (float,) or not _finite(value) or value <= 0 or int(value) != value for value in dimensions):
            raise ValueError("The title's virtual display dimensions must be positive integers")
        enabled = enhancements_enabled()
        capabilities = session_capabilities()
        capabilities.update(rollback=enabled, save=enabled and bool(getattr(renpy.config, "save", True)),
                            live2D=live2d["available"], volume=enabled, textSpeed=enabled,
                            autoForwardTime=enabled, textSize=False)
        engine = __import__("rr_engine_overlay").selection()
        emit("ready", runtimeVersion=_session["runtimeID"], launchMode=_session["launchMode"], engineOverlaySHA256=engine["engineOverlaySHA256"], virtualWidth=int(dimensions[0]), virtualHeight=int(dimensions[1]), live2D=live2d, capabilities=capabilities)
        _reading_preferences()
    _reading_state()


def _next_base(original, always=False):
    global _engine_keys, _in_pump
    if always:
        return os.path.dirname(_session["gameDirectory"]) if _session else original
    _in_pump = False
    import renpy
    _install_exception_handler()
    series_directory = os.environ["RENPY_MULTIPERSISTENT"]
    legacy_directory = _session["saveDirectory"] if os.path.abspath(series_directory) == os.path.abspath(os.path.join(_session["saveDirectory"], "MultiPersistent")) else None
    __import__("rr_series_state").install(renpy.persistent, series_directory,
        aliases=[renpy.defaultstore, renpy.store, renpy.loadsave], legacy_directory=legacy_directory)
    preloader = renpy.display.im.cache.preload_thread
    if preloader is not None and not preloader.is_alive():
        renpy.display.im.reset_module()
    _engine_keys = set(renpy.store.__dict__) if enhancements_enabled() else set()
    if hasattr(renpy.config, "after_default_callbacks"):
        renpy.config.after_default_callbacks.append(_session_started)
    return os.path.dirname(_session["gameDirectory"])


def game_directory():
    return _session["gameDirectory"]


def log_directory():
    return _session["logDirectory"]


def install(entry, base, engine_base=None):
    global _base, _initial_path
    _base = base
    import renpy.bootstrap
    entry.path_to_gamedir = lambda basedir, name: _session["gameDirectory"] if _session else base
    entry.path_to_saves = lambda gamedir, save_directory=None: (_session["tokenDirectory"] if save_directory == "tokens" else _session["saveDirectory"])
    entry.path_to_logdir = lambda basedir: _session["logDirectory"] if _session else base
    entry.path_to_renpy_base = lambda: engine_base if engine_base is not None else base
    renpy.bootstrap.get_alternate_base = _next_base
    __import__("rr_objc_string").install_iossupport()
    _initial_path = list(sys.path)

