"""Bundled entry point for the verified Ren'Py 8.5.3/Python 3.12 runtime."""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [BASE] + [item for item in sys.path if item != BASE]

def _stock_module(name, filename):
    if name in sys.modules:
        module = sys.modules[name]
        actual = getattr(module, "__file__", "")
        if actual.endswith((".pyc", ".pyo")):
            actual = actual[:-1]
        if os.path.realpath(actual) != os.path.realpath(os.path.join(BASE, filename)):
            raise RuntimeError("A host entry module does not belong to the trusted stock base")
        return module
    if sys.version_info[0] >= 3:
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, os.path.join(BASE, filename))
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    else:
        import imp
        module = imp.load_source(name, os.path.join(BASE, filename))
    return module


rr_engine_overlay = _stock_module("rr_engine_overlay", "rr_engine_overlay.py")
_stock_module("rr_inline_style", "rr_inline_style.py")
_stock_module("rr_objc_string", "rr_objc_string.py")
rr_host = _stock_module("rr_host", "rr_host.py")
# The frozen selection must precede install(), which imports renpy.bootstrap.
session = rr_host.begin_session()
_common_module = _stock_module("rr_common_cache", "rr_common_cache.py")
_common_cache = _common_module.Session(session, rr_host)
_preferences_module = _stock_module("rr_engine_preferences", "rr_engine_preferences.py")
_preferences = _preferences_module.Session(session, rr_host)
_save_slots_module = _stock_module("rr_save_slots", "rr_save_slots.py")
_save_slots = _save_slots_module.Session(session, rr_host)
_gesture_override_module = _stock_module("rr_gesture_override", "rr_gesture_override.py")
_gesture_override = _gesture_override_module.Session(session, rr_host)
ENGINE_BASE = rr_engine_overlay.select(BASE, session)
entry = _stock_module("rr_renpy_entry", "renpy.py")
rr_host.install(entry, BASE, ENGINE_BASE)
_common_cache.install(entry, ENGINE_BASE if ENGINE_BASE is not None else BASE)
# 7.4/7.5 import the process __main__ module for these launcher helpers;
# newer releases use renpy.__main__. Keep both references on the same paths.
for name, value in entry.__dict__.items():
    if name.startswith("path_to_"):
        sys.modules["__main__"].__dict__[name] = value
try:
    try:
        try:
            entry.main()
        finally:
            try:
                rr_host.close_inline_style()
            finally:
                rr_host.close_game_haptics()
                __import__("rr_series_state").uninstall()
    finally:
        try:
            _gesture_override.finish()
        finally:
            try:
                _save_slots.finish()
            finally:
                _preferences.finish()
finally:
    _common_cache.finish()
