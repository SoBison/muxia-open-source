# -*- coding: utf-8 -*-
"""Session-only repair for exact immutable compiled story editions.

The host must validate the entire immutable installation against the supplied
fingerprint before passing it here. This module does not itself attest that the installation manifest is genuine.
"""
import hashlib
import os
import stat
import sys

PATCH_ID = 'compiled-story-quick-continue-v1'
COMPILED_SCREENS = {'3e409438f9bc40d464eae86051114aae1802ffcbba02896f2dbd52a105fc5cdb': 'b3fde273b7a505aeaa7bc00dfccce35a694d154151c38f6651cf91bd0bb8a55f', '214852f84ff083e9fa3b2a39b5e4aeab07b8f365c005a052b3a08161ce8dafc2': 'ef7435d3f80aaf0d46db031c286fbe60a3a8b5bbcdda82b30532cc88177598ea', '55ac2293cda2d0a4b2b388334b05c7df383072f618fa1329c23a5df5cb163aee': 'e7037ab2739d9e7f570de670fb373222a65ccf09e6a7a28861ef3ce29d89a172', 'caea8bf76be7841f991b2b1c97cdb8d8f696e3c5f7af46b8b6bb48ff35bdcc88': '989070bae0721d329fee0ff67463fa4344b1f28830590e6b3239ae0e19736a03', 'b0d0d3c81676734ad55f56f19030673ed5cb1211861c3b97cbdeca476ce80aa7': 'd30194e551cee1ac46fb3c30893657ede89a5d0ed66dca7140d9589fe9a0a7b4', 'db1942a50647e20de2badb00fd76a0b2c15bbf0597ff43de1022645b531c769c': '0e0672df5cb7231041a0865ac97ae08686eda7445abdc408c7268df2bb8dbe4c'}
FINGERPRINTS = frozenset(COMPILED_SCREENS)


def eligible(session):
    """Match the host's validated source, not a title or an arbitrary Mod."""
    if (session.get("launchMode") != "enhanced" or session.get("runtimeID") != "8.5.3"
            or session.get("verifiedBuiltinPatchID") != PATCH_ID
            or session.get("verifiedContentFingerprint") not in FINGERPRINTS
            or "engineOverlaySHA256" not in session or session.get("engineOverlaySHA256") is not None):
        return False
    game = session.get("gameDirectory")
    if not isinstance(game, str) or not os.path.isabs(game):
        return False
    path = os.path.join(game, "screens.rpyc")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
                return False
            with os.fdopen(fd, "rb") as source:
                fd = -1
                return hashlib.sha256(source.read(8 * 1024 * 1024 + 1)).hexdigest() == COMPILED_SCREENS[session["verifiedContentFingerprint"]]
        finally:
            if fd >= 0:
                os.close(fd)
    except (IOError, OSError):
        return False


class MenuPreparation(object):
    """Run the SDK's normal layout setup during this title's init phase."""
    def __init__(self, renpy):
        self.renpy = renpy
        self.registry = renpy.game.post_init
        self.applied = False
        self.closed = False
        self.callback = self.apply
        self.registry.append(self.callback)

    def apply(self):
        if self.closed or self.applied:
            raise RuntimeError("Story menu initialization was repeated")
        if not all(self.renpy.exports.has_screen(name) for name in ("main_menu", "save", "load")):
            raise RuntimeError("The verified story's menu screens are unavailable")
        # This is the same SDK API used by the current authored stories. It
        # loads stock menu labels before analysis and clean-store capture.
        self.renpy.store.layout.defaults()
        if not self.renpy.exports.has_label("main_menu_screen") or self.renpy.store._game_menu_screen is None:
            raise RuntimeError("The verified story's native menus were not initialized")
        self.applied = True

    def close(self):
        if self.closed:
            return
        if self.renpy.game.post_init is not self.registry or self.registry.count(self.callback) != 1:
            raise RuntimeError("Story menu initialization ownership changed")
        self.registry.remove(self.callback)
        self.closed = True
        # Stock labels and layout state belong to Ren'Py and are discarded by
        # the host's existing reload_all, after this owned callback is removed.


def prepare_menus(renpy, session):
    return MenuPreparation(renpy) if eligible(session) else None


class Lease(object):
    def __init__(self, renpy):
        self.renpy = renpy
        self.file_load = renpy.store.FileLoad
        self.original_init = self.file_load.__init__
        self.original_can_load = renpy.can_load
        self.closed = False
        if not isinstance(self.file_load, type) or not callable(self.original_can_load):
            raise RuntimeError("The stock FileLoad API is unavailable")
        original_init = self.original_init
        original_can_load = self.original_can_load
        file_load = self.file_load
        if getattr(original_can_load, "_rr_story_patch_owner", None) is not None:
            raise RuntimeError("A story patch lease is already active")

        def from_screen(line):
            # SL2 expressions compile with their source location. Restrict the
            # adapter to the exact calls in the verified shipped screen; an
            # explicit slot="1" elsewhere must retain Ren'Py's stock behavior.
            frame = sys._getframe(2)
            filename = frame.f_code.co_filename.replace("\\", "/")
            return (filename == "game/screens.rpy" or filename.endswith("/game/screens.rpy")) and frame.f_lineno == line

        def patched_init(action, name, *args, **kwargs):
            # Only the exact main-menu call is special; explicit page, slot,
            # confirmation and all other authored calls retain their semantics.
            if name == "quick" and not args and not kwargs and from_screen(56):
                return original_init(action, "quick-1", slot=True)
            return original_init(action, name, *args, **kwargs)

        def patched_can_load(name, *args, **kwargs):
            if not args and not kwargs:
                if name == "quick" and from_screen(55):
                    return original_can_load("quick-1")
                if name in ("1", "2", "3", "4") and from_screen(104):
                    return file_load(name).get_sensitive()
            return original_can_load(name, *args, **kwargs)

        self.patched_init = patched_init
        self.patched_can_load = patched_can_load
        patched_can_load._rr_story_patch_owner = self
        self.file_load.__init__ = patched_init
        try:
            self.renpy.can_load = patched_can_load
        except Exception:
            self.file_load.__init__ = original_init
            raise

    def close(self):
        if self.closed:
            return
        # Do not overwrite a later author/engine mutation or leave half a hook.
        # The host must quarantine this runtime if an ownership check fails.
        if self.file_load.__init__ is not self.patched_init or self.renpy.can_load is not self.patched_can_load:
            raise RuntimeError("Story patch ownership changed before cleanup")
        self.file_load.__init__ = self.original_init
        self.renpy.can_load = self.original_can_load
        self.closed = True


def install(renpy, session):
    return Lease(renpy) if eligible(session) else None
