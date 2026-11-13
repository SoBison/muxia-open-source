# -*- coding: utf-8 -*-
"""Candidate session-owned iosVibrate bridge. Python 2.7 and 3 compatible."""
import math
import threading
import time

try:
    _integers = (int, long)
except NameError:
    _integers = (int,)


def _number(value, lower, upper):
    if type(value) not in _integers + (float,):
        return False
    try:
        return not math.isnan(value) and not math.isinf(value) and lower <= value <= upper
    except (OverflowError, ValueError, TypeError):
        return False


class GameHaptics(object):
    def __init__(self, store, session_id, epoch, emit, allowed, clock=None):
        if len(session_id) != 36 or type(epoch) not in _integers or not 0 < epoch < 2 ** 64:
            raise ValueError("Invalid haptic session")
        self.store = store
        self.session_id = session_id
        self.epoch = epoch
        self.emit = emit
        self.allowed = allowed
        self.clock = clock or getattr(time, "monotonic", time.time)
        self.owner_thread = threading.current_thread().ident
        self.last = None
        self.installed = False

        self.function = self
        # An existing title-defined bridge remains the title's own function.
        if not hasattr(store, "iosVibrate"):
            global _active
            if _active is not None:
                raise RuntimeError("A preceding haptic bridge still owns its session")
            store.iosVibrate = self
            self.installed = True
            _active = self

    def __call__(self, duration=0.1, intensity=1.0, sharpness=0.5):
        # This reports enqueueing, never the existence of a physical motor.
        if (not self.installed or getattr(self.store, "iosVibrate", None) is not self
                or threading.current_thread().ident != self.owner_thread or not self.allowed()
                or not _number(duration, 0.01, 2.0) or not _number(intensity, 0.0, 1.0)
                or not _number(sharpness, 0.0, 1.0)):
            return False
        now = self.clock()
        if not _number(now, 0.0, 1e15) or (self.last is not None and now < self.last + 0.05):
            return False
        self.last = now
        self.emit("deviceVibration", hapticRequest={"schemaVersion": 1, "sessionID": self.session_id,
            "epoch": self.epoch, "duration": duration, "intensity": intensity, "sharpness": sharpness})
        return True

    def __reduce__(self):
        # Never persist store/emit/closures or a stale epoch in a Ren'Py save.
        # Loading an authorized save rebinds this value to its current session.
        return (_current_vibrator, ())

    def close(self):
        global _active
        self.installed = False
        if _active is self:
            _active = None
        if getattr(self.store, "iosVibrate", None) is self.function:
            delattr(self.store, "iosVibrate")


_active = None

class _InactiveVibrator(object):
    def __call__(self, *args, **kwargs):
        return False

    def __reduce__(self):
        return (_current_vibrator, ())


_inactive_vibrator = _InactiveVibrator()


def _current_vibrator():
    if _active is None or not _active.installed:
        # A save created with enhancements must remain loadable in native
        # compatibility mode, where no vibration bridge is installed.
        return _inactive_vibrator
    return _active
