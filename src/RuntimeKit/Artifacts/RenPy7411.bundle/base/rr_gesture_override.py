# -*- coding: utf-8 -*-
"""Session-owned override-all gestures on the unchanged stock host.

Candidate software only. The resource manifest pins all 17 official SDK finish
bodies; neither this module nor its capability grants native qualification.
"""
from __future__ import absolute_import, division, print_function, unicode_literals
try:
    import _thread as _threading
except ImportError:
    import thread as _threading
try:
    _ints, _texts = (int, long), (str, unicode)
except NameError:
    _ints, _texts = (int,), (str,)

_active = None
_retained = None
renpy = None
_directions = frozenset(('n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw'))


class GestureOverrideError(RuntimeError):
    pass


def _owner():
    if _active is None or not _active.owns():
        raise GestureOverrideError('No current session owns the gesture adapter')
    return _active


def _function(value):
    return getattr(value, '__func__', getattr(value, 'im_func', value))


# Exact official GestureRecognizer.finish body, apart from its top-level name.
# In particular None does not end an interaction. Do not use a game wrapper as
# this fallback: a later game wrapper may itself retain our _finish callback.
def _stock_finish(self):
    rv = None

    if self.x is None:
        return

    if self.strokes:
        func = renpy.config.dispatch_gesture

        if func is None:
            func = dispatch_gesture

        rv = func("_".join(self.strokes))

    self.x = None
    self.y = None

    return rv


def dispatch_gesture(direction):
    # The stock body's module-global dispatch fallback, not a captured game hook.
    return renpy.display.gesture.dispatch_gesture(direction)


def _finish(recognizer):
    owner = _owner()
    if not isinstance(recognizer, owner.recognizer):
        raise GestureOverrideError('The gesture recognizer belongs to another engine')
    stamp = getattr(recognizer, '_rr_gesture_session', None)
    if stamp is not None and stamp != (owner.session_id, owner.epoch):
        raise GestureOverrideError('The gesture recognizer belongs to a retired session')
    recognizer._rr_gesture_session = (owner.session_id, owner.epoch)
    if not owner.enabled():
        return _stock_finish(recognizer)
    if recognizer.x is None:
        return
    try:
        direction = '_'.join(recognizer.strokes)
        bindings = owner.host._gesture_bindings
        if direction in _directions and direction in bindings:
            return owner.original_gesture_dispatch(direction)
        return None
    finally:
        recognizer.x = recognizer.y = None


def _sync():
    owner = _active
    if owner is None or not owner.current():
        raise GestureOverrideError('A retired gesture sync callback was called')
    result = owner.original_sync()
    owner.sync_finish()
    return result


def _next_base(*args, **kwargs):
    owner = _owner()
    result = owner.original_base(*args, **kwargs)
    always = kwargs.get('always', args[1] if len(args) > 1 else False)
    if not always:
        owner.before_init()
    return result


def _post_init():
    owner = _owner()
    registry = owner.renpy.config.interact_callbacks
    if _interaction not in registry:
        registry.append(_interaction)
        owner.callbacks.append((registry, _interaction))
    owner.sync_finish()


def _interaction():
    return _sync()


def _capabilities():
    owner = _active
    if owner is None or not owner.current():
        raise GestureOverrideError('A retired gesture capability callback was called')
    result = dict(owner.original_capabilities())
    result['gestureOverrideAllV1'] = owner.supported(result)
    return result


def _emit(kind, *args, **kwargs):
    owner = _active
    if owner is None:
        raise GestureOverrideError('A retired gesture observer was called')
    commit = False
    if kind == 'readingPreferences' and owner.owns():
        request_id = args[0] if args else kwargs.get('request_id')
        commit = owner.pending is not None and request_id == owner.pending[0]
        kwargs = dict(kwargs)
        kwargs['overrideAllGestures'] = owner.pending[1] if commit else owner.override
    result = owner.original_emit(kind, *args, **kwargs)
    # The original dispatcher has validated/applied its entire legacy payload
    # before this successful readback. Rejected old keys never commit our flag.
    if commit:
        owner.override = owner.pending[1]
        owner.pending = None
        owner.sync_finish()
    if kind == 'didReset':
        owner.reset = owner.owns()
    elif kind in ('quarantined', 'error'):
        owner.quarantined = True
    return result


def _dispatch(request):
    owner = _active
    if owner is None or not owner.current():
        raise GestureOverrideError('A retired gesture dispatcher was called')
    if type(request) is not dict or request.get('type') != 'setPreferences':
        return owner.original_dispatch(request)
    payload = request.get('payload')
    if type(payload) is not dict:
        raise GestureOverrideError('Runtime preferences must be an object')
    if 'overrideAllGestures' not in payload and 'gestureBindings' not in payload:
        return owner.original_dispatch(request)
    if not owner.owns():
        raise GestureOverrideError('The gesture session is quarantined')
    owner.validate_request(request)
    if owner.pending is not None:
        raise GestureOverrideError('A gesture preference update is already pending')
    desired = payload.get('overrideAllGestures', False)
    if type(desired) is not bool:
        raise GestureOverrideError('overrideAllGestures must be a boolean')
    if desired and ('gestureBindings' not in payload or type(payload['gestureBindings']) is not dict
                    or not owner.supported(owner.original_capabilities())):
        raise GestureOverrideError('Override-all gestures require available enhanced gesture bindings')
    clean = dict(request)
    clean['payload'] = dict(payload)
    clean['payload'].pop('overrideAllGestures', None)
    owner.pending = (request['requestID'], desired)
    try:
        result = owner.original_dispatch(clean)
        if owner.pending is not None:
            raise GestureOverrideError('The host did not acknowledge gesture preferences')
        return result
    finally:
        owner.pending = None


class Session(object):
    def __init__(self, session, host):
        global _active
        if (_active is not None or _retained is not None or type(session) is not dict
                or host._session is not session or type(session.get('sessionID')) not in _texts
                or not session['sessionID'] or type(session.get('epoch')) not in _ints):
            raise GestureOverrideError('A gesture adapter owner has not quiescently reset')
        self.session, self.host = session, host
        self.session_id, self.epoch = session['sessionID'], session['epoch']
        self.thread = _threading.get_ident()
        self.override = self.reset = self.quarantined = self.closed = False
        self.pending = None
        self.renpy = self.recognizer = self.restore_finish = self.stock_finish = None
        self.callbacks = []
        self.original_emit = host.emit
        self.original_capabilities = host.session_capabilities
        self.original_base = host._next_base
        self.original_sync = host._sync_gesture_hook
        self.original_dispatch = host._dispatch
        self.original_gesture_dispatch = host._dispatch_gesture
        self.patches = ((host, 'emit', self.original_emit, _emit),
                        (host, 'session_capabilities', self.original_capabilities, _capabilities),
                        (host, '_next_base', self.original_base, _next_base),
                        (host, '_sync_gesture_hook', self.original_sync, _sync),
                        (host, '_dispatch', self.original_dispatch, _dispatch))
        _active = self
        for target, name, original, replacement in self.patches:
            setattr(target, name, replacement)
        self.event('gestureOverrideAllInstalled', 'installed')

    def current(self):
        return (_active is self and not self.closed
                and _threading.get_ident() == self.thread and self.host._session is self.session
                and type(self.session.get('sessionID')) in _texts and self.session['sessionID'] == self.session_id
                and type(self.session.get('epoch')) in _ints and self.session['epoch'] == self.epoch)

    def owns(self):
        return self.current() and not self.quarantined

    def supported(self, capabilities):
        return (self.owns() and self.session.get('launchMode', 'enhanced') == 'enhanced'
                and self.host.enhancements_enabled()
                and capabilities.get('preferences') is True and capabilities.get('gestures') is True
                and self.recognizer is not None
                and self.renpy.display.gesture.GestureRecognizer is self.recognizer)

    def enabled(self):
        return self.override and self.supported(self.original_capabilities()) and self.host._gesture_bindings is not None

    def validate_request(self, request):
        if (set(request) != set(('schemaVersion', 'sessionID', 'epoch', 'requestID', 'type', 'payload'))
                or type(request['schemaVersion']) not in _ints or request['schemaVersion'] != 1
                or type(request['sessionID']) not in _texts or request['sessionID'] != self.session_id
                or type(request['epoch']) not in _ints or request['epoch'] != self.epoch
                or type(request['requestID']) not in _texts or not 1 <= len(request['requestID']) <= 128):
            raise GestureOverrideError('The gesture preference packet has a stale or invalid owner')

    def before_init(self):
        global renpy
        import renpy as engine
        self.restore_stock_class()
        self.renpy = renpy = engine
        self.recognizer = engine.display.gesture.GestureRecognizer
        self.stock_finish = self.restore_finish = _function(self.recognizer.finish)
        registry = engine.game.post_init
        if _post_init not in registry:
            registry.append(_post_init)
            self.callbacks.append((registry, _post_init))

    def restore_class(self):
        if self.recognizer is not None and self.recognizer.__dict__.get('finish') is _finish:
            self.recognizer.finish = self.restore_finish

    def restore_stock_class(self):
        # Official Backup restores class globals by reference, not their method
        # dictionaries. After SDK reload (before init or after didReset), a title
        # finish wrapper must not carry its captured owner into the next title.
        if (self.recognizer is not None and self.stock_finish is not None
                and self.renpy.display.gesture.GestureRecognizer is self.recognizer):
            self.recognizer.finish = self.stock_finish
        else:
            self.restore_class()

    def sync_finish(self):
        if self.enabled():
            current = _function(self.recognizer.finish)
            if current is not _finish:
                self.restore_finish = current
                self.recognizer.finish = _finish
        else:
            self.restore_class()

    def event(self, kind, state):
        self.original_emit(kind, schemaVersion=1, sessionID=self.session_id, epoch=self.epoch,
                           state=state, quarantined=bool(self.quarantined), didReset=bool(self.reset))

    def finish(self):
        global _active, _retained, renpy
        if self.closed:
            return
        if _active is not self or _threading.get_ident() != self.thread:
            raise GestureOverrideError('A different owner attempted gesture cleanup')
        if self.host._session is not None and not self.current():
            raise GestureOverrideError('A retired owner attempted gesture cleanup')
        if not self.reset or self.quarantined:
            _retained = self
            self.event('gestureOverrideAllRetained', 'quarantined')
            return
        self.restore_stock_class()
        for registry, callback in self.callbacks:
            if callback in registry:
                registry.remove(callback)
        for target, name, original, replacement in reversed(self.patches):
            if target.__dict__.get(name) is replacement:
                setattr(target, name, original)
        self.closed = True
        self.event('gestureOverrideAllClosed', 'closed')
        self.pending = None
        self.callbacks = []
        self.renpy = self.recognizer = self.restore_finish = self.stock_finish = None
        renpy = _active = None
