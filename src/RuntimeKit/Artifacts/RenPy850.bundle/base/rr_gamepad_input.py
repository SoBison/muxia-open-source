"""Session-local digital-button mappings over the existing Ren'Py controller path.

Candidate only. The caller supplies an owner-thread physical-button snapshot and
an input-allowed predicate. This does not isolate unbound/raw controller input.
"""
from __future__ import unicode_literals

try:
    _text_types = (basestring,)
    _integer_types = (int, long)
except NameError:
    _text_types = (str,)
    _integer_types = (int,)

BUTTONS = frozenset(("a", "b", "x", "y", "back", "guide", "start", "leftstick",
                     "rightstick", "leftshoulder", "rightshoulder", "dpup", "dpdown", "dpleft", "dpright"))
ACTIONS = frozenset(("quickSave", "quickLoad", "rollback", "toggleAuto", "toggleSkip",
                     "history", "showTools", "preferences", "hideInterface", "gameMenu"))
_MARKER = "RenReader.gamepad.mapping.v1"


class GamepadMapping(object):
    def __init__(self, controller, pygame, event_type, session_id, epoch, mode,
                 physical_buttons, input_allowed, dispatch, input_generation=None):
        if (not isinstance(session_id, _text_types) or not session_id or
                type(epoch) not in _integer_types or epoch < 1 or
                mode not in ("enhanced", "minimal", "nativeCompatibility")):
            raise ValueError("Invalid gamepad session")
        if mode != "nativeCompatibility" and not callable(input_generation):
            raise ValueError("Gamepad mapping requires an input ownership generation")
        self.controller = controller
        self.pygame = pygame
        self.event_type = event_type
        self.session_id = session_id
        self.epoch = epoch
        self.mode = mode
        self.physical_buttons = physical_buttons
        self.input_allowed = input_allowed
        self.input_generation = input_generation
        self.dispatch = dispatch
        self.original_event = controller.event
        self.original_post = controller.post_event
        self.bindings = None
        self.pending = None
        self.has_pending = False
        self.generation = 0
        self.owned = set()
        self.seen_down = set()
        self.quarantined = set()
        self.instance_epochs = {}
        self.next_instance_epoch = 0
        self.context = None
        self.closed = False
        self._event_wrapper = self.event
        self._post_wrapper = self.post_event
        self.installed = mode != "nativeCompatibility"
        if self.installed:
            controller.event = self._event_wrapper
            controller.post_event = self._post_wrapper

    def _snapshot(self):
        value = self.physical_buttons()
        if type(value) is not dict:
            raise ValueError("Physical controller snapshot must be a dictionary")
        result = set()
        for instance, buttons in value.items():
            if type(instance) not in _integer_types or instance < 0 or type(buttons) not in (list, tuple, set, frozenset):
                raise ValueError("Invalid physical controller snapshot")
            for button in buttons:
                if not isinstance(button, _text_types) or button not in BUTTONS:
                    raise ValueError("Invalid physical controller button")
                result.add((instance, button))
        return result

    def configure(self, session_id, epoch, bindings):
        if (self.closed or not isinstance(session_id, _text_types) or
                type(epoch) not in _integer_types or session_id != self.session_id or epoch != self.epoch):
            raise ValueError("Stale gamepad configuration")
        if bindings is not None:
            if type(bindings) is not dict or len(bindings) > len(BUTTONS):
                raise ValueError("Invalid gamepad bindings")
            for button, action in bindings.items():
                if (not isinstance(button, _text_types) or not isinstance(action, _text_types) or
                        button not in BUTTONS or action not in ACTIONS):
                    raise ValueError("Unsupported gamepad binding")
            bindings = dict(bindings)
        if self.mode == "nativeCompatibility":
            self.bindings = None
            self.pending = None
            self.has_pending = False
            return
        if bindings == self.bindings:
            self.pending = None
            self.has_pending = False
            return
        self.pending = bindings
        self.has_pending = True
        self._apply_pending()

    def _apply_pending(self):
        if not self.has_pending or self.seen_down or self._snapshot():
            return
        self.bindings = self.pending
        self.pending = None
        self.has_pending = False
        self.generation += 1
        self.owned.clear()
        self.quarantined.clear()

    def _allowed(self):
        interface = self.controller.renpy.display.interface
        return bool(interface is not None and interface.keyboard_focused and
                    not self.controller.ignore and self.input_allowed())

    def _input_generation(self):
        generation = self.input_generation()
        return generation if type(generation) in _integer_types and generation >= 0 else None

    def _allowed_generation(self):
        # Capture ownership before permission checks. A complete close/open
        # during those checks must not stamp an older edge with the new owner.
        generation = self._input_generation()
        if generation is None or not self._allowed() or self._input_generation() != generation:
            return None
        return generation

    def event(self, event):
        if event.type == self.event_type and getattr(event, "rr_gamepad_marker", None) == _MARKER:
            button = getattr(event, "rr_button", None)
            action = getattr(event, "rr_action", None)
            if (not self.closed and self.mode != "nativeCompatibility" and
                    getattr(event, "rr_session", None) == self.session_id and
                    type(getattr(event, "rr_epoch", None)) in _integer_types and
                    getattr(event, "rr_epoch", None) == self.epoch and
                    type(getattr(event, "rr_generation", None)) in _integer_types and
                    getattr(event, "rr_generation", None) == self.generation and
                    isinstance(button, _text_types) and isinstance(action, _text_types) and action in ACTIONS and
                    self.bindings is not None and
                    self.bindings.get(button) == action and
                    type(getattr(event, "rr_gate_generation", None)) in _integer_types and
                    getattr(event, "rr_gate_generation", None) == self._allowed_generation() and
                    type(getattr(event, "rr_instance", None)) in _integer_types and
                    type(getattr(event, "rr_instance_epoch", None)) in _integer_types and
                    getattr(event, "rr_instance_epoch", None) == self.instance_epochs.get(event.rr_instance)):
                # Runs at the ordinary controller-event interaction point, never
                # while constructing/repeating an event. Control exceptions pass.
                self.dispatch(event.rr_action, event.rr_button, event.rr_gate_generation)
            return None
        if self.closed or self.mode == "nativeCompatibility":
            return self.original_event(event)
        down, up = self.pygame.CONTROLLERBUTTONDOWN, self.pygame.CONTROLLERBUTTONUP
        context = None
        if event.type in (down, up):
            if event.which not in self.instance_epochs:
                self.next_instance_epoch += 1
                self.instance_epochs[event.which] = self.next_instance_epoch
            button = self.controller.get_string_for_button(event.button)
            pair = (event.which, button)
            if event.type == down and button in BUTTONS:
                self.seen_down.add(pair)
            context = {"instance": event.which, "suppressed": False, "pair": pair}
        previous = self.context
        self.context = context
        try:
            result = self.original_event(event)
        finally:
            self.context = previous
        if event.type == up:
            self.seen_down.discard(context["pair"])
            self._apply_pending()
        if event.type == self.pygame.CONTROLLERDEVICEADDED and (self.bindings or self.has_pending):
            self.next_instance_epoch += 1
            self.instance_epochs[event.which] = self.next_instance_epoch
            # SDL may report an already held button when a controller opens.
            self.quarantined.update(self._snapshot())
        elif event.type == self.pygame.CONTROLLERDEVICEREMOVED:
            self.instance_epochs.pop(event.which, None)
            self.owned = set(pair for pair in self.owned if pair[0] != event.which)
            self.seen_down = set(pair for pair in self.seen_down if pair[0] != event.which)
            self.quarantined = set(pair for pair in self.quarantined if pair[0] != event.which)
            self._apply_pending()
        return None if context is not None and context["suppressed"] else result

    def post_event(self, control, state, repeat):
        if self.closed or self.mode == "nativeCompatibility" or control not in BUTTONS:
            return self.original_post(control, state, repeat)
        if state not in ("press", "release"):
            return self.original_post(control, state, repeat)
        context = self.context
        pair = (context["instance"], control) if context is not None else None
        action = self.bindings.get(control) if self.bindings is not None else None
        owns = pair in self.owned if pair is not None else False
        consume = action is not None or owns
        if not consume:
            result = self.original_post(control, state, repeat)
            if not repeat and state == "release":
                self._apply_pending()
            return result
        if context is not None:
            context["suppressed"] = True
        if repeat:
            return None
        if pair is None:
            # No raw controller instance: never manufacture a host button edge.
            return None
        if state == "release":
            self.owned.discard(pair)
            self.quarantined.discard(pair)
            self._apply_pending()
            return None
        first_down = pair not in self.owned
        self.owned.add(pair)
        if first_down and pair not in self.quarantined:
            gate_generation = self._allowed_generation()
            if gate_generation is None:
                return None
            event = self.pygame.event.Event(self.event_type, {
                "eventnames": [], "up": False,
                "rr_gamepad_marker": _MARKER, "rr_session": self.session_id,
                "rr_epoch": self.epoch, "rr_generation": self.generation,
                "rr_gate_generation": gate_generation,
                "rr_button": control, "rr_action": action, "rr_instance": pair[0],
                "rr_instance_epoch": self.instance_epochs[pair[0]]})
            # Respect the engine/author event filter and bounded SDL queue.
            self.pygame.event.post(event)
        return None

    def state(self):
        return {"schemaVersion": 1, "sessionID": self.session_id, "epoch": self.epoch,
                "bindings": dict(self.bindings) if self.bindings is not None else None,
                "pending": self.has_pending, "generation": self.generation,
                "ownedButtons": len(self.owned), "closed": self.closed}

    def close(self):
        self.closed = True
        event_owned = not self.installed or self.controller.event is self._event_wrapper
        post_owned = not self.installed or self.controller.post_event is self._post_wrapper
        if self.installed and event_owned:
            self.controller.event = self.original_event
        if self.installed and post_owned:
            self.controller.post_event = self.original_post
        self.bindings = None
        self.pending = None
        self.has_pending = False
        self.owned.clear()
        self.seen_down.clear()
        self.quarantined.clear()
        self.instance_epochs.clear()
        self.dispatch = None
        self.physical_buttons = None
        self.input_allowed = None
        self.input_generation = None
        return event_owned and post_owned
