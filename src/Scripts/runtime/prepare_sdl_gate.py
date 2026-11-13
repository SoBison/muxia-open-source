#!/usr/bin/env python3
"""Patch exact SDL2.0.20 input objects; keep every other official object."""
from pathlib import Path
import difflib
import hashlib
import shutil


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Inspect exact SDL2.0.20 input hook: " + old[:90])
    return text.replace(old, new, 1)


def wrap(text, start, end, name, wrapper):
    first = text.index(start)
    last = text.index(end, first)
    body = text[first:last]
    body = once(body, name + "(", "RRSDL_" + name + "(")
    if not body.startswith("static "):
        body = "static " + body
    return text[:first] + body + wrapper + "\n\n" + text[last:]


def prepare(source, output):
    source, output = Path(source), Path(output)
    if not (source / "include/SDL_version.h").is_file():
        raise ValueError("Supply the already obtained official release-2.0.20 source tree")
    shutil.copytree(source, output, dirs_exist_ok=True)
    headers = '#include "RRInputGate.h"\n#include "RRAuxiliaryInput.h"\n'
    keyboard = output / "src/events/SDL_keyboard.c"
    text = keyboard.read_text()
    text = once(text, '#include "../SDL_internal.h"\n', '#include "../SDL_internal.h"\n' + headers)
    text = once(text, '        keyboard->keysource[scancode] = 0;\n', '''        /* Preserve hardware/autorelease when the host source releases, and
         * preserve the host source when a hardware release arrives first. */
        if (source == RR_AUX_KEY_SOURCE || (keyboard->keysource[scancode] & RR_AUX_KEY_SOURCE)) {
            if (!(keyboard->keysource[scancode] & source)) return 0;
            keyboard->keysource[scancode] &= ~source;
            if (keyboard->keysource[scancode]) return 0;
        } else keyboard->keysource[scancode] = 0;
''')
    text = once(text, '        event.key.keysym.mod = keyboard->modstate;\n', '        event.key.keysym.mod = keyboard->modstate;\n        event.key.keysym.unused = source == RR_AUX_KEY_SOURCE ? RR_AUX_KEY_MARKER : 0;\n')
    text = once(text, '    SDL_Keyboard *keyboard = &SDL_keyboard;\n\n    if (keyboard->focus && !window)',
                '    SDL_Keyboard *keyboard = &SDL_keyboard;\n\n    RRAuxiliaryFocusChanged(window ? window->id : 0);\n    if (keyboard->focus && !window)')
    text = wrap(text, 'static int\nSDL_SendKeyboardKeyInternal(', '\nint\nSDL_SendKeyboardKey(', 'SDL_SendKeyboardKeyInternal', '''
static int
SDL_SendKeyboardKeyInternal(Uint8 source, Uint8 state, SDL_Scancode scancode)
{
    int result;
    if (!RRInputGateEnterKey(source, state, scancode)) return 0;
    result = RRSDL_SDL_SendKeyboardKeyInternal(source, state, scancode);
    RRInputGateLeave();
    return result;
}

/* Source-owned state reset: no private structure is borrowed by the host. */
void RRSDL_ClearKeyboardState(Uint16 lock_modifiers)
{
    SDL_memset(SDL_keyboard.keystate, 0, sizeof(SDL_keyboard.keystate));
    SDL_memset(SDL_keyboard.keysource, 0, sizeof(SDL_keyboard.keysource));
    SDL_keyboard.modstate = lock_modifiers;
    SDL_keyboard.autorelease_pending = SDL_FALSE;
}

int RRSDL_SendAuxiliaryKey(Uint8 state, SDL_Scancode scancode)
{
    return SDL_SendKeyboardKeyInternal(RR_AUX_KEY_SOURCE, state, scancode);
}

void RRSDL_ClearAuxiliaryKeyboardSource(Uint8 released[SDL_NUM_SCANCODES])
{
    int scan;
    SDL_memset(released, 0, SDL_NUM_SCANCODES);
    for (scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
        if (!(SDL_keyboard.keysource[scan] & RR_AUX_KEY_SOURCE)) continue;
        SDL_keyboard.keysource[scan] &= ~RR_AUX_KEY_SOURCE;
        if (SDL_keyboard.keysource[scan]) continue;
        released[scan] = SDL_keyboard.keystate[scan] != 0;
        SDL_keyboard.keystate[scan] = 0;
        switch (SDL_keyboard.keymap[scan]) {
            case SDLK_LCTRL: SDL_keyboard.modstate &= ~KMOD_LCTRL; break;
            case SDLK_LSHIFT: SDL_keyboard.modstate &= ~KMOD_LSHIFT; break;
            case SDLK_LALT: SDL_keyboard.modstate &= ~KMOD_LALT; break;
        }
    }
}
''')
    text = wrap(text, 'int\nSDL_SendKeyboardText(', '\nint\nSDL_SendEditingText(', 'SDL_SendKeyboardText', '''
int SDL_SendKeyboardText(const char *text)
{
    int result;
    if (!RRInputGateEnterText()) return 0;
    result = RRSDL_SDL_SendKeyboardText(text);
    RRInputGateLeave();
    return result;
}
''')
    text = wrap(text, 'int\nSDL_SendEditingText(', '\nconst Uint8 *\nSDL_GetKeyboardState(', 'SDL_SendEditingText', '''
int SDL_SendEditingText(const char *text, int start, int length)
{
    int result;
    if (!RRInputGateEnterText()) return 0;
    result = RRSDL_SDL_SendEditingText(text, start, length);
    RRInputGateLeave();
    return result;
}
''')
    keyboard.write_text(text)
    events = output / "src/events/SDL_events.c"
    text = events.read_text()
    text = once(text, '#include "../SDL_internal.h"\n', '#include "../SDL_internal.h"\n' + headers)
    text = once(text, 'if (action == SDL_GETEVENT) {\n                            SDL_CutEvent(entry);', 'if (action == SDL_GETEVENT) {\n                            RRInputGateDidDeliver(&entry->event);\n                            SDL_CutEvent(entry);')
    text = once(text, 'SDL_CutEvent(SDL_EventEntry *entry)\n{\n', 'SDL_CutEvent(SDL_EventEntry *entry)\n{\n    RRInputGateDidRemove(&entry->event);\n')
    # All producers take gate -> watcher -> queue. GET bookkeeping remains
    # atomic under the queue lock and never takes the gate in reverse order.
    text = once(text, 'used += SDL_AddEvent(&events[i]);', '''int admission = RRInputGateEnterPost(&events[i]);
                if (admission) used += SDL_AddEvent(&events[i]);
                if (admission == 2) RRInputGateLeave();''')
    text = wrap(text, 'static int\nSDL_PeepEventsInternal(', '\nint\nSDL_PeepEvents(', 'SDL_PeepEventsInternal', '''
static int SDL_PeepEventsInternal(SDL_Event *events, int numevents, SDL_eventaction action,
                                  Uint32 minType, Uint32 maxType, SDL_bool include_sentinel)
{
    int result;
    if (action == SDL_ADDEVENT) RRInputGateLock();
    result = RRSDL_SDL_PeepEventsInternal(events, numevents, action, minType, maxType, include_sentinel);
    if (action == SDL_ADDEVENT) RRInputGateLeave();
    return result;
}
''')
    text = wrap(text, 'int\nSDL_PushEvent(', '\nvoid\nSDL_SetEventFilter(', 'SDL_PushEvent', '''
int SDL_PushEvent(SDL_Event *event)
{
    int result, admission = RRInputGateEnterPost(event);
    SDL_Event submitted;
    if (!admission) return 0;
    submitted = *event;
    result = RRSDL_SDL_PushEvent(event);
    RRInputGateDidPost(&submitted, result);
    if (admission == 2) RRInputGateLeave();
    return result;
}
''')
    text = wrap(text, 'void\nSDL_FilterEvents(', '\nUint8\nSDL_EventState(', 'SDL_FilterEvents', '''
void SDL_FilterEvents(SDL_EventFilter filter, void *userdata)
{
    RRInputGateLock();
    RRSDL_SDL_FilterEvents(filter, userdata);
    RRInputGateLeave();
}
''')
    events.write_text(text)
    mouse = output / 'src/events/SDL_mouse.c'
    text = mouse.read_text()
    text = once(text, '#include "../SDL_internal.h"\n', '#include "../SDL_internal.h"\n' + headers)
    text = once(text, 'static SDL_Mouse SDL_mouse;\n', 'static SDL_Mouse SDL_mouse;\nstatic float rr_aux_wheel_x, rr_aux_wheel_y;\n')
    # Never change global hints or synthesize a second finger stream for the
    # host's independent pointer source. Other mouse/touch sources are intact.
    text = once(text, 'if (mouseID != SDL_TOUCH_MOUSEID && !relative && track_mouse_down)', 'if (mouseID != SDL_TOUCH_MOUSEID && mouseID != RR_AUX_MOUSE_ID && !relative && track_mouse_down)')
    text = once(text, 'if (mouseID != SDL_TOUCH_MOUSEID && button == SDL_BUTTON_LEFT)', 'if (mouseID != SDL_TOUCH_MOUSEID && mouseID != RR_AUX_MOUSE_ID && button == SDL_BUTTON_LEFT)')
    text = once(text, '        event.button.clicks = (Uint8) SDL_min(clicks, 255);\n', '        event.button.clicks = (Uint8) SDL_min(clicks, 255);\n        event.button.padding1 = 0;\n')
    text = wrap(text, 'int\nSDL_SendMouseMotion(', '\nstatic SDL_MouseInputSource', 'SDL_SendMouseMotion', '''
int SDL_SendMouseMotion(SDL_Window *window, SDL_MouseID mouseID, int relative, int x, int y)
{
    RRInputGateStats gate;
    int result;
    RRInputGateLock();
    RRInputGateCopyStats(&gate);
    /* SDL_UpdateMouseFocus otherwise emits the first synthetic motion with
     * the global hardware ID before the auxiliary source can emit its own. */
    if (mouseID == RR_AUX_MOUSE_ID && !gate.blocked) SDL_SetMouseFocus(window);
    result = (mouseID == RR_AUX_MOUSE_ID && gate.blocked) ? 0 : RRSDL_SDL_SendMouseMotion(window, mouseID, relative, x, y);
    RRInputGateLeave(); return result;
}
''')
    text = wrap(text, 'static int\nSDL_PrivateSendMouseButton(', '\nint\nSDL_SendMouseButtonClicks(', 'SDL_PrivateSendMouseButton', '''
static int SDL_PrivateSendMouseButton(SDL_Window *window, SDL_MouseID mouseID, Uint8 state, Uint8 button, int clicks)
{
    RRInputGateStats gate;
    int result;
    RRInputGateLock();
    RRInputGateCopyStats(&gate);
    if (mouseID == RR_AUX_MOUSE_ID && !gate.blocked) SDL_SetMouseFocus(window);
    result = (mouseID == RR_AUX_MOUSE_ID && gate.blocked) ? 0 : RRSDL_SDL_PrivateSendMouseButton(window, mouseID, state, button, clicks);
    RRInputGateLeave(); return result;
}
''')
    first = text.index('int\nSDL_SendMouseWheel(')
    last = text.index('\nvoid\nSDL_MouseQuit(', first)
    wheel = text[first:last]
    wheel = once(wheel, '    int integral_x, integral_y;\n', '''    int integral_x, integral_y;
    float *accumulated_x = mouseID == RR_AUX_MOUSE_ID ? &rr_aux_wheel_x : &mouse->accumulated_wheel_x;
    float *accumulated_y = mouseID == RR_AUX_MOUSE_ID ? &rr_aux_wheel_y : &mouse->accumulated_wheel_y;
''')
    # Replace only arithmetic references, preserving the pointer initializers.
    head, body = wheel.split('\n    if (window)', 1)
    body = body.replace('mouse->accumulated_wheel_x', '(*accumulated_x)').replace('mouse->accumulated_wheel_y', '(*accumulated_y)')
    text = text[:first] + head + '\n    if (window)' + body + text[last:]
    text = wrap(text, 'int\nSDL_SendMouseWheel(', '\nvoid\nSDL_MouseQuit(', 'SDL_SendMouseWheel', '''
int SDL_SendMouseWheel(SDL_Window *window, SDL_MouseID mouseID, float x, float y, SDL_MouseWheelDirection direction)
{
    RRInputGateStats gate;
    int result;
    RRInputGateLock();
    RRInputGateCopyStats(&gate);
    result = (mouseID == RR_AUX_MOUSE_ID && gate.blocked) ? 0 : RRSDL_SDL_SendMouseWheel(window, mouseID, x, y, direction);
    RRInputGateLeave(); return result;
}

void RRSDL_ClearAuxiliaryMouseSource(void)
{
    int i;
    rr_aux_wheel_x = rr_aux_wheel_y = 0;
    for (i = 0; i < SDL_mouse.num_sources; ++i)
        if (SDL_mouse.sources[i].mouseID == RR_AUX_MOUSE_ID) SDL_mouse.sources[i].buttonstate = 0;
}
''')
    mouse.write_text(text)
    video = output / 'src/video/SDL_video.c'
    text = video.read_text()
    text = once(text, '#include "../SDL_internal.h"\n', '#include "../SDL_internal.h"\n#include "RRAuxiliaryInput.h"\n')
    text = once(text, 'SDL_StartTextInput(void)\n{\n    SDL_Window *window;\n', 'SDL_StartTextInput(void)\n{\n    SDL_Window *window;\n    RRAuxiliaryTextInputChanged(1);\n')
    text = once(text, 'SDL_StopTextInput(void)\n{\n    SDL_Window *window;\n', 'SDL_StopTextInput(void)\n{\n    SDL_Window *window;\n    RRAuxiliaryTextInputChanged(0);\n')
    video.write_text(text)
    virtual = output / 'src/joystick/virtual/SDL_virtualjoystick.c'
    if hashlib.sha256(virtual.read_bytes()).hexdigest() != 'fa71809a115db088cd2bc86832d2c30e1638631c8a6e46b7251cc209d0e86356':
        raise ValueError('Inspect exact SDL2.0.20 virtual joystick source')
    text = once(virtual.read_text(), '    if (hwdata->axes) {\n', '''    /* An opened controller can outlive virtual-device removal. Detach only
     * this exact virtual hardware object before freeing its storage. */
    {
        SDL_Joystick *joystick = SDL_JoystickFromInstanceID(hwdata->instance_id);
        if (joystick && joystick->driver == &SDL_VIRTUAL_JoystickDriver && joystick->hwdata == hwdata) {
            joystick->hwdata = NULL;
        }
    }
    if (hwdata->axes) {
''')
    virtual.write_text(text)
    if hashlib.sha256(virtual.read_bytes()).hexdigest() != 'f34e92e8fe786113218da9b8363c739b00f776df79c493cb451c660a36d6c5b6':
        raise ValueError('Virtual joystick repair differs from the verified source')
    names = ('src/events/SDL_keyboard.c', 'src/events/SDL_events.c', 'src/events/SDL_mouse.c', 'src/video/SDL_video.c', 'src/joystick/virtual/SDL_virtualjoystick.c')
    patch = "".join("".join(difflib.unified_diff((source / name).read_text().splitlines(True), (output / name).read_text().splitlines(True), fromfile="upstream/" + name, tofile="renreader/" + name)) for name in names)
    (output / "RenReader-input-gate.patch").write_text(patch)
    return [keyboard, events, mouse, video, virtual]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(prepare(args.source, args.output))
