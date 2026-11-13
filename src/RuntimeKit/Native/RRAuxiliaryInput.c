#include "SDL_internal.h"
#include "RRAuxiliaryInput.h"
#include "RRInputGate.h"
#include "events/SDL_mouse_c.h"
#include "events/SDL_keyboard_c.h"
#include <math.h>
#include <string.h>

static RRAuxiliaryOwner currentOwner;
static SDL_threadID ownerThread;
static RRAuxiliaryInputState current;
static Uint8 hostKeys[SDL_NUM_SCANCODES];
static _Thread_local int hostTextCall;

static int reject(int reason) { current.rejected++; current.lastError = reason; return reason; }
static int sameOwner(RRAuxiliaryOwner value) {
    return current.active && value.sessionHigh == currentOwner.sessionHigh && value.sessionLow == currentOwner.sessionLow && value.epoch == currentOwner.epoch;
}
static int checkOwner(RRAuxiliaryOwner value) {
    if (!sameOwner(value)) return reject(RR_AUX_STALE_OWNER);
    if (SDL_ThreadID() != ownerThread) return reject(RR_AUX_WRONG_THREAD);
    return RR_AUX_ACCEPTED;
}
static SDL_Window *window(void) { return SDL_GetWindowFromID(current.windowID); }
static int approvedKey(int scan) {
    switch (scan) {
        case SDL_SCANCODE_ESCAPE: case SDL_SCANCODE_TAB: case SDL_SCANCODE_RETURN:
        case SDL_SCANCODE_SPACE: case SDL_SCANCODE_BACKSPACE: case SDL_SCANCODE_DELETE:
        case SDL_SCANCODE_UP: case SDL_SCANCODE_DOWN: case SDL_SCANCODE_LEFT: case SDL_SCANCODE_RIGHT:
        case SDL_SCANCODE_HOME: case SDL_SCANCODE_END: case SDL_SCANCODE_PAGEUP: case SDL_SCANCODE_PAGEDOWN:
        case SDL_SCANCODE_F1: case SDL_SCANCODE_F2: case SDL_SCANCODE_F3: case SDL_SCANCODE_F4: case SDL_SCANCODE_F5:
        case SDL_SCANCODE_F6: case SDL_SCANCODE_F7: case SDL_SCANCODE_F8: case SDL_SCANCODE_F9: case SDL_SCANCODE_F10:
        case SDL_SCANCODE_LCTRL: case SDL_SCANCODE_LSHIFT: case SDL_SCANCODE_LALT: return 1;
        default: return 0;
    }
}
static void closeOwnedKeyboard(void) {
    if (current.keyboardOwned) {
        if (window() && SDL_GetKeyboardFocus() == window()) { hostTextCall++; SDL_StopTextInput(); hostTextCall--; }
        current.keyboardOwned = 0;
    }
}
static int cancelHeld(void) {
    int result = RRInputGateCancelAuxiliary();
    memset(hostKeys, 0, sizeof(hostKeys));
    current.heldKeys = current.heldButtons = 0;
    current.pendingReleases = RRInputGateAuxiliaryPendingReleases();
    if (result < 0) return reject(RR_AUX_QUEUE_FULL);
    return RR_AUX_ACCEPTED;
}

int RRAuxiliaryBegin(RRAuxiliaryOwner owner, uint32_t windowID, uint64_t geometry, int allowed) {
    RRInputGateLock();
    int result;
    if ((!owner.sessionHigh && !owner.sessionLow) || !owner.epoch || !windowID || !geometry || (allowed != 0 && allowed != 1)) result = reject(RR_AUX_INVALID);
    else if (current.active) {
        if (!sameOwner(owner)) result = reject(RR_AUX_BUSY);
        else if (SDL_ThreadID() != ownerThread) result = reject(RR_AUX_WRONG_THREAD);
        else if (current.windowID != windowID || current.geometry != geometry || current.allowed != (uint32_t)allowed) result = reject(RR_AUX_INVALID);
        else result = SDL_GetWindowFromID(windowID) ? RR_AUX_UNCHANGED : reject(RR_AUX_UNAVAILABLE);
    } else if (!(SDL_WasInit(SDL_INIT_VIDEO) & SDL_INIT_VIDEO) || !SDL_GetWindowFromID(windowID)) result = reject(RR_AUX_UNAVAILABLE);
    else {
        currentOwner = owner; ownerThread = SDL_ThreadID();
        current = (RRAuxiliaryInputState){.active = 1, .allowed = allowed, .windowID = windowID, .geometry = geometry, .epoch = owner.epoch};
        memset(hostKeys, 0, sizeof(hostKeys)); result = RR_AUX_ACCEPTED;
    }
    RRInputGateLeave(); return result;
}

int RRAuxiliarySetGeometry(RRAuxiliaryOwner owner, uint64_t geometry) {
    RRInputGateLock();
    int result = checkOwner(owner);
    if (result > 0) {
        if (!window()) result = reject(RR_AUX_UNAVAILABLE);
        else if (!geometry || geometry < current.geometry) result = reject(RR_AUX_STALE_GEOMETRY);
        else if (geometry == current.geometry) result = RR_AUX_UNCHANGED;
        else if ((result = cancelHeld()) > 0) current.geometry = geometry;
    }
    RRInputGateLeave(); return result;
}

int RRAuxiliarySubmit(RRAuxiliaryOwner owner, uint64_t geometry, int kind, int code, double x, double y) {
    RRInputGateLock();
    int result = checkOwner(owner);
    SDL_Window *target = result > 0 ? window() : NULL;
    RRInputGateStats gate; RRInputGateCopyStats(&gate);
    if (result > 0 && !target) result = reject(RR_AUX_UNAVAILABLE);
    if (result > 0 && SDL_GetKeyboardFocus() != target) result = reject(RR_AUX_UNAVAILABLE);
    if (result > 0 && geometry != current.geometry) result = reject(RR_AUX_STALE_GEOMETRY);
    if (result > 0 && !current.allowed) result = reject(RR_AUX_MODE_DISABLED);
    if (result > 0 && gate.blocked) result = reject(RR_AUX_BLOCKED);
    if (result > 0 && (!isfinite(x) || !isfinite(y))) result = reject(RR_AUX_INVALID);
    if (result > 0 && RRInputGateAuxiliaryPendingReleases()) result = reject(RR_AUX_BUSY);
    if (result <= 0) { RRInputGateLeave(); return result; }
    uint64_t failuresBefore = RRInputGateAuxiliaryPostFailures();
    int posted = 0;
    switch (kind) {
        case RR_AUX_MOVE: {
            int width, height; SDL_GetWindowSize(target, &width, &height);
            if (code || x < 0 || x > 1 || y < 0 || y > 1 || width <= 0 || height <= 0 || SDL_GetRelativeMouseMode()) { result = reject(RR_AUX_INVALID); break; }
            posted = SDL_SendMouseMotion(target, RR_AUX_MOUSE_ID, 0, (int)llround(x * (width - 1)), (int)llround(y * (height - 1)));
            break;
        }
        case RR_AUX_BUTTON: {
            if (code < 1 || code > 3 || (x != 0 && x != 1) || y) { result = reject(RR_AUX_INVALID); break; }
            uint32_t bit = SDL_BUTTON(code);
            if (!!(current.heldButtons & bit) == !!x) { result = RR_AUX_UNCHANGED; break; }
            posted = SDL_SendMouseButton(target, RR_AUX_MOUSE_ID, x ? SDL_PRESSED : SDL_RELEASED, (Uint8)code);
            if (x) current.heldButtons |= bit; else current.heldButtons &= ~bit;
            break;
        }
        case RR_AUX_WHEEL:
            if (code || fabs(x) > 20 || fabs(y) > 20) { result = reject(RR_AUX_INVALID); break; }
            posted = SDL_SendMouseWheel(target, RR_AUX_MOUSE_ID, (float)x, (float)y, SDL_MOUSEWHEEL_NORMAL);
            break;
        case RR_AUX_KEY:
        case RR_AUX_KEY_TAP: {
            if (!approvedKey(code) || y || (kind == RR_AUX_KEY && x != 0 && x != 1) || (kind == RR_AUX_KEY_TAP && x)) { result = reject(RR_AUX_INVALID); break; }
            if (RRInputGateAuxiliaryKeyBlocked((SDL_Scancode)code)) { result = reject(RR_AUX_BLOCKED); break; }
            if (SDL_GetKeyboardFocus() != target) { result = reject(RR_AUX_UNAVAILABLE); break; }
            if (kind == RR_AUX_KEY_TAP) {
                if (hostKeys[code]) { result = reject(RR_AUX_BUSY); break; }
                posted = RRSDL_SendAuxiliaryKey(SDL_PRESSED, (SDL_Scancode)code);
                RRSDL_SendAuxiliaryKey(SDL_RELEASED, (SDL_Scancode)code);
            } else {
                if (!!hostKeys[code] == !!x) { result = RR_AUX_UNCHANGED; break; }
                posted = RRSDL_SendAuxiliaryKey(x ? SDL_PRESSED : SDL_RELEASED, (SDL_Scancode)code);
                hostKeys[code] = !!x;
                if (x) current.heldKeys++; else current.heldKeys--;
            }
            break;
        }
        case RR_AUX_SCREEN_KEYBOARD:
            if ((code != 0 && code != 1) || x || y) { result = reject(RR_AUX_INVALID); break; }
            if (!SDL_HasScreenKeyboardSupport()) { result = reject(RR_AUX_UNAVAILABLE); break; }
            if (SDL_GetKeyboardFocus() != target) { result = reject(RR_AUX_UNAVAILABLE); break; }
            if (code) {
                if (!SDL_IsTextInputActive()) current.keyboardOwned = 1;
                hostTextCall++; SDL_StartTextInput(); hostTextCall--;
            } else closeOwnedKeyboard();
            posted = 1;
            break;
        default: result = reject(RR_AUX_INVALID); break;
    }
    if (result > 0 && RRInputGateAuxiliaryPostFailures() != failuresBefore) {
        /* An ordinary up can fail after its down was queued or consumed. Drop
         * only our unconsumed inputs and use the existing boundary ledger to
         * pair consumed downs. Pending releases survive a still-full queue. */
        cancelHeld();
        result = reject(RR_AUX_QUEUE_FULL);
    } else if (result > 0) { current.accepted++; current.lastError = 0; result = RR_AUX_ACCEPTED; }
    /* A filtered ordinary input is still a device-state transition. SDL's
     * author filter decides event delivery; we never bypass it here. */
    (void)posted;
    RRInputGateLeave(); return result;
}

int RRAuxiliaryCancel(RRAuxiliaryOwner owner) {
    RRInputGateLock(); int result = checkOwner(owner);
    if (result > 0) { result = cancelHeld(); closeOwnedKeyboard(); }
    RRInputGateLeave(); return result;
}
int RRAuxiliaryEnd(RRAuxiliaryOwner owner) {
    RRInputGateLock(); int result = RRAuxiliaryCancel(owner);
    if (result > 0) { current.active = 0; memset(&currentOwner, 0, sizeof(currentOwner)); ownerThread = 0; }
    RRInputGateLeave(); return result;
}
void RRAuxiliaryReset(void) {
    RRInputGateLock(); closeOwnedKeyboard(); memset(&current, 0, sizeof(current));
    memset(&currentOwner, 0, sizeof(currentOwner)); memset(hostKeys, 0, sizeof(hostKeys)); ownerThread = 0;
    RRInputGateLeave();
}
void RRAuxiliaryGateBlocked(void) {
    /* Called on the same owner thread as the host modal/lifecycle boundary. */
    memset(hostKeys, 0, sizeof(hostKeys)); current.heldKeys = current.heldButtons = 0;
    closeOwnedKeyboard();
}
void RRAuxiliaryTextInputChanged(int active) {
    (void)active;
    RRInputGateLock();
    /* An author Start/Stop is a new ownership decision, even when SDL text
     * input was already active. A later host cancel must not undo it. */
    if (!hostTextCall) current.keyboardOwned = 0;
    RRInputGateLeave();
}
void RRAuxiliaryFocusChanged(uint32_t windowID) {
    RRInputGateLock();
    if (current.active && current.windowID != windowID) {
        if (SDL_ThreadID() == ownerThread) { cancelHeld(); closeOwnedKeyboard(); }
        else reject(RR_AUX_WRONG_THREAD);
    }
    RRInputGateLeave();
}
void RRAuxiliaryCopyState(RRAuxiliaryInputState *output) {
    RRInputGateLock(); *output = current; output->pendingReleases = RRInputGateAuxiliaryPendingReleases(); RRInputGateLeave();
}
