/* Host keyboard ownership around SDL2.0.20's public/native event path. */
#include "RRInputGate.h"
#include "RRAuxiliaryInput.h"
#include "RRMFIInputGate.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
_Static_assert(SDL_NUM_SCANCODES == 512, "Pinned SDL2 scan ABI");
_Static_assert(sizeof(SDL_Event) == 56, "Pinned SDL2 event ABI");

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t mutex;
static int blocked = 1;
static Uint8 physical[SDL_NUM_SCANCODES], quarantine[SDL_NUM_SCANCODES];
static uint64_t physicalVersion[SDL_NUM_SCANCODES];
static _Atomic unsigned char delivered[SDL_NUM_SCANCODES];
static _Atomic unsigned char composing;
static _Atomic Uint32 composingWindow;
static _Atomic unsigned char pendingComposition, queuedComposition;
static _Atomic Uint32 pendingCompositionWindow;
/* Written under SDL's event queue lock. Read only after FilterEvents' barrier. */
static SDL_KeyboardEvent lastDown[SDL_NUM_SCANCODES];
static Uint16 lockModifiers;
static _Thread_local int emittingRelease;
static RRInputGateStats stats;
static Uint8 auxKeyTouched[SDL_NUM_SCANCODES];
static _Atomic unsigned char pendingKey[SDL_NUM_SCANCODES], queuedKey[SDL_NUM_SCANCODES];
static _Atomic unsigned char auxMouseDown[4], pendingMouse[4], queuedMouse[4];
static SDL_MouseButtonEvent lastAuxMouseDown[4];
static uint64_t auxiliaryPostFailures;

static void initialize(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mutex, &attr);
    pthread_mutexattr_destroy(&attr);
}
static void lock(void) { pthread_once(&once, initialize); pthread_mutex_lock(&mutex); }
void RRInputGateLock(void) { lock(); }
void RRInputGateLeave(void) { pthread_mutex_unlock(&mutex); }
static int keyboard(Uint32 type) { return type == SDL_KEYDOWN || type == SDL_KEYUP; }
static int text(Uint32 type) { return type == SDL_TEXTINPUT || type == SDL_TEXTEDITING; }
static int valid(SDL_Scancode scan) { return scan > SDL_SCANCODE_UNKNOWN && scan < SDL_NUM_SCANCODES; }

int RRInputGateEnterKey(Uint8 source, Uint8 state, SDL_Scancode scan) {
    lock();
    if (!valid(scan) || (state != SDL_PRESSED && state != SDL_RELEASED)) { RRInputGateLeave(); return 0; }
    if (source & 1) { /* SDL's KEYBOARD_HARDWARE; autorelease is a separate source. */
        Uint8 previous = physical[scan];
        physicalVersion[scan]++;
        physical[scan] = state == SDL_PRESSED;
        if (blocked && state == SDL_PRESSED && !previous) {
            if (scan == SDL_SCANCODE_CAPSLOCK) lockModifiers ^= KMOD_CAPS;
            if (scan == SDL_SCANCODE_NUMLOCKCLEAR) lockModifiers ^= KMOD_NUM;
            if (scan == SDL_SCANCODE_SCROLLLOCK) lockModifiers ^= KMOD_SCROLL;
        }
    }
    if (blocked || quarantine[scan]) {
        stats.rejectedKeys++;
        if (quarantine[scan]) stats.quarantinedInputs++;
        if (state == SDL_RELEASED) quarantine[scan] = 0;
        RRInputGateLeave();
        return 0;
    }
    stats.acceptedKeys++;
    if (source == RR_AUX_KEY_SOURCE) auxKeyTouched[scan] = 1;
    return 1; /* Caller holds the lock through SDL state update and PushEvent. */
}

static int quarantinedPhysical(void) {
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan)
        if (quarantine[scan] && physical[scan]) return 1;
    return 0;
}

int RRInputGateEnterText(void) {
    lock();
    if (blocked || quarantinedPhysical()) {
        stats.rejectedText++;
        RRInputGateLeave();
        return 0;
    }
    return 1;
}

int RRInputGateEnterPost(const SDL_Event *event) {
    lock();
    if (!event) { RRInputGateLeave(); return 0; }
    if (!RRMFIInputAllowPost(event, blocked)) { stats.rejectedPosts++; RRInputGateLeave(); return 0; }
    if (blocked && (event->type == SDL_MOUSEMOTION || event->type == SDL_MOUSEBUTTONDOWN || event->type == SDL_MOUSEBUTTONUP || event->type == SDL_MOUSEWHEEL)
        && event->motion.which == RR_AUX_MOUSE_ID && !(emittingRelease && event->type == SDL_MOUSEBUTTONUP)) {
        stats.rejectedPosts++; RRInputGateLeave(); return 0;
    }
    if (blocked && (keyboard(event->type) || text(event->type)) &&
        !(emittingRelease && (event->type == SDL_KEYUP || event->type == SDL_TEXTEDITING))) {
        stats.rejectedPosts++;
        RRInputGateLeave();
        return 0;
    }
    if (!emittingRelease && text(event->type) && quarantinedPhysical()) {
        stats.rejectedPosts++;
        RRInputGateLeave();
        return 0;
    }
    if (keyboard(event->type) && valid(event->key.keysym.scancode) && quarantine[event->key.keysym.scancode]) {
        stats.quarantinedInputs++;
        RRInputGateLeave();
        return 0;
    }
    return 2; /* Locked; the wrapper releases after the original PushEvent. */
}

void RRInputGateDidDeliver(const SDL_Event *event) {
    RRMFIInputDidDeliver(event);
    if (event && (event->type == SDL_MOUSEBUTTONDOWN || event->type == SDL_MOUSEBUTTONUP)
        && event->button.which == RR_AUX_MOUSE_ID && event->button.button >= 1 && event->button.button <= 3) {
        int button = event->button.button;
        if (event->type == SDL_MOUSEBUTTONDOWN) {
            lastAuxMouseDown[button] = event->button;
            atomic_store(&auxMouseDown[button], 1);
        } else {
            atomic_store(&auxMouseDown[button], 0); atomic_store(&pendingMouse[button], 0); atomic_store(&queuedMouse[button], 0);
        }
    }
    if (event && event->type == SDL_TEXTEDITING) {
        atomic_store(&composingWindow, event->edit.windowID);
        atomic_store(&composing, event->edit.text[0] != '\0');
        if (!event->edit.text[0] && event->edit.windowID == atomic_load(&pendingCompositionWindow)) {
            atomic_store(&pendingComposition, 0); atomic_store(&queuedComposition, 0);
        }
    }
    if (event && event->type == SDL_TEXTINPUT) {
        atomic_store(&composing, 0);
        if (event->text.windowID == atomic_load(&pendingCompositionWindow)) {
            atomic_store(&pendingComposition, 0); atomic_store(&queuedComposition, 0);
        }
    }
    if (!event || !keyboard(event->type) || !valid(event->key.keysym.scancode)) return;
    int scan = event->key.keysym.scancode;
    if (event->type == SDL_KEYDOWN) {
        lastDown[scan] = event->key;
        atomic_store_explicit(&delivered[scan], 1, memory_order_release);
    } else {
        atomic_store_explicit(&delivered[scan], 0, memory_order_release);
        atomic_store(&pendingKey[scan], 0); atomic_store(&queuedKey[scan], 0);
    }
}

void RRInputGateDidPost(const SDL_Event *event, int result) {
    /* SDL_Send* collapses PushEvent's -1 (queue failure) and 0 (author filter).
     * Observe the original result before that collapse, without changing the
     * author's filter/watchers. The producer already holds the gate lock. */
    if (result >= 0 || !event) return;
    if ((keyboard(event->type) && event->key.keysym.unused == RR_AUX_KEY_MARKER)
        || ((event->type == SDL_MOUSEMOTION || event->type == SDL_MOUSEBUTTONDOWN || event->type == SDL_MOUSEBUTTONUP || event->type == SDL_MOUSEWHEEL)
            && event->motion.which == RR_AUX_MOUSE_ID)) auxiliaryPostFailures++;
}
void RRInputGateDidRemove(const SDL_Event *event) {
    RRMFIInputDidRemove(event);
    /* CutEvent is shared by GET, FlushEvents and an author's FilterEvents.
     * A dropped boundary must become retryable; it was never delivered. GET
     * has already cleared the debt in DidDeliver before reaching this hook. */
    if (event && event->type == SDL_KEYUP && valid(event->key.keysym.scancode) && event->key.keysym.unused == RR_AUX_BOUNDARY_KEY_MARKER)
        atomic_store(&queuedKey[event->key.keysym.scancode], 0);
    if (event && event->type == SDL_MOUSEBUTTONUP && event->button.which == RR_AUX_MOUSE_ID
        && event->button.button >= 1 && event->button.button <= 3 && event->button.padding1 == RR_AUX_BOUNDARY_MOUSE_MARKER)
        atomic_store(&queuedMouse[event->button.button], 0);
    if (event && event->type == SDL_TEXTEDITING && !event->edit.text[0] && event->edit.windowID == atomic_load(&pendingCompositionWindow))
        atomic_store(&queuedComposition, 0);
}
uint64_t RRInputGateAuxiliaryPostFailures(void) {
    lock(); uint64_t result = auxiliaryPostFailures; RRInputGateLeave(); return result;
}

static int removeQueued(void *unused, SDL_Event *event) {
    (void)unused;
    if (keyboard(event->type) || text(event->type)) {
        if (keyboard(event->type) && valid(event->key.keysym.scancode)) atomic_store(&queuedKey[event->key.keysym.scancode], 0);
        stats.filteredQueued++; return 0;
    }
    if ((event->type == SDL_MOUSEMOTION || event->type == SDL_MOUSEBUTTONDOWN || event->type == SDL_MOUSEBUTTONUP || event->type == SDL_MOUSEWHEEL)
        && event->motion.which == RR_AUX_MOUSE_ID) {
        if (event->type == SDL_MOUSEBUTTONUP && event->button.button >= 1 && event->button.button <= 3) atomic_store(&queuedMouse[event->button.button], 0);
        stats.filteredQueued++; return 0;
    }
    return 1;
}

static int flushAuxiliaryReleases(void) {
    int failed = 0;
    int previous = emittingRelease;
    emittingRelease = 1;
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
        if (!atomic_load(&pendingKey[scan]) || atomic_load(&queuedKey[scan])) continue;
        SDL_Event event; SDL_zero(event); event.key = lastDown[scan];
        event.key.type = SDL_KEYUP; event.key.state = SDL_RELEASED; event.key.repeat = 0;
        event.key.keysym.mod = SDL_GetModState(); event.key.keysym.unused = RR_AUX_BOUNDARY_KEY_MARKER;
        event.key.timestamp = SDL_GetTicks();
        Uint8 held = quarantine[scan]; quarantine[scan] = 0;
        atomic_store(&queuedKey[scan], 1);
        if (SDL_PeepEvents(&event, 1, SDL_ADDEVENT, 0, 0) > 0) stats.balancedReleases++;
        else { atomic_store(&queuedKey[scan], 0); failed = 1; }
        quarantine[scan] = held;
    }
    for (int button = 1; button <= 3; ++button) {
        if (!atomic_load(&pendingMouse[button]) || atomic_load(&queuedMouse[button])) continue;
        SDL_Event event; SDL_zero(event); event.button = lastAuxMouseDown[button];
        event.button.type = SDL_MOUSEBUTTONUP; event.button.state = SDL_RELEASED;
        event.button.padding1 = RR_AUX_BOUNDARY_MOUSE_MARKER; event.button.timestamp = SDL_GetTicks();
        atomic_store(&queuedMouse[button], 1);
        if (SDL_PeepEvents(&event, 1, SDL_ADDEVENT, 0, 0) > 0) stats.balancedReleases++;
        else { atomic_store(&queuedMouse[button], 0); failed = 1; }
    }
    if (atomic_load(&pendingComposition) && !atomic_load(&queuedComposition)) {
        SDL_Event event; SDL_zero(event); event.edit.type = SDL_TEXTEDITING;
        event.edit.windowID = atomic_load(&pendingCompositionWindow); event.edit.timestamp = SDL_GetTicks();
        atomic_store(&queuedComposition, 1);
        if (SDL_PeepEvents(&event, 1, SDL_ADDEVENT, 0, 0) <= 0) { atomic_store(&queuedComposition, 0); failed = 1; }
    }
    emittingRelease = previous;
    return failed ? -1 : 1;
}

static int removeAuxiliaryQueued(void *context, SDL_Event *event) {
    Uint8 *foreignUps = context;
    if (keyboard(event->type) && valid(event->key.keysym.scancode)) {
        if (event->key.keysym.unused == RR_AUX_BOUNDARY_KEY_MARKER) return 1;
        if (event->key.keysym.unused == RR_AUX_KEY_MARKER) { stats.filteredQueued++; return 0; }
        if (event->type == SDL_KEYUP && event->key.windowID == lastDown[event->key.keysym.scancode].windowID) foreignUps[event->key.keysym.scancode] = 1;
    }
    if ((event->type == SDL_MOUSEMOTION || event->type == SDL_MOUSEBUTTONDOWN || event->type == SDL_MOUSEBUTTONUP || event->type == SDL_MOUSEWHEEL)
        && event->motion.which == RR_AUX_MOUSE_ID) {
        if (event->type == SDL_MOUSEBUTTONUP && event->button.padding1 == RR_AUX_BOUNDARY_MOUSE_MARKER) return 1;
        stats.filteredQueued++; return 0;
    }
    return 1;
}

int RRInputGateCancelAuxiliary(void) {
    lock();
    if (!SDL_WasInit(SDL_INIT_EVENTS)) { RRInputGateLeave(); return 1; }
    Uint8 released[SDL_NUM_SCANCODES];
    RRSDL_ClearAuxiliaryKeyboardSource(released);
    const Uint8 *state = SDL_GetKeyboardState(NULL);
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
        if (auxKeyTouched[scan] && !state[scan]) released[scan] = 1;
        auxKeyTouched[scan] = 0;
    }
    RRSDL_ClearAuxiliaryMouseSource();
    Uint8 foreignUps[SDL_NUM_SCANCODES] = {0};
    SDL_FilterEvents(removeAuxiliaryQueued, foreignUps);
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
        if (foreignUps[scan] && !atomic_load(&queuedKey[scan])) atomic_store(&pendingKey[scan], 0);
        else if (released[scan] && atomic_load(&delivered[scan]) && !foreignUps[scan]) atomic_store(&pendingKey[scan], 1);
    }
    for (int button = 1; button <= 3; ++button)
        if (atomic_load(&auxMouseDown[button])) atomic_store(&pendingMouse[button], 1);
    int result = flushAuxiliaryReleases();
    RRInputGateLeave(); return result;
}
uint32_t RRInputGateAuxiliaryPendingReleases(void) {
    lock(); uint32_t count = 0;
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) count += !!atomic_load(&pendingKey[scan]);
    for (int button = 1; button <= 3; ++button) count += !!atomic_load(&pendingMouse[button]);
    count += !!atomic_load(&pendingComposition);
    RRInputGateLeave(); return count;
}
int RRInputGateAuxiliaryKeyBlocked(SDL_Scancode scan) {
    lock(); int result = blocked || !valid(scan) || quarantine[scan]; RRInputGateLeave(); return result;
}

void RRInputGateSetBlocked(int value) {
    lock();
    value = !!value;
    if (blocked == value) {
        /* A previous boundary may have found an author's full queue. Retry
         * only that pending release; never cancel newly held inputs here. */
        flushAuxiliaryReleases();
        RRInputGateLeave(); return;
    }
    blocked = value;
    stats.generation++;
    if (blocked) {
        RRMFIInputBlockQueue();
        lockModifiers = SDL_GetModState() & (KMOD_CAPS | KMOD_NUM | KMOD_SCROLL);
        /* This takes SDL's queue lock without replacing an author's filter or
         * flushing other event types. GET delivery bookkeeping runs under that
         * same lock, so lastDown is stable after this barrier. */
        if (SDL_WasInit(SDL_INIT_EVENTS)) SDL_FilterEvents(removeQueued, NULL);
        RRSDL_ClearKeyboardState(lockModifiers);
        RRSDL_ClearAuxiliaryMouseSource();
        memset(auxKeyTouched, 0, sizeof(auxKeyTouched));
        RRAuxiliaryGateBlocked();
        emittingRelease = 1;
        for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
            quarantine[scan] = physical[scan];
            if (!atomic_load_explicit(&delivered[scan], memory_order_acquire)) continue;
            SDL_Event release;
            SDL_zero(release);
            release.key = lastDown[scan];
            release.key.type = SDL_KEYUP;
            release.key.state = SDL_RELEASED;
            release.key.repeat = 0;
            release.key.keysym.mod = lockModifiers;
            release.key.keysym.unused = RR_AUX_BOUNDARY_KEY_MARKER;
            /* Boundary releases must pass even for quarantined held keys. */
            Uint8 held = quarantine[scan]; quarantine[scan] = 0;
            release.key.timestamp = SDL_GetTicks();
            /* Pair a down already consumed by the engine even if an author
             * filter now rejects up; ADDEVENT deliberately bypasses watchers. */
            atomic_store(&pendingKey[scan], 1); atomic_store(&queuedKey[scan], 1);
            if (SDL_PeepEvents(&release, 1, SDL_ADDEVENT, 0, 0) > 0) stats.balancedReleases++;
            else atomic_store(&queuedKey[scan], 0);
            quarantine[scan] = held;
        }
        for (int button = 1; button <= 3; ++button)
            if (atomic_load(&auxMouseDown[button])) atomic_store(&pendingMouse[button], 1);
        if (atomic_load(&composing)) {
            atomic_store(&pendingCompositionWindow, atomic_load(&composingWindow));
            atomic_store(&pendingComposition, 1);
        }
        flushAuxiliaryReleases();
        emittingRelease = 0;
    } else {
        /* Do not replay modifiers or repeats held over a host modal. */
        RRSDL_ClearKeyboardState(lockModifiers);
        for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) quarantine[scan] = physical[scan];
        flushAuxiliaryReleases();
    }
    RRInputGateLeave();
}

void RRInputGateBegin(void) {
    lock();
    blocked = 1;
    memset(physical, 0, sizeof(physical)); memset(quarantine, 0, sizeof(quarantine));
    memset(physicalVersion, 0, sizeof(physicalVersion));
    for (int scan = 0; scan < SDL_NUM_SCANCODES; ++scan) atomic_store(&delivered[scan], 0);
    memset(lastDown, 0, sizeof(lastDown)); memset(&stats, 0, sizeof(stats));
    atomic_store(&composing, 0);
    atomic_store(&composingWindow, 0);
    atomic_store(&pendingComposition, 0); atomic_store(&queuedComposition, 0); atomic_store(&pendingCompositionWindow, 0);
    lockModifiers = 0;
    memset(auxKeyTouched, 0, sizeof(auxKeyTouched));
    auxiliaryPostFailures = 0;
    for (int scan = 0; scan < SDL_NUM_SCANCODES; ++scan) { atomic_store(&pendingKey[scan], 0); atomic_store(&queuedKey[scan], 0); }
    for (int button = 0; button <= 3; ++button) { atomic_store(&auxMouseDown[button], 0); atomic_store(&pendingMouse[button], 0); atomic_store(&queuedMouse[button], 0); }
    RRAuxiliaryReset();
    RRInputGateLeave();
}
void RRInputGateEnd(void) {
    RRInputGateSetBlocked(1);
    lock();
    memset(physical, 0, sizeof(physical)); memset(quarantine, 0, sizeof(quarantine));
    for (int scan = 0; scan < SDL_NUM_SCANCODES; ++scan) atomic_store(&delivered[scan], 0);
    atomic_store(&composing, 0);
    RRInputGateLeave();
}
void RRInputGateCopyStats(RRInputGateStats *output) {
    lock();
    *output = stats;
    output->blocked = blocked; output->heldPhysical = output->deliveredDown = 0;
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
        output->heldPhysical += !!physical[scan];
        output->deliveredDown += !!atomic_load(&delivered[scan]);
    }
    RRInputGateLeave();
}

void RRInputGatePhysicalVersions(uint64_t output[SDL_NUM_SCANCODES]) {
    lock(); memcpy(output, physicalVersion, sizeof(physicalVersion)); RRInputGateLeave();
}
void RRInputGateReconcilePhysical(const uint64_t versions[SDL_NUM_SCANCODES], const Uint8 state[SDL_NUM_SCANCODES]) {
    lock();
    if (!blocked) { RRInputGateLeave(); return; }
    for (int scan = 1; scan < SDL_NUM_SCANCODES; ++scan) {
        if (physicalVersion[scan] != versions[scan]) continue;
        physical[scan] = !!state[scan];
        quarantine[scan] = physical[scan];
    }
    RRInputGateLeave();
}
