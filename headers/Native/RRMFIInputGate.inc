/* New controlled-MFI scope only. Other existing SDL backends stay unchanged.
 * Existing runtime MFI Update/GC notification ownership stays on main; normal
 * producer callbacks preserve SDL core's unlocked dispatch and take Gate.
 * Platform/reset/close take Joystick -> Gate -> Queue; queue callbacks never
 * acquire either producer lock. GET/remove use atomics and queue-owned snapshots;
 * they never take either producer lock or call SDL. */
#include "RRInputGate.h"
#include "RRMFIInputGate.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#define DEVICES 64
#define BUTTONS 64
#define AXES 16
#define HATS 4
#define JBUTTON 0
#define CBUTTON 64
#define JAXIS 128
#define CAXIS 144
#define JHAT 160
#define SIGNALS 164

typedef struct {
    _Atomic int value, pending, queued;
    SDL_Event last, release;
} Signal;
typedef struct {
    _Atomic int id, quarantined, pendingCount;
    SDL_Joystick *joystick;
    int naxes, nbuttons, nhats;
    uint64_t generation;
    Sint16 rawAxis[AXES];
    Uint8 rawButton[BUTTONS], rawHat[HATS];
    Signal signals[SIGNALS];
} Device;
static Device devices[DEVICES];
static pthread_once_t once = PTHREAD_ONCE_INIT;
static _Atomic int initialized;
static _Thread_local int postingBoundary;
/* A private centering observation travels through normal SDL author filters
 * and controller watchers, then is refused at the queue's second admission.
 * Only this explicitly owned pointer gets the exception; direct author Peep
 * submissions never acquire an implicit outer-post lease. */
static _Thread_local const SDL_Event *neutralWatcherEvent;
static _Thread_local int neutralWatcherPhase;
static _Thread_local SDL_JoystickID neutralWatcherOwner;

static void initialize(void) {
    for (int i = 0; i < DEVICES; i++) atomic_store(&devices[i].id, -1);
    atomic_store_explicit(&initialized, 1, memory_order_release);
}
static int rawNeutral(const Device *device, int axis) {
    return device->naxes == 6 && (axis == 2 || axis == 5) ? SDL_JOYSTICK_AXIS_MIN : 0;
}
static int neutral(const Device *device, int signal) {
    return signal >= JAXIS && signal < CAXIS ? rawNeutral(device, signal - JAXIS) : 0;
}
static int signalFor(const SDL_Event *event, int *id) {
    if (!event || !id) return -1;
    int signal;
    switch (event->type) {
        case SDL_JOYBUTTONDOWN: case SDL_JOYBUTTONUP:
            if (event->jbutton.button >= BUTTONS) return -1;
            *id = event->jbutton.which; return JBUTTON + event->jbutton.button;
        case SDL_CONTROLLERBUTTONDOWN: case SDL_CONTROLLERBUTTONUP:
            if (event->cbutton.button >= BUTTONS) return -1;
            *id = event->cbutton.which; return CBUTTON + event->cbutton.button;
        case SDL_JOYAXISMOTION:
            signal = event->jaxis.axis; if (signal >= AXES) return -1;
            *id = event->jaxis.which; return JAXIS + signal;
        case SDL_CONTROLLERAXISMOTION:
            signal = event->caxis.axis; if (signal >= AXES) return -1;
            *id = event->caxis.which; return CAXIS + signal;
        case SDL_JOYHATMOTION:
            signal = event->jhat.hat; if (signal >= HATS) return -1;
            *id = event->jhat.which; return JHAT + signal;
        default: return -1; /* Hotplug, author/user and other device events. */
    }
}
static Device *find(int id) {
    if (id < 0 || !atomic_load_explicit(&initialized, memory_order_acquire)) return NULL;
    for (int i = 0; i < DEVICES; i++)
        if (atomic_load_explicit(&devices[i].id, memory_order_acquire) == id) return &devices[i];
    return NULL;
}
/* Slot id remains -1 for every initialization step. Queue observers must
 * never see an empty roster entry temporarily published as instance zero. */
static void prepare(Device *device, SDL_Joystick *joystick) {
    device->joystick = joystick;
    device->naxes = joystick->naxes; device->nbuttons = joystick->nbuttons; device->nhats = joystick->nhats;
    device->generation = UINT64_MAX;
    atomic_store(&device->quarantined, 1); atomic_store(&device->pendingCount, 0);
    memset(device->rawAxis, 0, sizeof(device->rawAxis));
    memset(device->rawButton, 0, sizeof(device->rawButton));
    memset(device->rawHat, 0, sizeof(device->rawHat));
    for (int i = 0; i < SIGNALS; i++) {
        Signal *signal = &device->signals[i];
        atomic_store(&signal->value, 0); atomic_store(&signal->pending, 0); atomic_store(&signal->queued, 0);
        memset(&signal->last, 0, sizeof(signal->last)); memset(&signal->release, 0, sizeof(signal->release));
    }
    for (int axis = 0; axis < AXES; axis++) {
        device->rawAxis[axis] = (Sint16)rawNeutral(device, axis);
        atomic_store(&device->signals[JAXIS + axis].value, rawNeutral(device, axis));
    }
}
static Device *admit(SDL_Joystick *joystick) {
    pthread_once(&once, initialize);
    if (joystick->instance_id < 0 || joystick->naxes < 0 || joystick->nbuttons < 0 || joystick->nhats < 0) return NULL;
    Device *device = find(joystick->instance_id);
    if (device) return device;
    if (joystick->naxes > AXES || joystick->nbuttons > BUTTONS || joystick->nhats > HATS) return NULL;
    for (int i = 0; i < DEVICES; i++) {
        device = &devices[i];
        if (atomic_load(&device->id) != -1) continue;
        prepare(device, joystick);
        atomic_store_explicit(&device->id, joystick->instance_id, memory_order_release);
        return device;
    }
    SDL_SetError("The controlled MFI input roster is full");
    return NULL; /* The producer still writes neutral, never uncontrolled input. */
}
static int filter(void *context, SDL_Event *event) {
    int id, signal = signalFor(event, &id);
    if (signal < 0) return 1;
    Device *device = context;
    return device ? id != atomic_load(&device->id) : find(id) == NULL;
}
static void makePending(Device *device) {
    for (int i = 0; i < SIGNALS; i++) {
        Signal *signal = &device->signals[i];
        if (atomic_load(&signal->value) == neutral(device, i) || atomic_load(&signal->pending)) continue;
        signal->release = signal->last;
        signal->release.common.timestamp = SDL_GetTicks();
        if (i < CBUTTON) { signal->release.type = SDL_JOYBUTTONUP; signal->release.jbutton.state = SDL_RELEASED; }
        else if (i < JAXIS) { signal->release.type = SDL_CONTROLLERBUTTONUP; signal->release.cbutton.state = SDL_RELEASED; }
        else if (i < CAXIS) signal->release.jaxis.value = (Sint16)neutral(device, i);
        else if (i < JHAT) signal->release.caxis.value = 0;
        else signal->release.jhat.value = SDL_HAT_CENTERED;
        atomic_store(&signal->queued, 0);
        atomic_store_explicit(&signal->pending, 1, memory_order_release);
        atomic_fetch_add(&device->pendingCount, 1);
    }
}
static void retry(void) {
    if (!(SDL_WasInit(SDL_INIT_EVENTS) & SDL_INIT_EVENTS)) return;
    for (int i = 0; i < DEVICES; i++) {
        Device *device = &devices[i];
        if (atomic_load(&device->id) < 0) continue;
        if (!device->joystick && !atomic_load(&device->pendingCount)) {
            SDL_FilterEvents(filter, device); /* queue barrier before slot reuse */
            atomic_store_explicit(&device->id, -1, memory_order_release);
            continue;
        }
        if (!atomic_load(&device->pendingCount)) continue;
        for (int j = 0; j < SIGNALS; j++) {
            Signal *signal = &device->signals[j];
            if (!atomic_load(&signal->pending) || atomic_load(&signal->queued)) continue;
            postingBoundary++;
            atomic_store_explicit(&signal->queued, 1, memory_order_release);
            if (SDL_PeepEvents(&signal->release, 1, SDL_ADDEVENT, 0, 0) <= 0) atomic_store(&signal->queued, 0);
            postingBoundary--;
        }
    }
}
static void rr_mfi_input_retry(void) {
    pthread_once(&once, initialize);
    RRInputGateLock(); retry(); RRInputGateLeave();
}
/* Called by RRInputGateSetBlocked with Gate held; never takes Joystick. */
void RRMFIInputBlockQueue(void) {
    pthread_once(&once, initialize);
    for (int i = 0; i < DEVICES; i++)
        if (atomic_load(&devices[i].id) >= 0) atomic_store(&devices[i].quarantined, 1);
    if (SDL_WasInit(SDL_INIT_EVENTS)) SDL_FilterEvents(filter, NULL);
    for (int i = 0; i < DEVICES; i++) if (atomic_load(&devices[i].id) >= 0) makePending(&devices[i]);
    retry();
}
int RRMFIInputAllowPost(const SDL_Event *event, int blocked) {
    if (event && event == neutralWatcherEvent) return neutralWatcherPhase++ == 0;
    int id;
    if (!event || signalFor(event, &id) < 0) return 1;
    Device *device = find(id);
    if (device && neutralWatcherEvent && !postingBoundary && id == neutralWatcherOwner) {
        int index = signalFor(event, &id);
        int value = index < CBUTTON ? event->jbutton.state : index < JAXIS ? event->cbutton.state :
            index < CAXIS ? event->jaxis.value : index < JHAT ? event->caxis.value : event->jhat.value;
        if (value == neutral(device, index)) return 0;
    }
    return !device || postingBoundary || (!blocked && !atomic_load(&device->quarantined));
}
void RRMFIInputDidDeliver(const SDL_Event *event) {
    int id, index = signalFor(event, &id);
    if (index < 0) return;
    Device *device = find(id);
    if (!device) return;
    Signal *signal = &device->signals[index];
    int value = index < CBUTTON ? event->jbutton.state : index < JAXIS ? event->cbutton.state :
        index < CAXIS ? event->jaxis.value : index < JHAT ? event->caxis.value : event->jhat.value;
    signal->last = *event; /* This callback is serialized by SDL's queue lock. */
    atomic_store(&signal->value, value);
    if (value == neutral(device, index)) {
        if (atomic_exchange(&signal->pending, 0)) atomic_fetch_sub(&device->pendingCount, 1);
        atomic_store(&signal->queued, 0);
    }
}
void RRMFIInputDidRemove(const SDL_Event *event) {
    int id, index = signalFor(event, &id);
    if (index < 0) return;
    Device *device = find(id);
    if (!device) return;
    Signal *signal = &device->signals[index];
    if (atomic_load(&signal->pending) && atomic_load_explicit(&signal->queued, memory_order_acquire)
        && memcmp(event, &signal->release, sizeof(*event)) == 0) atomic_store(&signal->queued, 0);
}
static Device *before(SDL_Joystick *joystick) {
    Device *device = admit(joystick);
    if (!device) return NULL;
    RRInputGateStats stats; RRInputGateCopyStats(&stats);
    if (stats.blocked || device->generation != stats.generation) atomic_store(&device->quarantined, 1);
    device->generation = stats.generation;
    return device;
}
static int rr_mfi_input_axis(SDL_Joystick *joystick, Uint8 axis, Sint16 value) {
    RRInputGateLock(); Device *device = before(joystick);
    if (device && axis < AXES) device->rawAxis[axis] = value;
    Sint16 accepted = !device || atomic_load(&device->quarantined) ?
        (Sint16)(joystick->naxes == 6 && (axis == 2 || axis == 5) ? SDL_JOYSTICK_AXIS_MIN : 0) : value;
    int result = SDL_PrivateJoystickAxis(joystick, axis, accepted);
    RRInputGateLeave(); return result;
}
static int rr_mfi_input_button(SDL_Joystick *joystick, Uint8 button, Uint8 value) {
    RRInputGateLock(); Device *device = before(joystick);
    if (device && button < BUTTONS) device->rawButton[button] = value;
    int result = SDL_PrivateJoystickButton(joystick, button, !device || atomic_load(&device->quarantined) ? SDL_RELEASED : value);
    RRInputGateLeave(); return result;
}
static int rr_mfi_input_hat(SDL_Joystick *joystick, Uint8 hat, Uint8 value) {
    RRInputGateLock(); Device *device = before(joystick);
    if (device && hat < HATS) device->rawHat[hat] = value;
    int result = SDL_PrivateJoystickHat(joystick, hat, !device || atomic_load(&device->quarantined) ? SDL_HAT_CENTERED : value);
    RRInputGateLeave(); return result;
}
static void rr_mfi_input_after_update(SDL_Joystick *joystick) {
    RRInputGateLock(); Device *device = find(joystick->instance_id);
    if (device) {
        RRInputGateStats stats; RRInputGateCopyStats(&stats);
        int released = !stats.blocked && !atomic_load(&device->pendingCount);
        for (int i = 0; i < device->naxes; i++) {
            int value = device->rawAxis[i], idle = rawNeutral(device, i);
            released &= idle == SDL_JOYSTICK_AXIS_MIN ? value <= idle + 8000 : (value >= -8000 && value <= 8000);
        }
        for (int i = 0; i < device->nbuttons; i++) released &= !device->rawButton[i];
        for (int i = 0; i < device->nhats; i++) released &= device->rawHat[i] == SDL_HAT_CENTERED;
        if (released) atomic_store(&device->quarantined, 0);
    }
    retry(); RRInputGateLeave();
}
typedef struct {
    SDL_JoystickID id;
    Uint32 type;
    int index, value;
} Center;
#define CENTER_EVENTS (DEVICES * (AXES + HATS))

static void observeCenter(const Center *center) {
    if (SDL_GetEventState(center->type) != SDL_ENABLE) return;
    SDL_Event event; memset(&event, 0, sizeof(event)); event.type = center->type;
    if (center->type == SDL_JOYAXISMOTION) {
        event.jaxis.which = center->id; event.jaxis.axis = (Uint8)center->index; event.jaxis.value = (Sint16)center->value;
    } else {
        event.jhat.which = center->id; event.jhat.hat = (Uint8)center->index; event.jhat.value = (Uint8)center->value;
    }
    const SDL_Event *previous = neutralWatcherEvent; int phase = neutralWatcherPhase;
    SDL_JoystickID previousOwner = neutralWatcherOwner;
    neutralWatcherEvent = &event; neutralWatcherPhase = 0; neutralWatcherOwner = center->id;
    (void)SDL_PushEvent(&event);
    neutralWatcherEvent = previous; neutralWatcherPhase = phase; neutralWatcherOwner = previousOwner;
}
static void notifyCenters(const Center *centers, int count, uint64_t generation) {
    /* No Joystick or Gate lock here: authored filters/watchers may reenter SDL
     * or synchronously ask a peer thread for a public SDL roster read. */
    for (int i = 0; i < count; i++) {
        RRInputGateStats current; RRInputGateCopyStats(&current);
        if (current.generation != generation) break;
        Device *device = find(centers[i].id);
        if (device && device->joystick) observeCenter(&centers[i]);
    }
}
static void collectCenter(Device *device, Center *centers, int *count, Uint32 type, int index, int value) {
    if (!centers || !count || *count >= CENTER_EVENTS) return;
    centers[(*count)++] = (Center){atomic_load(&device->id), type, index, value};
}
static void neutralize(Device *device, Center *centers, int *count) {
    SDL_Joystick *joystick = device->joystick;
    if (!joystick || SDL_JoystickFromInstanceID(atomic_load(&device->id)) != joystick) { device->joystick = NULL; return; }
    for (int i = 0; i < device->naxes; i++) {
        int idle = rawNeutral(device, i), previous = joystick->axes[i].value;
        SDL_PrivateJoystickAxis(joystick, i, (Sint16)idle);
        if (previous != idle) collectCenter(device, centers, count, SDL_JOYAXISMOTION, i, idle);
    }
    for (int i = 0; i < device->nbuttons; i++) SDL_PrivateJoystickButton(joystick, i, SDL_RELEASED);
    for (int i = 0; i < device->nhats; i++) {
        Uint8 previous = joystick->hats[i];
        SDL_PrivateJoystickHat(joystick, i, SDL_HAT_CENTERED);
        if (previous != SDL_HAT_CENTERED) collectCenter(device, centers, count, SDL_JOYHATMOTION, i, SDL_HAT_CENTERED);
    }
}
void RRMFIInputSetBlocked(int blocked) {
    (void)blocked; /* Actual normalized state/generation comes from pinned Gate. */
    Center centers[CENTER_EVENTS]; int count = 0;
    pthread_once(&once, initialize);
    SDL_LockJoysticks(); RRInputGateLock();
    RRInputGateStats stats; RRInputGateCopyStats(&stats);
    for (int i = 0; i < DEVICES; i++) {
        Device *device = &devices[i];
        if (atomic_load(&device->id) < 0 || device->generation == stats.generation) continue;
        atomic_store(&device->quarantined, 1); device->generation = stats.generation;
        neutralize(device, centers, &count);
        if (device->joystick) device->joystick->driver->Update(device->joystick);
    }
    retry(); RRInputGateLeave(); SDL_UnlockJoysticks();
    notifyCenters(centers, count, stats.generation);
}
static void rr_mfi_input_forget(SDL_Joystick *joystick) {
    RRInputGateLock(); Device *device = find(joystick->instance_id);
    if (device) {
        atomic_store(&device->quarantined, 1);
        if (SDL_WasInit(SDL_INIT_EVENTS)) SDL_FilterEvents(filter, device);
        makePending(device); neutralize(device, NULL, NULL); device->joystick = NULL;
        retry();
        if (!atomic_load(&device->pendingCount)) {
            if (SDL_WasInit(SDL_INIT_EVENTS)) SDL_FilterEvents(filter, device);
            atomic_store_explicit(&device->id, -1, memory_order_release);
        }
    }
    RRInputGateLeave();
}
void RRMFIInputReset(void) {
    Center centers[CENTER_EVENTS]; int count = 0;
    pthread_once(&once, initialize);
    SDL_LockJoysticks(); RRInputGateLock();
    RRInputGateStats stats; RRInputGateCopyStats(&stats);
    RRMFIInputBlockQueue();
    for (int i = 0; i < DEVICES; i++) {
        Device *device = &devices[i];
        if (atomic_load(&device->id) < 0) continue;
        neutralize(device, centers, &count);
        device->generation = UINT64_MAX;
        if (!device->joystick && !(SDL_WasInit(SDL_INIT_EVENTS) & SDL_INIT_EVENTS)) atomic_store(&device->id, -1);
    }
    retry(); RRInputGateLeave(); SDL_UnlockJoysticks();
    notifyCenters(centers, count, stats.generation);
}
