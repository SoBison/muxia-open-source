/* Candidate only. Included after the SDL MFI cleanup function is declared.
 * Callers hold SDL_LockJoysticks and use the runtime owner thread. */
#include <stdint.h>
#include <stdatomic.h>

static uint64_t rr_haptic_high, rr_haptic_low, rr_haptic_epoch;
static int rr_haptic_bound;
static _Atomic int rr_controller_haptics_allowed;
static uint64_t rr_haptic_generation;

static int rr_haptic_owner(uint64_t high, uint64_t low, uint64_t epoch) {
    return rr_haptic_bound && high == rr_haptic_high && low == rr_haptic_low && epoch == rr_haptic_epoch;
}

__attribute__((visibility("default"))) int RRPlatformControllerHapticsVersion(void) { return 1; }
__attribute__((visibility("default"))) int RRPlatformControllerHapticsCapabilities(void) {
#ifdef ENABLE_MFI_RUMBLE
    return 1;
#else
    return 0;
#endif
}

__attribute__((visibility("default"))) int RRPlatformControllerHapticsBegin(uint64_t high, uint64_t low, uint64_t epoch) {
    if (!rr_haptic_owner_thread()) return -4;
    if ((!high && !low) || !epoch) return -3;
    SDL_LockJoysticks();
    int result = 0;
    if (rr_haptic_bound) result = rr_haptic_owner(high, low, epoch) ? 0 : -2;
    else {
        rr_haptic_high = high; rr_haptic_low = low; rr_haptic_epoch = epoch; rr_haptic_bound = 1;
        atomic_store(&rr_controller_haptics_allowed, 0); ++rr_haptic_generation;
        rr_haptic_cleanup_controllers();
    }
    SDL_UnlockJoysticks(); return result;
}

__attribute__((visibility("default"))) int RRPlatformControllerHapticsPolicy(uint64_t high, uint64_t low, uint64_t epoch, int enabled) {
    if (!rr_haptic_owner_thread()) return -4;
    if (enabled != 0 && enabled != 1) return -3;
    SDL_LockJoysticks();
    int result = -2;
    if (rr_haptic_owner(high, low, epoch)) {
        if (atomic_load(&rr_controller_haptics_allowed) != enabled) {
            atomic_store(&rr_controller_haptics_allowed, 0);
            rr_haptic_cleanup_controllers(); ++rr_haptic_generation;
            atomic_store(&rr_controller_haptics_allowed, enabled);
        }
        result = 0;
    }
    SDL_UnlockJoysticks(); return result;
}

__attribute__((visibility("default"))) int RRPlatformControllerHapticsEnd(uint64_t high, uint64_t low, uint64_t epoch) {
    if (!rr_haptic_owner_thread()) return -4;
    SDL_LockJoysticks();
    int result = -2;
    if (rr_haptic_owner(high, low, epoch)) {
        atomic_store(&rr_controller_haptics_allowed, 0);
        rr_haptic_cleanup_controllers(); ++rr_haptic_generation;
        rr_haptic_bound = 0; rr_haptic_high = rr_haptic_low = rr_haptic_epoch = 0;
        result = 0;
    }
    SDL_UnlockJoysticks(); return result;
}

/* Native RRPlatformBegin/End must call this, in addition to the UI-owned End.
 * Reset always denies new effects before stopping existing owned engines. */
__attribute__((visibility("default"))) void RRPlatformControllerHapticsReset(void) {
    if (!rr_haptic_owner_thread()) return;
    SDL_LockJoysticks();
    atomic_store(&rr_controller_haptics_allowed, 0);
    rr_haptic_cleanup_controllers(); ++rr_haptic_generation;
    rr_haptic_bound = 0; rr_haptic_high = rr_haptic_low = rr_haptic_epoch = 0;
    SDL_UnlockJoysticks();
}
