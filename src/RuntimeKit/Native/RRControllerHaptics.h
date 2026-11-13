#ifndef RR_CONTROLLER_HAPTICS_CANDIDATE_H
#define RR_CONTROLLER_HAPTICS_CANDIDATE_H
#include <stdint.h>

/* C ABI 1, owner/main thread only. UUID words use network-byte order.
 * All return 0 on success, -2 wrong owner, -3 invalid input, -4 wrong thread.
 * Begin binds a denied owner; Policy enables only that exact owner.
 * End is owner-scoped; Reset is for native RRPlatformBegin/End only.
 * No symbols in this header have been published into current artifacts. */
int RRPlatformControllerHapticsVersion(void);
int RRPlatformControllerHapticsCapabilities(void); /* bit 0: compiled MFI backend */
int RRPlatformControllerHapticsBegin(uint64_t sessionHigh, uint64_t sessionLow, uint64_t epoch);
int RRPlatformControllerHapticsPolicy(uint64_t sessionHigh, uint64_t sessionLow, uint64_t epoch, int enabled);
int RRPlatformControllerHapticsEnd(uint64_t sessionHigh, uint64_t sessionLow, uint64_t epoch);
void RRPlatformControllerHapticsReset(void);
#endif
