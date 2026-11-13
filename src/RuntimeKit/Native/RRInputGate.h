#ifndef RR_INPUT_GATE_H
#define RR_INPUT_GATE_H
#include "SDL.h"
#include <stdint.h>

/* Internal hooks in the exact-version SDL source objects, not event filters. */
int RRInputGateEnterKey(Uint8 source, Uint8 state, SDL_Scancode scancode);
int RRInputGateEnterText(void);
int RRInputGateEnterPost(const SDL_Event *event);
void RRInputGateLock(void);
void RRInputGateLeave(void);
void RRInputGateDidDeliver(const SDL_Event *event);
void RRInputGateDidRemove(const SDL_Event *event);
void RRSDL_ClearKeyboardState(Uint16 lock_modifiers);
int RRSDL_SendAuxiliaryKey(Uint8 state, SDL_Scancode scancode);
void RRSDL_ClearAuxiliaryKeyboardSource(Uint8 released[SDL_NUM_SCANCODES]);
void RRSDL_ClearAuxiliaryMouseSource(void);
int RRInputGateCancelAuxiliary(void);
uint32_t RRInputGateAuxiliaryPendingReleases(void);
int RRInputGateAuxiliaryKeyBlocked(SDL_Scancode scan);
void RRInputGateDidPost(const SDL_Event *event, int result);
uint64_t RRInputGateAuxiliaryPostFailures(void);

void RRInputGateSetBlocked(int blocked);
void RRInputGateBegin(void);
void RRInputGateEnd(void);
typedef struct {
    uint64_t generation, acceptedKeys, rejectedKeys, rejectedText, rejectedPosts;
    uint64_t balancedReleases, quarantinedInputs, filteredQueued;
    uint32_t blocked, heldPhysical, deliveredDown;
} RRInputGateStats;
void RRInputGateCopyStats(RRInputGateStats *output);
void RRInputGatePhysicalVersions(uint64_t output[SDL_NUM_SCANCODES]);
void RRInputGateReconcilePhysical(const uint64_t versions[SDL_NUM_SCANCODES], const Uint8 state[SDL_NUM_SCANCODES]);
#endif
