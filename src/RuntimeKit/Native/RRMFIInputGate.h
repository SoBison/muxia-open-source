#pragma once
#include "SDL.h"

/* Hidden native integration only; no Python/Bridge/API expansion. */
void RRMFIInputSetBlocked(int blocked);
void RRMFIInputReset(void);
/* Under SDL queue lock: atomics/queue-owned snapshots only, no SDL/locks. */
void RRMFIInputDidDeliver(const SDL_Event *event);
void RRMFIInputDidRemove(const SDL_Event *event);
int RRMFIInputAllowPost(const SDL_Event *event, int blocked);
/* Existing recursive Gate lock held; Gate -> Queue, never Joystick. */
void RRMFIInputBlockQueue(void);
