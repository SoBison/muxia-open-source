#ifndef RR_AUXILIARY_INPUT_H
#define RR_AUXILIARY_INPUT_H
#include <stdint.h>

/* Host contract v1. Implementation uses pinned SDL2.0.20 source-owned APIs,
 * not a stable public SDL injection ABI. Move coordinates are normalized in
 * the current SDL window's logical points, never drawable pixels. */
typedef struct { uint64_t sessionHigh, sessionLow, epoch; } RRAuxiliaryOwner;
typedef enum {
    RR_AUX_MOVE = 1, RR_AUX_BUTTON = 2, RR_AUX_WHEEL = 3,
    RR_AUX_KEY = 4, RR_AUX_KEY_TAP = 5, RR_AUX_SCREEN_KEYBOARD = 6
} RRAuxiliaryKind;
typedef enum {
    RR_AUX_ACCEPTED = 1, RR_AUX_UNCHANGED = 0,
    RR_AUX_STALE_OWNER = -1, RR_AUX_STALE_GEOMETRY = -2,
    RR_AUX_BLOCKED = -3, RR_AUX_MODE_DISABLED = -4,
    RR_AUX_INVALID = -5, RR_AUX_WRONG_THREAD = -6,
    RR_AUX_UNAVAILABLE = -7, RR_AUX_BUSY = -8, RR_AUX_QUEUE_FULL = -9
} RRAuxiliaryResult;

/* All public RRPlatform entry points require the main/SDL owner thread.
 * Begin requires a live window. Same-owner Begin is idempotent only for the
 * exact same window, geometry, and mode. A stale token never cancels a new one.
 * Button: code 1..3, x=0/1. Key: approved SDL scancode, x=0/1; KeyTap pairs
 * down/up. Wheel x/y are finite [-20,20]. Keyboard: code=0/1, x=y=0.
 * Negative cleanup results retain ownership for an explicit retry. */
int RRPlatformAuxiliaryBegin(RRAuxiliaryOwner owner, uint32_t windowID, uint64_t geometry, int enhancementsAllowed);
int RRPlatformAuxiliarySetGeometry(RRAuxiliaryOwner owner, uint64_t geometry);
int RRPlatformAuxiliarySubmit(RRAuxiliaryOwner owner, uint64_t geometry, int kind, int code, double x, double y);
int RRPlatformAuxiliaryCancel(RRAuxiliaryOwner owner);
int RRPlatformAuxiliaryEnd(RRAuxiliaryOwner owner);
char *RRPlatformAuxiliaryStateJSON(void); /* caller frees; contains no pointers */

/* Internal helpers shared by the platform and exact SDL input gate. */
#define RR_AUX_MOUSE_ID UINT32_C(0xfffffffe)
#define RR_AUX_KEY_SOURCE 4
#define RR_AUX_KEY_MARKER UINT32_C(0x52524131)
#define RR_AUX_BOUNDARY_KEY_MARKER UINT32_C(0x52524231)
#define RR_AUX_BOUNDARY_MOUSE_MARKER 0xa5
typedef struct {
    uint64_t epoch, geometry, accepted, rejected;
    uint32_t windowID, active, allowed, heldButtons, heldKeys, keyboardOwned, pendingReleases;
    int lastError;
} RRAuxiliaryInputState;
int RRAuxiliaryBegin(RRAuxiliaryOwner owner, uint32_t windowID, uint64_t geometry, int allowed);
int RRAuxiliarySetGeometry(RRAuxiliaryOwner owner, uint64_t geometry);
int RRAuxiliarySubmit(RRAuxiliaryOwner owner, uint64_t geometry, int kind, int code, double x, double y);
int RRAuxiliaryCancel(RRAuxiliaryOwner owner);
int RRAuxiliaryEnd(RRAuxiliaryOwner owner);
void RRAuxiliaryReset(void);
void RRAuxiliaryGateBlocked(void);
void RRAuxiliaryTextInputChanged(int active);
void RRAuxiliaryFocusChanged(uint32_t windowID);
void RRAuxiliaryCopyState(RRAuxiliaryInputState *output);
#endif
