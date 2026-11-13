#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <string.h>
#include "RRInputGate.h"
#include "RRAuxiliaryInput.h"
#include "RRControllerHaptics.h"
#include "RRMFIInputGate.h"
#import <GameController/GameController.h>

extern void SDL_SetMainReady(void);
extern void SDL_iPhoneSetEventPump(SDL_bool enabled);
typedef void *(*RRLookupFunction)(void *, const char *);
static RRLookupFunction hostLookup;
static void *angleHandle;
static id keyboardDisconnectObserver;

void RRPlatformResyncPhysicalKeyboard(void);

__attribute__((visibility("default")))
void RRPlatformSetKeyboardBlocked(int blocked) {
    RRInputGateStats current; RRInputGateCopyStats(&current);
    if (!blocked && current.blocked) RRPlatformResyncPhysicalKeyboard();
    RRInputGateSetBlocked(blocked);
    RRMFIInputSetBlocked(!!blocked);
}

__attribute__((visibility("default")))
void RRPlatformResyncPhysicalKeyboard(void) {
    RRInputGateStats current; RRInputGateCopyStats(&current);
    if (!current.blocked) return;
    /* Snapshot public GC state without holding SDL/gate locks. A per-key
     * version prevents overwriting any hardware edge racing this snapshot. */
    uint64_t versions[SDL_NUM_SCANCODES]; Uint8 state[SDL_NUM_SCANCODES] = {0};
    RRInputGatePhysicalVersions(versions);
    GCKeyboardInput *input = GCKeyboard.coalescedKeyboard.keyboardInput;
    for (int key = 1; key <= 231; ++key) state[key] = [input buttonForKeyCode:(GCKeyCode)key].isPressed;
    RRInputGateReconcilePhysical(versions, state);
}

__attribute__((visibility("default")))
char *RRPlatformKeyboardInputStateJSON(void) {
    RRInputGateStats value; RRInputGateCopyStats(&value);
    NSDictionary *state = @{@"blocked": @(value.blocked != 0), @"generation": @(value.generation),
        @"acceptedKeys": @(value.acceptedKeys), @"rejectedKeys": @(value.rejectedKeys),
        @"rejectedText": @(value.rejectedText), @"rejectedPosts": @(value.rejectedPosts),
        @"balancedReleases": @(value.balancedReleases), @"quarantinedInputs": @(value.quarantinedInputs),
        @"filteredQueued": @(value.filteredQueued), @"heldPhysical": @(value.heldPhysical), @"deliveredDown": @(value.deliveredDown)};
    NSData *data = [NSJSONSerialization dataWithJSONObject:state options:0 error:nil];
    return strdup([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
}

// SDL's UIKit GL loader must resolve functions in the bundled ANGLE image.
// This alias is local to this Mach-O image; it does not interpose in the app.
void *RRPlatformDlsym(void *handle, const char *symbol) {
    if (angleHandle && handle == RTLD_DEFAULT && strncmp(symbol, "gl", 2) == 0) {
        void *result = hostLookup(angleHandle, symbol);
        if (result) return result;
    }
    return hostLookup(handle, symbol);
}

__attribute__((visibility("default")))
void RRPlatformBegin(RRLookupFunction lookup) {
    RRPlatformControllerHapticsReset();
    RRInputGateBegin();
    RRMFIInputReset();
    hostLookup = lookup;
    NSString *path = [[[NSBundle mainBundle].privateFrameworksURL URLByAppendingPathComponent:@"MetalANGLE.framework/MetalANGLE"] path];
    angleHandle = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    SDL_SetMainReady();
    SDL_iPhoneSetEventPump(1);
    if (!keyboardDisconnectObserver) {
        keyboardDisconnectObserver = [NSNotificationCenter.defaultCenter addObserverForName:GCKeyboardDidDisconnectNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
            if (!SDL_WasInit(SDL_INIT_EVENTS)) return;
            RRInputGateStats previous; RRInputGateCopyStats(&previous);
            RRInputGateSetBlocked(1);
            RRPlatformResyncPhysicalKeyboard();
            RRInputGateSetBlocked(previous.blocked);
            RRMFIInputSetBlocked(previous.blocked);
        }];
    }
}

__attribute__((visibility("default")))
void RRPlatformEnd(void) {
    RRPlatformControllerHapticsReset();
    RRInputGateEnd();
    RRMFIInputReset();
    RRAuxiliaryReset();
    SDL_iPhoneSetEventPump(0);
}

/* These entry points are deliberately native-only and owner-thread bound.
 * The Bridge also checks its mounted container and configured launch mode. */
__attribute__((visibility("default")))
int RRPlatformAuxiliaryBegin(RRAuxiliaryOwner owner, uint32_t windowID, uint64_t geometry, int allowed) {
    return NSThread.isMainThread ? RRAuxiliaryBegin(owner, windowID, geometry, allowed) : RR_AUX_WRONG_THREAD;
}
__attribute__((visibility("default")))
int RRPlatformAuxiliarySetGeometry(RRAuxiliaryOwner owner, uint64_t geometry) {
    return NSThread.isMainThread ? RRAuxiliarySetGeometry(owner, geometry) : RR_AUX_WRONG_THREAD;
}
__attribute__((visibility("default")))
int RRPlatformAuxiliarySubmit(RRAuxiliaryOwner owner, uint64_t geometry, int kind, int code, double x, double y) {
    return NSThread.isMainThread ? RRAuxiliarySubmit(owner, geometry, kind, code, x, y) : RR_AUX_WRONG_THREAD;
}
__attribute__((visibility("default")))
int RRPlatformAuxiliaryCancel(RRAuxiliaryOwner owner) {
    return NSThread.isMainThread ? RRAuxiliaryCancel(owner) : RR_AUX_WRONG_THREAD;
}
__attribute__((visibility("default")))
int RRPlatformAuxiliaryEnd(RRAuxiliaryOwner owner) {
    return NSThread.isMainThread ? RRAuxiliaryEnd(owner) : RR_AUX_WRONG_THREAD;
}
__attribute__((visibility("default")))
char *RRPlatformAuxiliaryStateJSON(void) {
    if (!NSThread.isMainThread) return strdup("{\"apiVersion\":1,\"active\":false,\"reason\":\"wrongThread\"}");
    RRAuxiliaryInputState value; RRAuxiliaryCopyState(&value);
    RRInputGateStats gate; RRInputGateCopyStats(&gate);
    BOOL video = (SDL_WasInit(SDL_INIT_VIDEO) & SDL_INIT_VIDEO) != 0;
    NSDictionary *state = @{@"apiVersion": @1, @"active": @(value.active != 0), @"allowed": @(value.allowed != 0),
        @"blocked": @(gate.blocked != 0), @"windowID": @(value.windowID), @"epoch": @(value.epoch), @"geometry": @(value.geometry),
        @"accepted": @(value.accepted), @"rejected": @(value.rejected), @"lastError": @(value.lastError),
        @"heldButtons": @(value.heldButtons), @"heldKeys": @(value.heldKeys), @"pendingReleases": @(value.pendingReleases),
        @"keyboardOwned": @(value.keyboardOwned != 0), @"screenKeyboardSupported": @(video && SDL_HasScreenKeyboardSupport()),
        @"textInputActive": @(video && SDL_IsTextInputActive()), @"relativeMouseMode": @(video && SDL_GetRelativeMouseMode())};
    NSData *data = [NSJSONSerialization dataWithJSONObject:state options:0 error:nil];
    return strdup([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
}
