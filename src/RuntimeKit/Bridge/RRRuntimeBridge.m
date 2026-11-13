#import "RRRuntimeBridge.h"
#import <dlfcn.h>
#include "../Native/RRAuxiliaryInput.h"
#include <math.h>
#include <limits.h>

static NSString *const RRRuntimeErrorDomain = @"RenReader.Runtime";
typedef int (*RRRunFunction)(const char *resourceDirectory, void *(*lookup)(void *, const char *));

// SDL2 guarantees this 72-byte public SysWM ABI: version, subsystem and a
// 64-byte native-info union. UIKit's first field is its UIWindow pointer.
// https://github.com/libsdl-org/SDL/blob/SDL2/include/SDL_syswm.h
typedef struct { uint8_t major, minor, patch; } RRSDLVersion;
typedef struct {
    RRSDLVersion version;
    int subsystem;
    union {
        struct { void *window; uint32_t framebuffer, colorbuffer, resolveFramebuffer; } uikit;
        uint8_t padding[64];
    } info;
} RRSDLSysWMInfo;
_Static_assert(sizeof(RRSDLSysWMInfo) == 72, "SDL2 native window ABI");

typedef struct {
    int (*begin)(RRAuxiliaryOwner, uint32_t, uint64_t, int);
    int (*geometry)(RRAuxiliaryOwner, uint64_t);
    int (*submit)(RRAuxiliaryOwner, uint64_t, int, int, double, double);
    int (*cancel)(RRAuxiliaryOwner);
    int (*end)(RRAuxiliaryOwner);
    char *(*snapshot)(void);
} RRBridgeAuxiliaryAPI;

@interface RRRuntimeBridge ()
@property(nonatomic, readwrite, copy) NSString *state;
@property(nonatomic, strong) NSMutableArray<NSString *> *commands;
@property(nonatomic, copy, nullable) NSString *pendingLaunch;
@property(nonatomic, strong, nullable) NSDictionary *configuration;
@property(nonatomic, weak, nullable) UIView *container;
@property(nonatomic, strong, nullable) UIViewController *surfaceController;
@property(nonatomic, strong, nullable) UIWindow *sdlWindow;
@property(nonatomic, assign) BOOL launching;
@property(nonatomic, assign) void *runtimeHandle;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSValue *> *runtimeHandles;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *runtimeEngineIdentities;
@property(nonatomic, assign) uint32_t backgroundWakeEvent;
@property(nonatomic, strong, nullable) NSDictionary *pendingResetEvent;
@property(nonatomic, assign) BOOL hostKeyboardBlocked;
@property(nonatomic, assign) BOOL surfaceRedraw;
@property(nonatomic, assign) BOOL auxiliaryBound;
@property(nonatomic, assign) BOOL auxiliaryLifecycleActive;
@property(nonatomic, assign) BOOL sceneLifecycleManaged;
@property(nonatomic, assign) BOOL readerSceneActive;
@property(nonatomic, assign) BOOL sceneLifecycleReady;
@property(nonatomic, assign) BOOL waitingForSceneForeground;
// 0 active, 1 resigning, 2 background, 3 entering foreground.
@property(nonatomic, assign) NSInteger sdlLifecyclePhase;
@property(nonatomic, assign) RRAuxiliaryOwner auxiliaryOwner;
@property(nonatomic, assign) uint64_t auxiliaryGeometry;
@property(nonatomic, assign) CGRect auxiliaryFrame;
@property(nonatomic, assign) CGSize auxiliaryBounds;
@property(nonatomic, assign) CGSize auxiliaryLogicalSize;
@property(nonatomic, assign) uint32_t auxiliaryWindowID;
- (NSInteger)cancelBoundAuxiliaryInput;
- (NSInteger)endBoundAuxiliaryInput;
- (void)sceneLifecycleResign;
- (void)sceneLifecycleBackground;
- (void)sceneLifecycleForeground;
- (void)sceneLifecycleActivate;
- (void)resumeDeferredInterpreterIfPossible;
- (void)cancelUnstartedSession;
@end

@implementation RRRuntimeBridge

+ (RRRuntimeBridge *)shared {
    static RRRuntimeBridge *instance;
    static dispatch_once_t token;
    dispatch_once(&token, ^{ instance = [[self alloc] init]; });
    return instance;
}

- (instancetype)init {
    if ((self = [super init])) {
        _state = @"idle";
        _commands = [NSMutableArray array];
        _runtimeHandles = [NSMutableDictionary dictionary];
        _runtimeEngineIdentities = [NSMutableDictionary dictionary];
        _hostKeyboardBlocked = YES;
        _auxiliaryLifecycleActive = YES;
        _readerSceneActive = YES;
        NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
        for (NSNotificationName name in @[UIApplicationWillResignActiveNotification, UIApplicationDidEnterBackgroundNotification, UIApplicationWillEnterForegroundNotification, UIApplicationDidBecomeActiveNotification, UIApplicationDidReceiveMemoryWarningNotification]) {
            [center addObserver:self selector:@selector(applicationLifecycle:) name:name object:nil];
        }
    }
    return self;
}

- (void)applicationLifecycle:(NSNotification *)notification {
    NSAssert(NSThread.isMainThread, @"SDL lifecycle belongs to the runtime owner thread");
    if (self.sceneLifecycleManaged && [notification.name isEqual:UIApplicationDidBecomeActiveNotification]) {
        [self resumeDeferredInterpreterIfPossible];
    }
    if (self.sceneLifecycleManaged && self.sceneLifecycleReady && ![notification.name isEqual:UIApplicationDidReceiveMemoryWarningNotification]) {
        if ([notification.name isEqual:UIApplicationWillResignActiveNotification] ||
            [notification.name isEqual:UIApplicationDidEnterBackgroundNotification]) {
            self.auxiliaryLifecycleActive = NO;
            [self cancelBoundAuxiliaryInput];
        } else if ([notification.name isEqual:UIApplicationDidBecomeActiveNotification]) {
            self.auxiliaryLifecycleActive = self.readerSceneActive;
        }
        [self applyHostKeyboardGate];
        // SDL may not yet be initialized during startup; reconcile at ready.
        if (!self.sceneLifecycleReady || !self.runtimeHandle || ![@[@"running", @"stopping"] containsObject:self.state]) return;
        if ([notification.name isEqual:UIApplicationWillResignActiveNotification]) [self sceneLifecycleResign];
        else if ([notification.name isEqual:UIApplicationDidEnterBackgroundNotification]) [self sceneLifecycleBackground];
        else if ([notification.name isEqual:UIApplicationWillEnterForegroundNotification] && self.readerSceneActive) [self sceneLifecycleForeground];
        else if ([notification.name isEqual:UIApplicationDidBecomeActiveNotification] && self.readerSceneActive) [self sceneLifecycleActivate];
        return;
    }
    if ([notification.name isEqual:UIApplicationWillResignActiveNotification] || [notification.name isEqual:UIApplicationDidEnterBackgroundNotification]) {
        self.auxiliaryLifecycleActive = NO;
        [self cancelBoundAuxiliaryInput];
    } else if ([notification.name isEqual:UIApplicationDidBecomeActiveNotification]) self.auxiliaryLifecycleActive = YES;
    if (!self.runtimeHandle || ![@[@"starting", @"running", @"stopping"] containsObject:self.state]) return;
    if ([notification.name isEqual:UIApplicationDidBecomeActiveNotification]) {
        void (*resync)(void) = dlsym(self.runtimeHandle, "RRPlatformResyncPhysicalKeyboard");
        if (resync) resync();
    }
    [self applyHostKeyboardGate];
    // The bundled SDL2 2.0.20 only forwards these in SDLUIKitDelegate. A SwiftUI
    // host owns a different delegate. Do not double-forward a future SDL host.
    if ([NSStringFromClass(UIApplication.sharedApplication.delegate.class) hasPrefix:@"SDLUIKit"]) return;
    NSDictionary *symbols = @{UIApplicationWillResignActiveNotification: @"SDL_OnApplicationWillResignActive", UIApplicationDidEnterBackgroundNotification: @"SDL_OnApplicationDidEnterBackground", UIApplicationWillEnterForegroundNotification: @"SDL_OnApplicationWillEnterForeground", UIApplicationDidBecomeActiveNotification: @"SDL_OnApplicationDidBecomeActive", UIApplicationDidReceiveMemoryWarningNotification: @"SDL_OnApplicationDidReceiveMemoryWarning"};
    NSString *symbol = symbols[notification.name];
    void (*forward)(void) = dlsym(self.runtimeHandle, symbol.UTF8String);
    if (forward) forward();
}

- (void)sceneLifecycleForward:(const char *)symbol {
    if ([NSStringFromClass(UIApplication.sharedApplication.delegate.class) hasPrefix:@"SDLUIKit"]) return;
    void (*forward)(void) = dlsym(self.runtimeHandle, symbol);
    if (forward) forward();
}
- (void)sceneLifecycleResign {
    if (self.sdlLifecyclePhase == 3) [self sceneLifecycleActivate];
    if (self.sdlLifecyclePhase != 0) return;
    [self sceneLifecycleForward:"SDL_OnApplicationWillResignActive"];
    self.sdlLifecyclePhase = 1;
}
- (void)sceneLifecycleBackground {
    [self sceneLifecycleResign];
    if (self.sdlLifecyclePhase != 1) return;
    [self sceneLifecycleForward:"SDL_OnApplicationDidEnterBackground"];
    self.sdlLifecyclePhase = 2;
}
- (void)sceneLifecycleForeground {
    if (self.sdlLifecyclePhase != 2) return;
    [self sceneLifecycleForward:"SDL_OnApplicationWillEnterForeground"];
    self.sdlLifecyclePhase = 3;
}
- (void)sceneLifecycleActivate {
    [self sceneLifecycleForeground];
    if (self.sdlLifecyclePhase != 1 && self.sdlLifecyclePhase != 3) return;
    void (*resync)(void) = dlsym(self.runtimeHandle, "RRPlatformResyncPhysicalKeyboard");
    if (resync) resync();
    [self sceneLifecycleForward:"SDL_OnApplicationDidBecomeActive"];
    self.sdlLifecyclePhase = 0;
}
- (BOOL)setReaderSceneActive:(BOOL)active sessionID:(NSString *)sessionID epoch:(uint64_t)epoch {
    NSAssert(NSThread.isMainThread, @"Reader scene lifecycle belongs to the runtime owner thread");
    if (!NSThread.isMainThread || ![self.configuration[@"sessionID"] isEqualToString:sessionID] ||
        [self.configuration[@"epoch"] unsignedLongLongValue] != epoch ||
        ![@[@"prepared", @"starting", @"running", @"stopping"] containsObject:self.state]) return NO;
    if ([@[@"prepared", @"starting"] containsObject:self.state] || !self.sceneLifecycleReady) {
        self.sceneLifecycleManaged = YES;
        self.readerSceneActive = active;
        self.auxiliaryLifecycleActive = active && UIApplication.sharedApplication.applicationState == UIApplicationStateActive;
        [self applyHostKeyboardGate];
        [self resumeDeferredInterpreterIfPossible];
        return YES;
    }
    if (!self.runtimeHandle) return NO;
    const char *symbols[] = {"SDL_OnApplicationWillResignActive", "SDL_OnApplicationDidEnterBackground",
                             "SDL_OnApplicationWillEnterForeground", "SDL_OnApplicationDidBecomeActive"};
    for (int i = 0; i < 4; i++) if (!dlsym(self.runtimeHandle, symbols[i])) return NO;
    if (!active && self.auxiliaryBound) {
        RRBridgeAuxiliaryAPI api;
        if (![self auxiliaryAPI:&api] || [self cancelBoundAuxiliaryInput] < 0) return NO;
    }
    self.sceneLifecycleManaged = YES;
    self.readerSceneActive = active;
    self.auxiliaryLifecycleActive = active && UIApplication.sharedApplication.applicationState == UIApplicationStateActive;
    if (!active) [self sceneLifecycleBackground];
    else if (UIApplication.sharedApplication.applicationState == UIApplicationStateActive) [self sceneLifecycleActivate];
    [self applyHostKeyboardGate];
    return YES;
}

- (void)applyHostKeyboardGate {
    void (*gate)(int) = self.runtimeHandle ? dlsym(self.runtimeHandle, "RRPlatformSetKeyboardBlocked") : NULL;
    BOOL blocked = self.hostKeyboardBlocked || !self.auxiliaryLifecycleActive || (self.sceneLifecycleManaged && !self.readerSceneActive)
        || UIApplication.sharedApplication.applicationState != UIApplicationStateActive
        || ![@[@"starting", @"running"] containsObject:self.state];
    if (gate) gate(blocked ? 1 : 0);
}

- (void)setHostKeyboardBlocked:(BOOL)blocked inContainerView:(UIView *)container {
    NSAssert(NSThread.isMainThread, @"Host input ownership belongs to the main thread");
    if (!NSThread.isMainThread || container != self.container) return;
    self.hostKeyboardBlocked = blocked;
    [self applyHostKeyboardGate];
}

- (NSString *)keyboardInputStateJSON {
    char *(*snapshot)(void) = self.runtimeHandle ? dlsym(self.runtimeHandle, "RRPlatformKeyboardInputStateJSON") : NULL;
    if (!snapshot) return @"{\"available\":false,\"blocked\":true}";
    char *value = snapshot();
    NSString *result = value ? [NSString stringWithUTF8String:value] : @"{}";
    free(value);
    return result;
}

- (BOOL)auxiliaryAPI:(RRBridgeAuxiliaryAPI *)api {
    if (!self.runtimeHandle) return NO;
    *api = (RRBridgeAuxiliaryAPI){
        .begin = dlsym(self.runtimeHandle, "RRPlatformAuxiliaryBegin"),
        .geometry = dlsym(self.runtimeHandle, "RRPlatformAuxiliarySetGeometry"),
        .submit = dlsym(self.runtimeHandle, "RRPlatformAuxiliarySubmit"),
        .cancel = dlsym(self.runtimeHandle, "RRPlatformAuxiliaryCancel"),
        .end = dlsym(self.runtimeHandle, "RRPlatformAuxiliaryEnd"),
        .snapshot = dlsym(self.runtimeHandle, "RRPlatformAuxiliaryStateJSON")};
    return api->begin && api->geometry && api->submit && api->cancel && api->end && api->snapshot;
}

- (NSInteger)cancelBoundAuxiliaryInput {
    RRBridgeAuxiliaryAPI api;
    return self.auxiliaryBound && [self auxiliaryAPI:&api] ? api.cancel(self.auxiliaryOwner) : RR_AUX_UNCHANGED;
}

- (NSInteger)endBoundAuxiliaryInput {
    RRBridgeAuxiliaryAPI api;
    NSInteger result = self.auxiliaryBound && [self auxiliaryAPI:&api] ? api.end(self.auxiliaryOwner) : RR_AUX_UNCHANGED;
    if (result >= 0 || result == RR_AUX_STALE_OWNER) {
        self.auxiliaryBound = NO;
        self.auxiliaryOwner = (RRAuxiliaryOwner){0};
        self.auxiliaryGeometry = 0; self.auxiliaryWindowID = 0;
        self.auxiliaryFrame = CGRectNull; self.auxiliaryBounds = self.auxiliaryLogicalSize = CGSizeZero;
    }
    return result;
}

- (BOOL)auxiliarySessionMatches:(NSString *)sessionID epoch:(uint64_t)epoch container:(UIView *)container {
    return NSThread.isMainThread && container && container == self.container && self.configuration
        && [sessionID isEqual:self.configuration[@"sessionID"]] && epoch == [self.configuration[@"epoch"] unsignedLongLongValue];
}

/// Only live SDL focus pointers whose public SysWM data matches the adopted
/// UIWindow are accepted. No ID scanning or process-wide window guessing.
- (void *)auxiliarySDLWindow {
    if (!self.sdlWindow || !self.surfaceController || self.surfaceController.view.superview != self.container) return NULL;
    void *(*keyboardFocus)(void) = dlsym(self.runtimeHandle, "SDL_GetKeyboardFocus");
    void *(*mouseFocus)(void) = dlsym(self.runtimeHandle, "SDL_GetMouseFocus");
    void (*version)(RRSDLVersion *) = dlsym(self.runtimeHandle, "SDL_GetVersion");
    int (*info)(void *, RRSDLSysWMInfo *) = dlsym(self.runtimeHandle, "SDL_GetWindowWMInfo");
    if (!keyboardFocus || !mouseFocus || !version || !info) return NULL;
    void *keyboard = keyboardFocus();
    void *windows[] = {keyboard, mouseFocus()};
    for (int i = 0; i < 2; ++i) {
        void *window = windows[i];
        if (!window || window != keyboard) continue; // Native auxiliary keys require this exact keyboard focus too.
        RRSDLSysWMInfo native = {0}; version(&native.version);
        if (info(window, &native) && native.subsystem == 5 && native.info.uikit.window == (__bridge void *)self.sdlWindow) return window;
    }
    return NULL;
}

- (NSInteger)refreshAuxiliaryGeometryForWindow:(void *)window api:(RRBridgeAuxiliaryAPI *)api {
    void (*size)(void *, int *, int *) = self.runtimeHandle ? dlsym(self.runtimeHandle, "SDL_GetWindowSize") : NULL;
    uint32_t (*identifier)(void *) = self.runtimeHandle ? dlsym(self.runtimeHandle, "SDL_GetWindowID") : NULL;
    CGRect frame = self.surfaceController.view.frame;
    CGSize bounds = self.surfaceController.view.bounds.size;
    int width = 0, height = 0;
    if (window && size) size(window, &width, &height);
    CGSize logical = CGSizeMake(width, height);
    if (!self.auxiliaryGeometry || !CGRectEqualToRect(self.auxiliaryFrame, frame) || !CGSizeEqualToSize(self.auxiliaryBounds, bounds)
        || !CGSizeEqualToSize(self.auxiliaryLogicalSize, logical)) {
        if (self.auxiliaryGeometry == UINT64_MAX) return RR_AUX_INVALID;
        self.auxiliaryGeometry++;
        self.auxiliaryFrame = frame; self.auxiliaryBounds = bounds; self.auxiliaryLogicalSize = logical;
    }
    if (self.auxiliaryBound) {
        NSInteger result = api->geometry(self.auxiliaryOwner, self.auxiliaryGeometry);
        if (result < 0) return result;
    }
    if (!window || !size || !identifier || !identifier(window) || width <= 0 || height <= 0 || !isfinite(bounds.width) || !isfinite(bounds.height)
        || bounds.width <= 0 || bounds.height <= 0 || fabs(bounds.width - width) > 1.0 || fabs(bounds.height - height) > 1.0) return RR_AUX_UNAVAILABLE;
    return RR_AUX_ACCEPTED;
}

- (NSDictionary<NSString *, id> *)auxiliaryUnavailable:(NSString *)reason {
    return @{@"available": @NO, @"virtualMouse": @NO, @"softwareKeys": @NO, @"screenKeyboard": @NO,
             @"geometry": @(self.auxiliaryGeometry), @"reason": reason};
}

- (NSDictionary<NSString *, id> *)auxiliaryInputStateForSessionID:(NSString *)sessionID epoch:(uint64_t)epoch inContainerView:(UIView *)container {
    if (!NSThread.isMainThread) return @{@"available": @NO, @"reason": @"wrongThread"};
    if (![self auxiliarySessionMatches:sessionID epoch:epoch container:container]) return [self auxiliaryUnavailable:@"staleSession"];
    if (![@[@"enhanced", @"minimal"] containsObject:self.configuration[@"launchMode"]]) return [self auxiliaryUnavailable:@"modeDisabled"];
    if (![self.state isEqual:@"running"] || !self.auxiliaryLifecycleActive || ![self isApplicationActive]
        || !container.window || !self.surfaceController || self.surfaceController.view.superview != container) return [self auxiliaryUnavailable:@"notRunning"];
    RRBridgeAuxiliaryAPI api;
    if (![self auxiliaryAPI:&api]) return [self auxiliaryUnavailable:@"componentUnavailable"];
    void *window = [self auxiliarySDLWindow];
    NSInteger geometryResult = [self refreshAuxiliaryGeometryForWindow:window api:&api];
    if (geometryResult < 0) return [self auxiliaryUnavailable:geometryResult == RR_AUX_QUEUE_FULL ? @"cleanupPending" : @"geometryNotSynchronized"];
    uint32_t (*identifier)(void *) = dlsym(self.runtimeHandle, "SDL_GetWindowID");
    uint32_t windowID = identifier(window);
    if (!self.auxiliaryBound) {
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:sessionID];
        if (!uuid) return [self auxiliaryUnavailable:@"invalidSessionToken"];
        uuid_t bytes; [uuid getUUIDBytes:bytes];
        RRAuxiliaryOwner owner = {.epoch = epoch};
        memcpy(&owner.sessionHigh, bytes, 8); memcpy(&owner.sessionLow, bytes + 8, 8);
        if (api.begin(owner, windowID, self.auxiliaryGeometry, 1) < 0) return [self auxiliaryUnavailable:@"beginFailed"];
        self.auxiliaryOwner = owner; self.auxiliaryWindowID = windowID; self.auxiliaryBound = YES;
    } else if (self.auxiliaryWindowID != windowID) return [self auxiliaryUnavailable:@"windowChanged"];
    char *json = api.snapshot();
    NSData *data = json ? [[NSString stringWithUTF8String:json] dataUsingEncoding:NSUTF8StringEncoding] : nil;
    free(json);
    NSDictionary *value = data.length > 0 && data.length <= 8192 ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    if (![value isKindOfClass:NSDictionary.class] || [value[@"apiVersion"] integerValue] != 1 || ![value[@"active"] boolValue]
        || ![value[@"allowed"] boolValue] || [value[@"epoch"] unsignedLongLongValue] != epoch || [value[@"windowID"] unsignedIntValue] != windowID
        || [value[@"geometry"] unsignedLongLongValue] != self.auxiliaryGeometry) return [self auxiliaryUnavailable:@"nativeStateMismatch"];
    NSMutableDictionary *result = [value mutableCopy];
    result[@"available"] = @YES;
    result[@"virtualMouse"] = @(![value[@"relativeMouseMode"] boolValue]);
    result[@"softwareKeys"] = @YES;
    result[@"screenKeyboard"] = @([value[@"screenKeyboardSupported"] boolValue]);
    return result;
}

- (NSInteger)submitAuxiliaryInput:(NSInteger)kind code:(NSInteger)code x:(double)x y:(double)y geometry:(uint64_t)geometry sessionID:(NSString *)sessionID epoch:(uint64_t)epoch inContainerView:(UIView *)container {
    if (!NSThread.isMainThread) return RR_AUX_WRONG_THREAD;
    if (![self auxiliarySessionMatches:sessionID epoch:epoch container:container]) return RR_AUX_STALE_OWNER;
    if (![@[@"enhanced", @"minimal"] containsObject:self.configuration[@"launchMode"]]) return RR_AUX_MODE_DISABLED;
    if (self.hostKeyboardBlocked || !self.auxiliaryLifecycleActive || ![self isApplicationActive] || ![self.state isEqual:@"running"]) return RR_AUX_BLOCKED;
    if (kind < RR_AUX_MOVE || kind > RR_AUX_SCREEN_KEYBOARD || code < INT_MIN || code > INT_MAX || !isfinite(x) || !isfinite(y)) return RR_AUX_INVALID;
    NSDictionary *state = [self auxiliaryInputStateForSessionID:sessionID epoch:epoch inContainerView:container];
    if (![state[@"available"] boolValue]) return RR_AUX_UNAVAILABLE;
    if (geometry != self.auxiliaryGeometry) return RR_AUX_STALE_GEOMETRY;
    if ((kind == RR_AUX_MOVE || kind == RR_AUX_BUTTON || kind == RR_AUX_WHEEL) && ![state[@"virtualMouse"] boolValue]) return RR_AUX_UNAVAILABLE;
    RRBridgeAuxiliaryAPI api;
    if (![self auxiliaryAPI:&api]) return RR_AUX_UNAVAILABLE;
    return api.submit(self.auxiliaryOwner, geometry, (int)kind, (int)code, x, y);
}

- (NSInteger)cancelAuxiliaryInputForSessionID:(NSString *)sessionID epoch:(uint64_t)epoch inContainerView:(UIView *)container {
    if (!NSThread.isMainThread) return RR_AUX_WRONG_THREAD;
    if (![self auxiliarySessionMatches:sessionID epoch:epoch container:container]) return RR_AUX_STALE_OWNER;
    return [self cancelBoundAuxiliaryInput];
}

- (BOOL)wakeBackgroundSave {
    uint32_t (*registerEvents)(int) = dlsym(self.runtimeHandle, "SDL_RegisterEvents");
    int (*pushEvent)(void *) = dlsym(self.runtimeHandle, "SDL_PushEvent");
    if (!registerEvents || !pushEvent) return NO;
    if (!self.backgroundWakeEvent) self.backgroundWakeEvent = registerEvents(1);
    if (self.backgroundWakeEvent == UINT32_MAX) return NO;
    union { uint32_t type; uint8_t bytes[56]; void *alignment; } event = {0};
    event.type = self.backgroundWakeEvent;
    return pushEvent(&event) == 1;
}

- (NSString *)runtimeSuffix {
    NSString *runtimeID = self.configuration[@"runtimeID"] ?: @"8.5.3";
    return [runtimeID stringByReplacingOccurrencesOfString:@"." withString:@""];
}

- (NSURL *)frameworkURL {
    return [[NSBundle mainBundle].privateFrameworksURL URLByAppendingPathComponent:[NSString stringWithFormat:@"RRRuntime%@.framework", self.runtimeSuffix]];
}

- (NSURL *)resourcesURL {
    return [[NSBundle mainBundle] URLForResource:[@"RenPy" stringByAppendingString:self.runtimeSuffix] withExtension:@"bundle"];
}

- (BOOL)runtimeAvailable {
    return [[NSFileManager defaultManager] fileExistsAtPath:[self frameworkURL].path]
        && [[NSFileManager defaultManager] fileExistsAtPath:[[self resourcesURL] URLByAppendingPathComponent:@"base/main.py"].path];
}

- (BOOL)fail:(NSString *)message error:(NSError **)error {
    if (error) *error = [NSError errorWithDomain:RRRuntimeErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: message}];
    return NO;
}

- (BOOL)checkEngineSelectionForRuntimeID:(NSString *)runtimeID overlaySHA256:(NSString *)overlaySHA256 error:(NSError **)error {
    NSAssert(NSThread.isMainThread, @"Engine selection belongs to the runtime owner thread");
    if (overlaySHA256 && (overlaySHA256.length != 64 || [overlaySHA256 rangeOfCharacterFromSet:
        [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location != NSNotFound)) {
        return [self fail:@"自定义引擎的内容摘要无效。" error:error];
    }
    NSString *selected = overlaySHA256 ?: @"stock";
    NSString *loaded = self.runtimeEngineIdentities[runtimeID];
    if (loaded && ![loaded isEqual:selected]) {
        return [self fail:@"此运行环境已载入另一份引擎。请完全关闭并重新打开 App 后，再阅读这个组合；原进度已保留。" error:error];
    }
    return YES;
}

- (BOOL)prepareGameAtURL:(NSURL *)gameDirectory saveDirectoryURL:(NSURL *)saveDirectory sessionID:(NSString *)sessionID epoch:(uint64_t)epoch error:(NSError **)error {
    return [self prepareGameAtURL:gameDirectory saveDirectoryURL:saveDirectory tokenDirectoryURL:[[saveDirectory URLByDeletingLastPathComponent] URLByAppendingPathComponent:@"Tokens" isDirectory:YES] runtimeID:@"8.5.3" sessionID:sessionID epoch:epoch error:error];
}

- (BOOL)prepareGameAtURL:(NSURL *)gameDirectory saveDirectoryURL:(NSURL *)saveDirectory tokenDirectoryURL:(NSURL *)tokenDirectory runtimeID:(NSString *)runtimeID sessionID:(NSString *)sessionID epoch:(uint64_t)epoch error:(NSError **)error {
    NSAssert(NSThread.isMainThread, @"Runtime ownership is the main OS thread");
    NSDictionary *storyPatch = self.storySessionPatch;
    self.storySessionPatch = nil;
    if (![@[@"idle", @"prepared"] containsObject:self.state]) return [self fail:@"The previous runtime session has not finished resetting." error:error];
    BOOL wantsAutomaticResume = self.resumeAutomatically;
    NSString *requestedStartupSlot = self.startupSaveSlot;
    self.resumeAutomatically = NO;
    self.startupSaveSlot = nil;
    self.checkpointSelectionHandler = nil;
    NSInteger auxiliaryEnd = [self endBoundAuxiliaryInput];
    if (auxiliaryEnd < 0 && auxiliaryEnd != RR_AUX_STALE_OWNER) return [self fail:@"The previous auxiliary inputs are still being released. Retry after the runtime drains its event queue." error:error];
    NSSet *supported = [NSSet setWithArray:@[@"7.4.11", @"7.5.3", @"7.6.3", @"7.7.3", @"7.8.4", @"7.8.7", @"7.8.8", @"8.0.3", @"8.1.3", @"8.2.3", @"8.3.4", @"8.3.7", @"8.4.1", @"8.5.0", @"8.5.2", @"8.5.3", @"8.5.4"]];
    if (![supported containsObject:runtimeID]) return [self fail:@"Unknown exact runtime profile." error:error];
    if (![self checkEngineSelectionForRuntimeID:runtimeID overlaySHA256:self.engineOverlayManifestSHA256 error:error]) return NO;
    if ((self.engineBaseDirectoryURL == nil) != (self.engineOverlayManifestSHA256 == nil)) {
        return [self fail:@"自定义引擎目录与身份不一致。" error:error];
    }
    if (self.engineBaseDirectoryURL) {
        BOOL engineDirectory = NO;
        if (!self.engineBaseDirectoryURL.isFileURL ||
            ![[NSFileManager defaultManager] fileExistsAtPath:self.engineBaseDirectoryURL.path isDirectory:&engineDirectory] || !engineDirectory) {
            return [self fail:@"自定义引擎尚未准备好。" error:error];
        }
        NSString *suffix = [runtimeID stringByReplacingOccurrencesOfString:@"." withString:@""];
        NSURL *bundle = [[NSBundle mainBundle] URLForResource:[@"RenPy" stringByAppendingString:suffix] withExtension:@"bundle"];
        NSData *profileData = bundle ? [NSData dataWithContentsOfURL:[bundle URLByAppendingPathComponent:@"runtime-profile.json"]] : nil;
        NSDictionary *profile = profileData ? [NSJSONSerialization JSONObjectWithData:profileData options:0 error:nil] : nil;
        if (![profile isKindOfClass:NSDictionary.class] || ![profile[@"engineOverlaySchemaVersion"] isEqual:@1]) {
            return [self fail:@"当前运行时资源尚未接入自定义引擎。" error:error];
        }
    }
    NSString *mode = self.launchMode ?: @"enhanced";
    if (![@[@"enhanced", @"minimal", @"nativeCompatibility"] containsObject:mode]) return [self fail:@"Unknown reader launch mode." error:error];
    if (storyPatch) {
        // Keep the bridge closed until host installation and cleanup are certified.
        static const BOOL certifiedStoryHost = YES;
        if (!certifiedStoryHost) return [self fail:@"当前运行时尚未认证作品修复。" error:error];
        NSSet *fingerprints = [NSSet setWithArray:@[
            @"3e409438f9bc40d464eae86051114aae1802ffcbba02896f2dbd52a105fc5cdb",
            @"214852f84ff083e9fa3b2a39b5e4aeab07b8f365c005a052b3a08161ce8dafc2",
            @"caea8bf76be7841f991b2b1c97cdb8d8f696e3c5f7af46b8b6bb48ff35bdcc88",
            @"db1942a50647e20de2badb00fd76a0b2c15bbf0597ff43de1022645b531c769c",
            @"55ac2293cda2d0a4b2b388334b05c7df383072f618fa1329c23a5df5cb163aee",
            @"b0d0d3c81676734ad55f56f19030673ed5cb1211861c3b97cbdeca476ce80aa7"
        ]];
        NSURL *bundle = [[NSBundle mainBundle] URLForResource:@"RenPy853" withExtension:@"bundle"];
        NSData *data = bundle ? [NSData dataWithContentsOfURL:[bundle URLByAppendingPathComponent:@"runtime-profile.json"]] : nil;
        NSDictionary *profile = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (![runtimeID isEqualToString:@"8.5.3"] || ![mode isEqualToString:@"enhanced"] || self.engineOverlayManifestSHA256 ||
            ![storyPatch[@"id"] isEqual:@"compiled-story-quick-continue-v1"] || ![storyPatch[@"fingerprint"] isKindOfClass:NSString.class] ||
            ![fingerprints containsObject:storyPatch[@"fingerprint"]] ||
            ![storyPatch[@"sessionID"] isEqual:sessionID] || ![storyPatch[@"epoch"] isEqual:@(epoch)] ||
            ![profile isKindOfClass:NSDictionary.class] || ![profile[@"storySessionPatchSchemaVersion"] isEqual:@2]) {
            return [self fail:@"当前会话的作品修复身份无效。" error:error];
        }
    }
    NSURL *multiPersistent = self.multiPersistentDirectoryURL ?: [saveDirectory URLByAppendingPathComponent:@"MultiPersistent" isDirectory:YES];
    if (!multiPersistent.isFileURL) return [self fail:@"The series state directory is invalid." error:error];
    BOOL directory = NO;
    if (!gameDirectory.isFileURL || ![[NSFileManager defaultManager] fileExistsAtPath:gameDirectory.path isDirectory:&directory] || !directory) return [self fail:@"The game directory is unavailable." error:error];
    if (!saveDirectory.isFileURL || !tokenDirectory.isFileURL || !sessionID.length) return [self fail:@"The session configuration is invalid." error:error];
    if (![[NSFileManager defaultManager] createDirectoryAtURL:saveDirectory withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    NSURL *log = [[saveDirectory URLByDeletingLastPathComponent] URLByAppendingPathComponent:@"Logs" isDirectory:YES];
    if (![[NSFileManager defaultManager] createDirectoryAtURL:log withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    if (![[NSFileManager defaultManager] createDirectoryAtURL:tokenDirectory withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    if (![[NSFileManager defaultManager] createDirectoryAtURL:multiPersistent withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    NSMutableDictionary *configuration = [@{@"gameDirectory": gameDirectory.path, @"saveDirectory": saveDirectory.path, @"tokenDirectory": tokenDirectory.path, @"runtimeID": runtimeID, @"startupSaveSlot": requestedStartupSlot ?: NSNull.null, @"resumeAutomatically": @(wantsAutomaticResume), @"logDirectory": log.path, @"sessionID": sessionID, @"epoch": @(epoch), @"preserveScriptIdentity": @(self.scriptIdentityCaptureHandler != nil), @"launchMode": mode, @"multiPersistentDirectory": multiPersistent.path, @"engineOverlaySHA256": self.engineOverlayManifestSHA256 ?: NSNull.null, @"engineBaseDirectory": self.engineBaseDirectoryURL.path ?: NSNull.null} mutableCopy];
    if (storyPatch) {
        configuration[@"verifiedBuiltinPatchID"] = storyPatch[@"id"];
        configuration[@"verifiedContentFingerprint"] = storyPatch[@"fingerprint"];
    }
    self.configuration = configuration;
    self.sceneLifecycleManaged = NO;
    self.readerSceneActive = YES;
    self.sdlLifecyclePhase = 0;
    self.sceneLifecycleReady = NO;
    self.waitingForSceneForeground = NO;
    if (!self.runtimeAvailable) return [self fail:@"The exact Ren'Py runtime and resources have not been bundled. Run Scripts/runtime/build_runtime.py --version <profile>." error:error];
    [self.commands removeAllObjects];
    self.backgroundWakeEvent = 0;
    self.pendingResetEvent = nil;
    self.surfaceRedraw = NO;
    self.auxiliaryLifecycleActive = UIApplication.sharedApplication.applicationState == UIApplicationStateActive;
    self.state = @"prepared";
    return YES;
}

- (BOOL)startInContainerView:(UIView *)container error:(NSError **)error {
    NSAssert(NSThread.isMainThread, @"Runtime ownership is the main OS thread");
    if (![self.state isEqualToString:@"prepared"] || !container.window) return [self fail:@"Mount the reader container in a window before starting a prepared session." error:error];
    self.container = container;
    self.hostKeyboardBlocked = YES;
    NSMutableDictionary *launch = [self.configuration mutableCopy];
    launch[@"preserveScriptIdentity"] = @(self.scriptIdentityCaptureHandler != nil);
    self.configuration = launch;
    NSData *json = [NSJSONSerialization dataWithJSONObject:self.configuration options:0 error:error];
    if (!json) return NO;
    self.pendingLaunch = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    self.state = @"starting";
    if (!self.launching) {
        self.launching = YES;
        // A never-returning engine inside a dispatched main-queue block prevents
        // that queue from draining during SDL's nested UIKit run-loop pumping.
        [self performSelector:@selector(runInterpreter) withObject:nil afterDelay:0.0];
    }
    return YES;
}

- (void)runInterpreter {
    if (self.sceneLifecycleManaged && (!self.readerSceneActive || UIApplication.sharedApplication.applicationState != UIApplicationStateActive)) {
        self.waitingForSceneForeground = YES;
        [self emit:@{@"type": @"runtimeStartDeferred"}];
        return;
    }
    // SDL's iOS GL function loader queries process-visible graphics symbols.
    // MetalANGLE is the one shared graphics backend, never a Python ABI image.
    NSURL *angleURL = [[NSBundle mainBundle].privateFrameworksURL URLByAppendingPathComponent:@"MetalANGLE.framework/MetalANGLE"];
    dlopen(angleURL.path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL);
    NSURL *framework = [self frameworkURL];
    NSString *executable = [[NSBundle bundleWithURL:framework] executablePath];
    self.runtimeHandle = self.runtimeHandles[self.runtimeSuffix].pointerValue;
    if (!self.runtimeHandle) {
        self.runtimeHandle = dlopen(executable.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
        if (self.runtimeHandle) self.runtimeHandles[self.runtimeSuffix] = [NSValue valueWithPointer:self.runtimeHandle];
    }
    NSString *symbol = [NSString stringWithFormat:@"RR%@Run", self.runtimeSuffix];
    RRRunFunction run = self.runtimeHandle ? (RRRunFunction)dlsym(self.runtimeHandle, symbol.UTF8String) : NULL;
    void *keyboardGate = self.runtimeHandle ? dlsym(self.runtimeHandle, "RRPlatformSetKeyboardBlocked") : NULL;
    if (!run || !keyboardGate) {
        self.launching = NO;
        self.state = @"quarantined";
        [self emit:@{@"type": @"error", @"message": !run ? @"Unable to load the bundled runtime entry point." : @"The bundled keyboard input isolation component is missing; rebuild the matching runtime platform."}];
        return;
    }
    [self applyHostKeyboardGate];
    self.runtimeEngineIdentities[self.configuration[@"runtimeID"]] = self.configuration[@"engineOverlaySHA256"] == NSNull.null
        ? @"stock" : self.configuration[@"engineOverlaySHA256"];
    int result = run([self resourcesURL].path.fileSystemRepresentation, dlsym);
    [self endBoundAuxiliaryInput];
    self.scriptIdentityCaptureHandler = nil; self.checkpointSelectionHandler = nil; self.resumeAutomatically = NO;
    self.launching = NO;
    if (result == 0 && self.pendingResetEvent && [self.state isEqualToString:@"resetting"]) {
        NSDictionary *reset = self.pendingResetEvent;
        self.pendingResetEvent = nil;
        self.state = @"idle";
        [self emit:reset];
    } else {
        self.pendingResetEvent = nil;
        self.state = @"quarantined";
        [self emit:@{@"type": @"error", @"message": @"The embedded session failed to reset and requires a fresh application launch.", @"status": @(result)}];
    }
}

- (void)resumeDeferredInterpreterIfPossible {
    if (!self.waitingForSceneForeground || !self.readerSceneActive ||
        UIApplication.sharedApplication.applicationState != UIApplicationStateActive || ![self.state isEqualToString:@"starting"]) return;
    self.waitingForSceneForeground = NO;
    [self performSelector:@selector(runInterpreter) withObject:nil afterDelay:0.0];
}

- (BOOL)submitCommandJSON:(NSString *)command error:(NSError **)error {
    NSAssert(NSThread.isMainThread, @"Runtime ownership is the main OS thread");
    if (![command isKindOfClass:NSString.class]) return [self fail:@"The runtime command is invalid." error:error];
    NSData *encoded = [command dataUsingEncoding:NSUTF8StringEncoding];
    if (!encoded) return [self fail:@"The runtime command is not valid UTF-8." error:error];
    if (encoded.length > 65536) return [self fail:@"The runtime command exceeds the size limit." error:error];
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:encoded options:0 error:error];
    if (![value isKindOfClass:NSDictionary.class] || ![value[@"sessionID"] isEqual:self.configuration[@"sessionID"]] || ![value[@"epoch"] isEqual:self.configuration[@"epoch"]]) return [self fail:@"The runtime command belongs to a stale session." error:error];
    if (![@[@"running", @"starting", @"stopping"] containsObject:self.state]) return [self fail:@"The runtime is not accepting commands." error:error];
    if (self.commands.count >= 256) return [self fail:@"The runtime command queue is full. Retry after the outstanding command finishes." error:error];
    [self.commands addObject:command];
    NSDictionary *payload = [value[@"payload"] isKindOfClass:NSDictionary.class] ? value[@"payload"] : nil;
    if (![self isApplicationActive] && [value[@"type"] isEqual:@"save"] && [payload[@"slot"] isEqual:@"rr_background"] && ![self wakeBackgroundSave]) {
        [self.commands removeLastObject];
        return [self fail:@"Unable to wake the suspended runtime for its background save." error:error];
    }
    return YES;
}

- (void)requestStopSaving:(BOOL)save {
    NSAssert(NSThread.isMainThread, @"Runtime ownership is the main OS thread");
    if (![@[@"starting", @"running"] containsObject:self.state]) return;
    if ([self.state isEqualToString:@"starting"] && self.waitingForSceneForeground) {
        [self cancelUnstartedSession];
        return;
    }
    [self cancelBoundAuxiliaryInput];
    NSDictionary *request = @{@"schemaVersion": @1, @"sessionID": self.configuration[@"sessionID"], @"epoch": self.configuration[@"epoch"], @"requestID": NSUUID.UUID.UUIDString, @"type": @"stop", @"payload": @{@"save": @(save)}};
    NSString *json = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:request options:0 error:nil] encoding:NSUTF8StringEncoding];
    // Stop has reserved admission and is handled before ordinary tool commands.
    [self.commands insertObject:json atIndex:0];
    self.state = @"stopping";
    [self applyHostKeyboardGate];
}

- (void)cancelPreparedSession {
    NSAssert(NSThread.isMainThread, @"Runtime ownership is the main OS thread");
    if (![self.state isEqualToString:@"prepared"] || self.launching) return;
    [self cancelUnstartedSession];
}

- (void)cancelUnstartedSession {
    [self endBoundAuxiliaryInput];
    [self.commands removeAllObjects];
    self.pendingLaunch = nil;
    self.waitingForSceneForeground = NO;
    self.launching = NO;
    self.surfaceRedraw = NO;
    self.state = @"idle";
    self.scriptIdentityCaptureHandler = nil; self.checkpointSelectionHandler = nil; self.resumeAutomatically = NO;
    [self emit:@{@"type": @"didReset"}];
    self.configuration = nil;
    self.container = nil;
}

- (NSString *)waitForLaunchJSON {
    NSAssert(NSThread.isMainThread, @"The Python adapter must stay on the runtime owner thread");
    while (!self.pendingLaunch) {
        @autoreleasepool { [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.02]]; }
    }
    NSString *launch = self.pendingLaunch;
    self.pendingLaunch = nil;
    return launch;
}

- (NSString *)takeCommandJSON {
    NSAssert(NSThread.isMainThread, @"The Python adapter must stay on the runtime owner thread");
    if (!self.commands.count) return nil;
    NSString *command = self.commands.firstObject;
    [self.commands removeObjectAtIndex:0];
    return command;
}

- (BOOL)isApplicationActive {
    NSAssert(NSThread.isMainThread, @"Application state is read on the runtime owner thread");
    return UIApplication.sharedApplication.applicationState == UIApplicationStateActive && (!self.sceneLifecycleManaged || self.readerSceneActive);
}

- (nullable NSString *)chooseResumeCheckpointJSON:(NSString *)requestJSON {
    // Same-stack, file-only callback. Never dispatch to the main queue or reenter UIKit.
    if (!NSThread.isMainThread || ![self.state isEqualToString:@"starting"] || ![requestJSON isKindOfClass:NSString.class]) return nil;
    NSData *data = [requestJSON dataUsingEncoding:NSUTF8StringEncoding];
    if (!data || data.length > 8192) return nil;
    NSDictionary *request = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![request isKindOfClass:NSDictionary.class] ||
        ![request[@"sessionID"] isEqual:self.configuration[@"sessionID"]] ||
        ![request[@"epoch"] isEqual:self.configuration[@"epoch"]] ||
        ![self.configuration[@"resumeAutomatically"] boolValue] || !self.checkpointSelectionHandler) return nil;
    NSString *slot = self.checkpointSelectionHandler(self.configuration[@"sessionID"], [self.configuration[@"epoch"] unsignedLongLongValue], requestJSON);
    return [@[@"rr_suspend", @"rr_background"] containsObject:slot ?: @""] ? slot : nil;
}

- (nullable NSString *)captureScriptIdentityJSON:(NSString *)requestJSON {
    // Direct same-stack invocation: never dispatch to the main queue or pump UIKit here.
    if (!NSThread.isMainThread) return @"Compiled script identity capture requires the runtime owner thread.";
    if (![requestJSON isKindOfClass:NSString.class]) return @"Compiled script identity request is invalid.";
    NSData *data = [requestJSON dataUsingEncoding:NSUTF8StringEncoding];
    if (!data || data.length > 4u * 1024u * 1024u) return @"Compiled script identity request exceeds its size limit.";
    NSDictionary *request = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![request isKindOfClass:NSDictionary.class]
        || ![request[@"sessionID"] isKindOfClass:NSString.class]
        || ![request[@"epoch"] isKindOfClass:NSNumber.class]
        || ![request[@"sessionID"] isEqual:self.configuration[@"sessionID"]]
        || ![request[@"epoch"] isEqual:self.configuration[@"epoch"]]) {
        return @"Compiled script identity request belongs to a stale session.";
    }
    if (![@[@"starting", @"running", @"stopping"] containsObject:self.state]) return @"The compiler identity session is not active.";
    if (![@[@"script", @"module"] containsObject:request[@"phase"]]) return @"Invalid compiler identity phase.";
    NSArray *paths = request[@"requiredCompiledPaths"];
    if (![paths isKindOfClass:NSArray.class] || paths.count > 10000) return @"Invalid compiled output list.";
    for (id path in paths) if (![path isKindOfClass:NSString.class]) return @"Invalid compiled output path.";
    NSData *canonical = [NSJSONSerialization dataWithJSONObject:paths options:NSJSONWritingWithoutEscapingSlashes error:nil];
    if (!canonical || canonical.length > 4u * 1024u * 1024u) return @"Compiled output list exceeds its size limit.";
    NSString * _Nullable (^handler)(NSString *, uint64_t, NSString *) = self.scriptIdentityCaptureHandler;
    if (!handler) return @"The host has not supplied a compiled script identity capture handler.";
    return handler(self.configuration[@"sessionID"], [self.configuration[@"epoch"] unsignedLongLongValue], [[NSString alloc] initWithData:canonical encoding:NSUTF8StringEncoding]);
}

- (NSString *)takeBackgroundSaveJSON {
    NSAssert(NSThread.isMainThread, @"Background save polling stays on the runtime owner thread");
    for (NSUInteger index = 0; index < self.commands.count; index++) {
        NSString *command = self.commands[index];
        NSDictionary *value = [NSJSONSerialization JSONObjectWithData:[command dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        NSDictionary *payload = [value[@"payload"] isKindOfClass:NSDictionary.class] ? value[@"payload"] : nil;
        if ([value[@"type"] isEqual:@"save"] && [payload[@"slot"] isEqual:@"rr_background"]) {
            [self.commands removeObjectAtIndex:index];
            return command;
        }
    }
    return nil;
}

- (void)emit:(NSDictionary *)event {
    NSMutableDictionary *value = [event mutableCopy];
    value[@"sessionID"] = self.configuration[@"sessionID"] ?: @"";
    value[@"epoch"] = self.configuration[@"epoch"] ?: @0;
    void (^handler)(NSDictionary *) = self.eventHandler;
    if (handler) dispatch_async(dispatch_get_main_queue(), ^{ handler(value); });
}

- (void)emitEventJSON:(NSString *)event {
    NSAssert(NSThread.isMainThread, @"The Python adapter must stay on the runtime owner thread");
    if (![event isKindOfClass:NSString.class]) return;
    NSData *data = [event dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) return;
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![value isKindOfClass:NSDictionary.class]) return;
    if ([value[@"type"] isEqual:@"ready"]) { self.state = @"running"; [self attachRuntimeSurface]; }
    if ([value[@"type"] isEqual:@"firstFrameDrawn"]) {
        self.sceneLifecycleReady = YES;
        if (self.sceneLifecycleManaged && (!self.readerSceneActive || UIApplication.sharedApplication.applicationState != UIApplicationStateActive)) {
            [self sceneLifecycleBackground];
        }
    }
    if ([value[@"type"] isEqual:@"didReset"]) {
        [self endBoundAuxiliaryInput];
        [self.surfaceController willMoveToParentViewController:nil];
        [self.surfaceController.view removeFromSuperview];
        [self.surfaceController removeFromParentViewController];
        self.surfaceController = nil;
        self.surfaceRedraw = NO;
        self.sdlWindow.hidden = YES;
        self.sdlWindow = nil;
        [self.container.window makeKeyWindow];
        [self.commands removeAllObjects];
        // The adapter has cleaned up, but its C/Python frames still own the
        // main thread. Publish idle/didReset only after RRRun releases its GIL
        // and returns, preventing a reentrant next-session launch.
        self.pendingResetEvent = value;
        self.state = @"resetting";
        return;
    }
    if ([value[@"type"] isEqual:@"saveFailed"] && [self.state isEqual:@"stopping"]) self.state = @"running";
    if ([value[@"type"] isEqual:@"quarantined"]) {
        [self cancelBoundAuxiliaryInput];
        self.state = @"quarantined"; self.scriptIdentityCaptureHandler = nil; self.checkpointSelectionHandler = nil; self.resumeAutomatically = NO;
        [self applyHostKeyboardGate];
    }
    [self emit:value];
}

- (void)invalidatePresentationInContainerView:(UIView *)container {
    NSAssert(NSThread.isMainThread, @"Presentation invalidation belongs to the runtime owner thread");
    if (!NSThread.isMainThread || container != self.container || !self.surfaceController
        || self.surfaceController.view.superview != container) return;
    self.surfaceRedraw = YES;
    RRBridgeAuxiliaryAPI api;
    if ([self auxiliaryAPI:&api]) [self refreshAuxiliaryGeometryForWindow:[self auxiliarySDLWindow] api:&api];
}

- (BOOL)consumeSurfaceRedraw {
    NSAssert(NSThread.isMainThread, @"Presentation redraw belongs to the runtime owner thread");
    if (!NSThread.isMainThread || !self.surfaceRedraw || !self.container.window || !self.surfaceController
        || self.surfaceController.view.superview != self.container
        || UIApplication.sharedApplication.applicationState != UIApplicationStateActive) return NO;
    self.surfaceRedraw = NO;
    return YES;
}

- (BOOL)rehostSurfaceInContainer:(UIView *)container sessionID:(NSString *)sessionID epoch:(uint64_t)epoch {
    NSAssert(NSThread.isMainThread, @"Surface ownership belongs to the main thread");
    if (!NSThread.isMainThread || ![@[@"starting", @"running"] containsObject:self.state] || !container.window ||
        CGRectIsEmpty(container.bounds) || ![self.configuration[@"sessionID"] isEqualToString:sessionID] ||
        [self.configuration[@"epoch"] unsignedLongLongValue] != epoch) return NO;
    if (self.container == container) return YES;
    UIResponder *responder = container;
    while (responder && ![responder isKindOfClass:UIViewController.class]) responder = responder.nextResponder;
    UIViewController *owner = (UIViewController *)responder;
    if (!owner) return NO;
    if (!self.surfaceController) {
        if (self.auxiliaryBound) return NO;
        self.hostKeyboardBlocked = YES;
        [self applyHostKeyboardGate];
        self.container = container;
        if ([self.state isEqualToString:@"running"]) [self attachRuntimeSurface];
        return YES;
    }
    if (self.surfaceController.view.superview != self.container) return NO;
    RRBridgeAuxiliaryAPI api;
    if (self.auxiliaryBound && (![self auxiliaryAPI:&api] || [self cancelBoundAuxiliaryInput] < 0)) return NO;
    self.hostKeyboardBlocked = YES;
    [self applyHostKeyboardGate];
    UIViewController *surfaceController = self.surfaceController;
    [surfaceController willMoveToParentViewController:nil];
    [surfaceController.view removeFromSuperview];
    [surfaceController removeFromParentViewController];
    self.container = container;
    [owner addChildViewController:surfaceController];
    surfaceController.view.frame = container.bounds;
    surfaceController.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [container addSubview:surfaceController.view];
    [surfaceController didMoveToParentViewController:owner];
    [container setNeedsLayout];
    [container layoutIfNeeded];
    [container.window makeKeyWindow];
    [self invalidatePresentationInContainerView:container];
    [self emit:@{@"type": @"surfaceRehosted"}];
    return YES;
}

- (BOOL)attachRuntimeSurface {
    NSAssert(NSThread.isMainThread, @"SDL view adoption requires the main thread");
    if (self.surfaceController || !self.container || CGRectIsEmpty(self.container.bounds)) return NO;
    NSMutableOrderedSet<UIWindow *> *windows = [NSMutableOrderedSet orderedSet];
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class]) [windows addObjectsFromArray:((UIWindowScene *)scene).windows];
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [windows addObjectsFromArray:UIApplication.sharedApplication.windows];
#pragma clang diagnostic pop
    // Scene applications can omit SDL's legacy UIWindow from UIApplication's
    // inventory. Ask the actual SDL window manager before falling back to UI.
    void (*version)(RRSDLVersion *) = dlsym(self.runtimeHandle, "SDL_GetVersion");
    void *(*focus)(void) = dlsym(self.runtimeHandle, "SDL_GetKeyboardFocus");
    void *(*fromID)(uint32_t) = dlsym(self.runtimeHandle, "SDL_GetWindowFromID");
    int (*info)(void *, RRSDLSysWMInfo *) = dlsym(self.runtimeHandle, "SDL_GetWindowWMInfo");
    if (version && fromID && info) {
        void *window = focus ? focus() : NULL;
        for (uint32_t identifier = 1; !window && identifier <= 1024; identifier++) window = fromID(identifier);
        if (window) {
            RRSDLSysWMInfo native = {0};
            version(&native.version);
            if (info(window, &native) && native.subsystem == 5 && native.info.uikit.window) {
                UIWindow *actual = (__bridge UIWindow *)native.info.uikit.window;
                [windows insertObject:actual atIndex:0];
            }
        }
    }
    for (UIWindow *window in windows) {
        if (![NSStringFromClass(window.class) hasPrefix:@"SDL_"]) continue;
        UIViewController *controller = window.rootViewController;
        if (!controller) continue;
        self.sdlWindow = window;
        self.surfaceController = controller;
        UIView *surface = controller.view;
        UIResponder *responder = self.container;
        while (responder && ![responder isKindOfClass:UIViewController.class]) responder = responder.nextResponder;
        UIViewController *owner = (UIViewController *)responder;
        window.rootViewController = nil;
        if (owner) [owner addChildViewController:controller];
        [surface removeFromSuperview];
        surface.frame = self.container.bounds;
        surface.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [self.container addSubview:surface];
        if (owner) [controller didMoveToParentViewController:owner];
        [self.container setNeedsLayout];
        [self.container layoutIfNeeded];
        window.hidden = YES;
        [self.container.window makeKeyWindow];
        self.surfaceRedraw = YES;
        [self emit:@{@"type": @"surfaceAttached", @"width": @(surface.bounds.size.width), @"height": @(surface.bounds.size.height), @"hostWindow": NSStringFromClass(self.container.window.class)}];
        return YES;
    }
    return NO;
}
@end
