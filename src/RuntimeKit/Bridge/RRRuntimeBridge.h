#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Native host of the real, bundled Ren'Py runtime. All session calls are main-thread only.
@interface RRRuntimeBridge : NSObject
@property(class, nonatomic, readonly) RRRuntimeBridge *shared;
@property(nonatomic, copy, nullable) void (^eventHandler)(NSDictionary<NSString *, id> *event);
/// Synchronous file-only callback on the engine owner thread. Nil/empty is success;
/// an error string aborts script loading. Bind immutable paths before prepare.
@property(nonatomic, copy, nullable) NSString * _Nullable (^scriptIdentityCaptureHandler)(NSString *sessionID, uint64_t epoch, NSString *requiredCompiledPathsJSON);
@property(nonatomic, readonly, copy) NSString *state;
@property(nonatomic, readonly) BOOL runtimeAvailable;
/// Set before prepare. Nil starts the title normally; a valid slot resumes it.
@property(nonatomic, copy, nullable) NSString *startupSaveSlot;
/// Independently opts into automatic reader-checkpoint selection.
@property(nonatomic) BOOL resumeAutomatically;
/// Same-stack, file-only selection for the current frozen session.
@property(nonatomic, copy, nullable) NSString * _Nullable (^checkpointSelectionHandler)(NSString *sessionID, uint64_t epoch, NSString *requestJSON);
- (nullable NSString *)chooseResumeCheckpointJSON:(NSString *)requestJSON;
/// Frozen into the next prepared session. Nil selects enhanced mode.
@property(nonatomic, copy, nullable) NSString *launchMode;
@property(nonatomic, copy, nullable) NSURL *multiPersistentDirectoryURL;
/// A verified private Python source tree, frozen into the next session.
@property(nonatomic, copy, nullable) NSURL *engineBaseDirectoryURL;
@property(nonatomic, copy, nullable) NSString *engineOverlayManifestSHA256;
/// Optional host-verified session repair, consumed by the next prepare call.
@property(nonatomic, copy, nullable) NSDictionary<NSString *, id> *storySessionPatch;
/// Read-only preflight. Runtime images retain their first engine identity until
/// process exit, including stock; ordinary session reset cannot switch it.
- (BOOL)checkEngineSelectionForRuntimeID:(NSString *)runtimeID
                         overlaySHA256:(nullable NSString *)overlaySHA256
                                 error:(NSError **)error;

- (BOOL)prepareGameAtURL:(NSURL *)gameDirectory
       saveDirectoryURL:(NSURL *)saveDirectory
              sessionID:(NSString *)sessionID
                  epoch:(uint64_t)epoch
                  error:(NSError **)error;
- (BOOL)prepareGameAtURL:(NSURL *)gameDirectory
       saveDirectoryURL:(NSURL *)saveDirectory
      tokenDirectoryURL:(NSURL *)tokenDirectory
              runtimeID:(NSString *)runtimeID
              sessionID:(NSString *)sessionID
                  epoch:(uint64_t)epoch
                  error:(NSError **)error;
- (BOOL)startInContainerView:(UIView *)container error:(NSError **)error;
- (BOOL)submitCommandJSON:(NSString *)command error:(NSError **)error;
- (void)requestStopSaving:(BOOL)save;
- (void)cancelPreparedSession;

/// Called only by the shipped Python adapter through Pyobjus; not a general scripting API.
- (NSString *)waitForLaunchJSON;
- (nullable NSString *)takeCommandJSON;
- (nullable NSString *)takeBackgroundSaveJSON;
- (void)emitEventJSON:(NSString *)event;
- (nullable NSString *)captureScriptIdentityJSON:(NSString *)requestJSON;
- (BOOL)attachRuntimeSurface;
/// Moves an existing surface only for the current session and epoch.
- (BOOL)rehostSurfaceInContainer:(UIView *)container sessionID:(NSString *)sessionID epoch:(uint64_t)epoch;
/// Synchronize the owning reader scene without accepting stale sessions.
- (BOOL)setReaderSceneActive:(BOOL)active sessionID:(NSString *)sessionID epoch:(uint64_t)epoch;
/// Call after a mounted SDL child frame changes; stale containers cannot invalidate a new session.
- (void)invalidatePresentationInContainerView:(UIView *)container;
/// Adapter-only: consume at an engine safe point with a live display interface.
- (BOOL)consumeSurfaceRedraw;
- (BOOL)isApplicationActive;
/// Keyboard ownership only; does not change the first responder or SDL text-input mode.
- (void)setHostKeyboardBlocked:(BOOL)blocked inContainerView:(UIView *)container;
- (NSString *)keyboardInputStateJSON;
/// Optional pinned-SDL auxiliary input. Availability requires the complete
/// native component and a successful owner/window Begin, not symbol presence.
- (NSDictionary<NSString *, id> *)auxiliaryInputStateForSessionID:(NSString *)sessionID
                                                         epoch:(uint64_t)epoch
                                               inContainerView:(UIView *)container;
- (NSInteger)submitAuxiliaryInput:(NSInteger)kind code:(NSInteger)code x:(double)x y:(double)y
                         geometry:(uint64_t)geometry sessionID:(NSString *)sessionID epoch:(uint64_t)epoch
                  inContainerView:(UIView *)container;
/// Cancels only this owner's held inputs; does not end its ownership. Negative
/// results (including a full queue) are explicit and remain retryable.
- (NSInteger)cancelAuxiliaryInputForSessionID:(NSString *)sessionID epoch:(uint64_t)epoch
                            inContainerView:(UIView *)container;
@end

NS_ASSUME_NONNULL_END
