#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

extern void init_librenpy(void);
extern void Py_InitializeEx(int);
#if RR_PYTHON_MAJOR >= 3
extern void Py_SetPythonHome(const wchar_t *);
extern void Py_SetPath(const wchar_t *);
extern wchar_t *Py_DecodeLocale(const char *, size_t *);
#else
extern void Py_SetPythonHome(const char *);
extern void PyEval_InitThreads(void);
#endif
extern int PyRun_SimpleStringFlags(const char *, void *);
extern void *PyEval_SaveThread(void);
extern void PyEval_RestoreThread(void *);
extern int Py_IgnoreEnvironmentFlag;
extern int Py_DontWriteBytecodeFlag;
extern int Py_InspectFlag;
extern int Py_OptimizeFlag;
typedef void *(*RRLookupFunction)(void *, const char *);
extern void RRPlatformBegin(RRLookupFunction lookup);
extern void RRPlatformEnd(void);
static BOOL pythonInitialized;
static void *pythonThreadState;

/// The single exported entry point of this exact native/Python ABI image.
__attribute__((visibility("default")))
int RR_RUNTIME_RUN(const char *resourceDirectory, RRLookupFunction lookup) {
    NSCAssert(NSThread.isMainThread, @"Ren'Py iOS owns the main OS thread");
    @autoreleasepool {
        NSString *resources = [NSString stringWithUTF8String:resourceDirectory];
        setenv("RR_RUNTIME_RESOURCE_DIRECTORY", resourceDirectory, 1);
        setenv("RENPY_PLATFORM", "ios-arm64", 1);
        RRPlatformBegin(lookup);
        NSString *base = [resources stringByAppendingPathComponent:@"base"];
        if (!pythonInitialized) {
            init_librenpy();
            Py_IgnoreEnvironmentFlag = 1;
            // Imports must never create bytecode inside the signed app bundle.
            Py_DontWriteBytecodeFlag = 1;
            // A title cannot turn SystemExit into process termination.
            Py_InspectFlag = 1;
            Py_OptimizeFlag = 1;
#if RR_PYTHON_MAJOR >= 3
            Py_SetPythonHome(Py_DecodeLocale(base.fileSystemRepresentation, NULL));
            NSString *search = [NSString stringWithFormat:@"%@:%@/lib/python%s", base, base, RR_PYTHON_VERSION];
            Py_SetPath(Py_DecodeLocale(search.fileSystemRepresentation, NULL));
#else
            Py_SetPythonHome(strdup(base.fileSystemRepresentation));
#endif
            Py_InitializeEx(0);
#if RR_PYTHON_MAJOR < 3
            PyEval_InitThreads();
#endif
            pythonInitialized = YES;
        } else {
            PyEval_RestoreThread(pythonThreadState);
            pythonThreadState = NULL;
        }
        // No Py_RunMain/Py_Finalize: an ABI image owns one interpreter for the
        // application lifetime, while every session returns to the host stack.
        NSString *script = [base stringByAppendingPathComponent:@"main.py"];
        NSData *pathJSON = [NSJSONSerialization dataWithJSONObject:@[script] options:NSJSONWritingWithoutEscapingSlashes error:nil];
        NSString *quoted = [[NSString alloc] initWithData:pathJSON encoding:NSUTF8StringEncoding];
        NSString *code = [NSString stringWithFormat:@"# coding: utf-8\nimport sys\nsys.dont_write_bytecode = True\nsys.argv = [%@]\n__file__ = %@[0]\nexec(compile(open(__file__, 'rb').read(), __file__, 'exec'))\n", @"'RenReader'", quoted];
        int status = PyRun_SimpleStringFlags(code.UTF8String, NULL);
        pythonThreadState = PyEval_SaveThread();
        RRPlatformEnd();
        return status;
    }
}
