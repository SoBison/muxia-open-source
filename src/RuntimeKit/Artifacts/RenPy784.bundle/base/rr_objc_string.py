# -*- coding: utf-8 -*-
"""Owned UTF-16 copies avoid the SDK pyobjus char-pointer input reference leak."""
import ctypes
from pyobjus import autoclass

try:
    _text = unicode
except NameError:
    _text = str
_NSString = autoclass('NSString')
_iossupport_installed = False


def utf8_string(value):
    if type(value) is not _text:
        value = value.decode('utf-8')
    encoded = value.encode('utf-16-le')
    buffer = ctypes.create_string_buffer(encoded, max(2, len(encoded)))
    first = ctypes.c_ushort.from_buffer(buffer)
    # NSString copies the unichars synchronously; the buffer remains owned by
    # this frame through the call. The +0 factory preserves normal ownership.
    return _NSString.stringWithCharacters_length_(first, len(encoded) // 2)


class _LogBridge(object):
    def __init__(self, original):
        self.original = original
        runtime = ctypes.CDLL('/usr/lib/libobjc.A.dylib')
        runtime.objc_getClass.argtypes = [ctypes.c_char_p]
        runtime.objc_getClass.restype = ctypes.c_void_p
        runtime.sel_registerName.argtypes = [ctypes.c_char_p]
        runtime.sel_registerName.restype = ctypes.c_void_p
        runtime.class_getClassMethod.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        runtime.class_getClassMethod.restype = ctypes.c_void_p
        runtime.method_getArgumentType.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_size_t]
        runtime.method_getArgumentType.restype = None
        self.owner = runtime.objc_getClass(b'Log')
        self.selector = runtime.sel_registerName(b'log:')
        method = runtime.class_getClassMethod(self.owner, self.selector)
        if not self.owner or not method:
            raise RuntimeError('The SDK Log.log: class method is unavailable')
        signature = ctypes.create_string_buffer(64)
        runtime.method_getArgumentType(method, 2, signature, len(signature))
        self.argument_type = signature.value
        if self.argument_type in (b'*', b'r*'):
            # The fixed SDK Log API takes char*, not NSString. Use a fully
            # typed public ObjC send with a call-owned ctypes buffer, avoiding
            # pyobjus's deliberately unbalanced char* Python INCREF branch.
            send_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)
            self.send = send_type(('objc_msgSend', runtime))
        elif self.argument_type == b'@':
            self.send = None
        else:
            raise RuntimeError('Unsupported SDK Log.log: argument signature')

    def log_(self, value):
        if self.send is None:
            return self.original.log_(utf8_string(value))
        encoded = value.encode('utf-8') if type(value) is _text else value
        buffer = ctypes.create_string_buffer(encoded)
        self.send(self.owner, self.selector, buffer)
        return None

    def __getattr__(self, name):
        return getattr(self.original, name)


def install_iossupport():
    global _iossupport_installed
    if _iossupport_installed:
        return
    import iossupport
    # Limit replacement to this SDK module's entry points. LogFile buffering,
    # flush, URL checks and the public pyobjus/NSString API remain unchanged.
    iossupport.Log = _LogBridge(iossupport.Log)
    iossupport.objc_str = utf8_string
    _iossupport_installed = True


class _CFRange(ctypes.Structure):
    _fields_ = [('location', ctypes.c_long), ('length', ctypes.c_long)]


class BridgePoller(object):
    """Typed public calls for the three high-frequency, argument-free methods.

    The bridge owns +0 NSString results. Copy their UTF-16 contents synchronously;
    no Objective-C ownership is acquired or released by this adapter.
    """
    def __init__(self):
        runtime = ctypes.CDLL('/usr/lib/libobjc.A.dylib')
        def bind(name, result, arguments):
            function = getattr(runtime, name)
            function.restype, function.argtypes = result, arguments
            return function
        get_class = bind('objc_getClass', ctypes.c_void_p, [ctypes.c_char_p])
        selector = bind('sel_registerName', ctypes.c_void_p, [ctypes.c_char_p])
        class_method = bind('class_getClassMethod', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p])
        instance_method = bind('class_getInstanceMethod', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p])
        argument_count = bind('method_getNumberOfArguments', ctypes.c_uint, [ctypes.c_void_p])
        return_type = bind('method_getReturnType', None, [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t])
        owner = get_class(b'RRRuntimeBridge')
        if not owner:
            raise RuntimeError('The runtime bridge class is unavailable')
        self.return_types = {}
        def checked(name, allowed, factory=False):
            method_selector = selector(name)
            method = (class_method if factory else instance_method)(owner, method_selector)
            if not method or argument_count(method) != 2:
                raise RuntimeError('Unexpected runtime bridge method arity')
            signature = ctypes.create_string_buffer(32)
            return_type(method, signature, len(signature))
            if signature.value not in allowed:
                raise RuntimeError('Unexpected runtime bridge return signature')
            self.return_types[name.decode('ascii')] = signature.value.decode('ascii')
            return method_selector, signature.value
        shared, unused = checked(b'shared', (b'@',), True)
        active, active_type = checked(b'isApplicationActive', (b'B', b'c'))
        self.command, unused = checked(b'takeCommandJSON', (b'@',))
        self.background, unused = checked(b'takeBackgroundSaveJSON', (b'@',))
        self.object_send = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(('objc_msgSend', runtime))
        self.receiver = self.object_send(owner, shared)
        if not self.receiver:
            raise RuntimeError('The runtime bridge singleton is unavailable')
        boolean_type = ctypes.c_bool if active_type == b'B' else ctypes.c_byte
        self.active_send = ctypes.CFUNCTYPE(boolean_type, ctypes.c_void_p, ctypes.c_void_p)(('objc_msgSend', runtime))
        self.active = active
        foundation = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.type_id = foundation.CFGetTypeID
        self.type_id.restype, self.type_id.argtypes = ctypes.c_ulong, [ctypes.c_void_p]
        string_type = foundation.CFStringGetTypeID
        string_type.restype, string_type.argtypes = ctypes.c_ulong, []
        self.string_type = string_type()
        self.length = foundation.CFStringGetLength
        self.length.restype, self.length.argtypes = ctypes.c_long, [ctypes.c_void_p]
        self.characters = foundation.CFStringGetCharacters
        self.characters.restype, self.characters.argtypes = None, [ctypes.c_void_p, _CFRange, ctypes.POINTER(ctypes.c_ushort)]

    def is_application_active(self):
        return bool(self.active_send(self.receiver, self.active))

    def _copy_string(self, value):
        if not value:
            return None
        if self.type_id(value) != self.string_type:
            raise RuntimeError('The runtime bridge returned a nonstring JSON value')
        length = self.length(value)
        if not length:
            return u''
        buffer = (ctypes.c_ushort * length)()
        self.characters(value, _CFRange(0, length), buffer)
        return ctypes.string_at(buffer, length * 2).decode('utf-16-le')

    def take_command_json(self):
        return self._copy_string(self.object_send(self.receiver, self.command))

    def take_background_save_json(self):
        return self._copy_string(self.object_send(self.receiver, self.background))
