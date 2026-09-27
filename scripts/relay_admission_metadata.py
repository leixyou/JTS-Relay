"""File-descriptor metadata access on Linux and macOS, without external packages."""
import base64
import ctypes
import ctypes.util
import errno
import os
import sys

from relay_admission_public import require


def _darwin():
    require(sys.platform == "darwin", "extended_metadata_api_unavailable")
    library = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    library.flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    library.flistxattr.restype = ctypes.c_ssize_t
    library.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    library.fgetxattr.restype = ctypes.c_ssize_t
    library.fsetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    library.fsetxattr.restype = ctypes.c_int
    library.fremovexattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    library.fremovexattr.restype = ctypes.c_int
    library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    library.acl_get_fd_np.restype = ctypes.c_void_p
    library.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    library.acl_to_text.restype = ctypes.c_void_p
    library.acl_from_text.argtypes = [ctypes.c_char_p]
    library.acl_from_text.restype = ctypes.c_void_p
    library.acl_set_fd_np.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    library.acl_set_fd_np.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    library.acl_free.restype = ctypes.c_int
    library.acl_init.argtypes = [ctypes.c_int]
    library.acl_init.restype = ctypes.c_void_p
    return library


def _checked(value):
    if value < 0:
        raise OSError(ctypes.get_errno(), "extended_metadata_operation_failed")
    return value


def list_attributes(fd):
    if hasattr(os, "listxattr"):
        return os.listxattr(fd)
    library = _darwin()
    count = _checked(library.flistxattr(fd, None, 0, 0))
    require(count <= 65536, "extended_metadata_limit")
    buffer = ctypes.create_string_buffer(max(count, 1))
    actual = _checked(library.flistxattr(fd, buffer, count, 0))
    return [os.fsdecode(name) for name in buffer.raw[:actual].split(b"\0") if name]


def get_attribute(fd, name):
    if hasattr(os, "getxattr"):
        value = os.getxattr(fd, name)
        require(len(value) <= 65536, "extended_metadata_limit")
        return value
    library = _darwin()
    count = _checked(library.fgetxattr(fd, os.fsencode(name), None, 0, 0, 0))
    require(count <= 65536, "extended_metadata_limit")
    buffer = ctypes.create_string_buffer(max(count, 1))
    actual = _checked(library.fgetxattr(fd, os.fsencode(name), buffer, count, 0, 0))
    return buffer.raw[:actual]


def set_attribute(fd, name, value):
    if hasattr(os, "setxattr"):
        os.setxattr(fd, name, value)
    else:
        _checked(_darwin().fsetxattr(fd, os.fsencode(name), value, len(value), 0, 0))


def read_attributes(fd):
    result = {name: base64.b64encode(get_attribute(fd, name)).decode("ascii") for name in list_attributes(fd)}
    if sys.platform == "darwin":
        library = _darwin()
        acl = library.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED
        if not acl:
            if ctypes.get_errno() == errno.ENOENT:
                result["__operator_darwin_acl__"] = ""
                return result
            raise OSError(ctypes.get_errno(), "acl_read_failed")
        text = None
        try:
            length = ctypes.c_ssize_t()
            text = library.acl_to_text(acl, ctypes.byref(length))
            require(text and 0 <= length.value <= 65536, "acl_read_failed")
            result["__operator_darwin_acl__"] = base64.b64encode(ctypes.string_at(text, length.value)).decode("ascii")
        finally:
            if text:
                library.acl_free(text)
            library.acl_free(acl)
    return result


def restore_attributes(fd, attributes):
    for name in set(list_attributes(fd)) - set(attributes):
        if hasattr(os, "removexattr"):
            os.removexattr(fd, name)
        else:
            _checked(_darwin().fremovexattr(fd, os.fsencode(name), 0))
    for name, encoded in attributes.items():
        value = base64.b64decode(encoded, validate=True)
        if name == "__operator_darwin_acl__":
            library = _darwin()
            acl = library.acl_from_text(value) if value else library.acl_init(0)
            require(acl, "acl_restore_failed")
            try:
                _checked(library.acl_set_fd_np(fd, acl, 0x100))
            finally:
                library.acl_free(acl)
        else:
            set_attribute(fd, name, value)
