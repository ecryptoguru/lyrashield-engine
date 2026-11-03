"""Qualify Darwin extended ACLs on the actual financial file descriptor."""

from __future__ import annotations

import ctypes
import errno
import os
from functools import lru_cache


# Public sys/acl.h values, shared by arm64 and x86_64 Darwin. Do not interpret
# libc's private acl_t layout or use a pathname subprocess as an ACL proof.
_ACL_TYPE_EXTENDED = 0x100
_KNOWN_PERMISSIONS = 0x103FFE
_MUTATION_PERMISSIONS = sum(1 << bit for bit in (2, 4, 5, 6, 8, 10, 12, 13))
_MAX_ENTRIES = 128


@lru_cache(maxsize=1)
def _libc() -> ctypes.CDLL:
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    signatures = [
        ("acl_get_fd_np", ctypes.c_void_p, [ctypes.c_int, ctypes.c_int]),
        ("acl_valid", ctypes.c_int, [ctypes.c_void_p]),
        ("acl_get_entry", ctypes.c_int, [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]),
        ("acl_get_tag_type", ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p]),
        ("acl_get_permset_mask_np", ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p]),
        ("acl_get_qualifier", ctypes.c_void_p, [ctypes.c_void_p]),
        ("acl_free", ctypes.c_int, [ctypes.c_void_p]),
        ("mbr_uid_to_uuid", ctypes.c_int, [ctypes.c_uint32, ctypes.c_void_p]),
    ]
    for name, result, arguments in signatures:
        function = getattr(library, name)
        function.restype = result
        function.argtypes = arguments
    return library


def _trusted_principals(library: ctypes.CDLL) -> set[bytes]:
    # Root already has filesystem authority. No group (including the current
    # user's groups) is treated as exclusively owned by this financial owner.
    principals = set()
    for uid in {0, os.getuid()}:
        value = (ctypes.c_ubyte * 16)()
        if library.mbr_uid_to_uuid(uid, value) != 0:
            raise OSError("financial ACL owner identity is unavailable")
        principals.add(bytes(value))
    return principals


def qualify_acl(fd: int, *, private: bool) -> None:
    """Reject foreign grants beyond the mode policy, without modifying the ACL.

    Deny entries cannot add authority. ALLOW entries are checked conservatively
    even when inheritance-only: a financial parent must not confer unsafe rights
    on newly created records. Unknown permissions/tags or API errors fail closed.
    """
    library = _libc()
    ctypes.set_errno(0)
    acl = library.acl_get_fd_np(fd, _ACL_TYPE_EXTENDED)
    if not acl and ctypes.get_errno() == errno.ENOENT:
        # Darwin's filesec_get_property reports an absent FILESEC_ACL as ENOENT
        # even for a valid, held inode. Other errors are not an empty ACL.
        os.fstat(fd)
        return
    if not acl:
        raise OSError(ctypes.get_errno(), "financial extended ACL is unavailable")
    try:
        if library.acl_valid(acl) != 0:
            raise OSError("invalid financial extended ACL")
        trusted = _trusted_principals(library)
        for index in range(_MAX_ENTRIES + 1):
            entry = ctypes.c_void_p()
            ctypes.set_errno(0)
            result = library.acl_get_entry(acl, index, ctypes.byref(entry))
            # Darwin returns 0 on success and -1/EINVAL at the end (unlike
            # Linux's POSIX ACL iterator). The retrieved ACL is a private copy.
            if result == -1 and ctypes.get_errno() == errno.EINVAL:
                return
            if result != 0 or not entry or index == _MAX_ENTRIES:
                raise OSError("financial ACL entries cannot be qualified")
            tag, permissions = ctypes.c_int(), ctypes.c_uint64()
            if (
                library.acl_get_tag_type(entry, ctypes.byref(tag)) != 0
                or library.acl_get_permset_mask_np(entry, ctypes.byref(permissions)) != 0
                or tag.value not in {1, 2}
                or permissions.value & ~_KNOWN_PERMISSIONS
            ):
                raise OSError("unknown financial ACL entry")
            if tag.value == 2:
                continue
            qualifier = library.acl_get_qualifier(entry)
            if not qualifier:
                raise OSError("financial ACL principal is unavailable")
            try:
                foreign = ctypes.string_at(qualifier, 16) not in trusted
            finally:
                library.acl_free(qualifier)
            prohibited = permissions.value if private else permissions.value & _MUTATION_PERMISSIONS
            if foreign and prohibited:
                raise OSError("financial extended ACL grants foreign access")
    finally:
        library.acl_free(acl)
