"""Win32 financial files: process-crash atomicity, not a power-loss claim."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any, cast


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("descriptor", ctypes.c_void_p),
        ("inherit", wintypes.BOOL),
    ]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("high", ctypes.c_size_t),
        ("offset", wintypes.DWORD),
        ("offset_high", wintypes.DWORD),
        ("event", wintypes.HANDLE),
    ]


class WindowsDirectory:
    """Hold every parent against rename and reject reparse points/unsafe ACLs."""

    def __init__(self, path: Path, *, create: bool = False):
        if os.name != "nt":
            raise OSError("Win32 financial handles require Windows")
        win_dll = cast("Any", ctypes).WinDLL
        self.kernel = win_dll("kernel32", use_last_error=True)
        self.security = win_dll("advapi32", use_last_error=True)
        self.path = path
        self.handles: list[Any] = []
        self._bind()
        self.sid = self._token_sid(1)
        self.owner_sid = self._token_sid(4)
        try:
            for parent in [*reversed(path.parents), path]:
                try:
                    handle = self._open(parent, create=False, directory=True)
                except FileNotFoundError:
                    if not create or not self.handles:
                        raise
                    self._check_acl(self.handles[-1], private=False)
                    descriptor = self._descriptor()
                    attributes = _SecurityAttributes(
                        ctypes.sizeof(_SecurityAttributes), descriptor, 0
                    )
                    try:
                        self._check(
                            self.kernel.CreateDirectoryW(str(parent), ctypes.byref(attributes))
                        )
                    finally:
                        self.kernel.LocalFree(descriptor)
                    handle = self._open(parent, create=False, directory=True)
                self.handles.append(handle)
            self._check_acl(self.handles[-1], private=False)
        except BaseException:
            self.close()
            raise

    def _bind(self) -> None:
        signatures = [
            (self.kernel, "CreateDirectoryW", wintypes.BOOL, [wintypes.LPCWSTR, ctypes.c_void_p]),
            (
                self.kernel,
                "CreateFileW",
                wintypes.HANDLE,
                [
                    wintypes.LPCWSTR,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.HANDLE,
                ],
            ),
            (self.kernel, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE]),
            (self.kernel, "GetCurrentProcess", wintypes.HANDLE, []),
            (
                self.kernel,
                "GetFileInformationByHandleEx",
                wintypes.BOOL,
                [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
            ),
            (
                self.kernel,
                "ReplaceFileW",
                wintypes.BOOL,
                [
                    wintypes.LPCWSTR,
                    wintypes.LPCWSTR,
                    wintypes.LPCWSTR,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (
                self.kernel,
                "MoveFileExW",
                wintypes.BOOL,
                [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD],
            ),
            (
                self.kernel,
                "LockFileEx",
                wintypes.BOOL,
                [
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                ],
            ),
            (self.kernel, "LocalFree", ctypes.c_void_p, [ctypes.c_void_p]),
            (
                self.security,
                "OpenProcessToken",
                wintypes.BOOL,
                [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p],
            ),
            (
                self.security,
                "GetTokenInformation",
                wintypes.BOOL,
                [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p],
            ),
            (self.security, "GetLengthSid", wintypes.DWORD, [ctypes.c_void_p]),
            (self.security, "EqualSid", wintypes.BOOL, [ctypes.c_void_p, ctypes.c_void_p]),
            (
                self.security,
                "GetSecurityInfo",
                wintypes.DWORD,
                [
                    wintypes.HANDLE,
                    ctypes.c_int,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (
                self.security,
                "GetAce",
                wintypes.BOOL,
                [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p],
            ),
            (
                self.security,
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                wintypes.BOOL,
                [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p],
            ),
            (
                self.security,
                "GetSecurityDescriptorDacl",
                wintypes.BOOL,
                [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
            ),
            (
                self.security,
                "SetSecurityInfo",
                wintypes.DWORD,
                [
                    wintypes.HANDLE,
                    ctypes.c_int,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            ),
            (
                self.security,
                "ConvertStringSidToSidW",
                wintypes.BOOL,
                [wintypes.LPCWSTR, ctypes.c_void_p],
            ),
        ]
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype = result
            function.argtypes = arguments

    @staticmethod
    def _check(result: Any) -> None:
        if not result:
            raise OSError(cast("Any", ctypes).get_last_error(), "Win32 financial I/O failed")

    def _token_sid(self, information_class: int) -> Any:
        token = wintypes.HANDLE()
        self._check(
            self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token))
        )
        try:
            size = wintypes.DWORD()
            self.security.GetTokenInformation(token, information_class, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            self._check(
                self.security.GetTokenInformation(
                    token, information_class, buffer, size, ctypes.byref(size)
                )
            )
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            return ctypes.create_string_buffer(
                ctypes.string_at(sid, self.security.GetLengthSid(sid))
            )
        finally:
            self.kernel.CloseHandle(token)

    def _descriptor(self) -> ctypes.c_void_p:
        descriptor = ctypes.c_void_p()
        self._check(
            self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "D:P(A;;FA;;;OW)(A;;FA;;;SY)", 1, ctypes.byref(descriptor), None
            )
        )
        return descriptor

    def _open(self, path: Path, *, create: bool, directory: bool = False) -> Any:
        descriptor = self._descriptor() if create else None
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
        try:
            handle = self.kernel.CreateFileW(
                str(path),
                0x20080 if directory else 0xC0060000,
                3 if directory or path.name == ".finite-budget-activated" else 7,
                ctypes.byref(attributes) if create else None,
                1 if create else 3,
                0x00200000 | (0x02000000 if directory else 0x80),
                None,
            )
        finally:
            if descriptor is not None:
                self.kernel.LocalFree(descriptor)
        if handle == ctypes.c_void_p(-1).value:
            error = cast("Any", ctypes).get_last_error()
            if error in (2, 3):
                raise FileNotFoundError(error, "financial file not found", str(path))
            raise OSError(error, "CreateFileW financial open failed", str(path))
        try:
            # FILE_ATTRIBUTE_TAG_INFO: attributes and reparse tag, class 9.
            information = (wintypes.DWORD * 2)()
            self._check(
                self.kernel.GetFileInformationByHandleEx(
                    handle, 9, information, ctypes.sizeof(information)
                )
            )
            if information[0] & 0x400 or bool(information[0] & 0x10) != directory:
                raise OSError("financial path is a reparse point or wrong file type")  # noqa: TRY301 - release verified handles before propagating failure
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        else:
            return handle

    def _check_acl(self, handle: Any, *, private: bool) -> None:
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        error = self.security.GetSecurityInfo(
            handle,
            1,
            5,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if error:
            raise OSError(error, "cannot verify financial ACL")
        trusted: list[ctypes.c_void_p] = []
        try:
            for sid_text in ("S-1-5-18", "S-1-3-4", "S-1-5-32-544"):
                sid = ctypes.c_void_p()
                self._check(self.security.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)))
                trusted.append(sid)
            # New objects use TokenOwner, which may be Administrators for an
            # elevated process. Only that privileged default owner or TokenUser
            # is qualified; a shared unprivileged group owner is not private.
            own = self.security.EqualSid(owner, self.sid) or (
                self.security.EqualSid(owner, self.owner_sid)
                and self.security.EqualSid(owner, trusted[-1])
            )
            if not own or not dacl.value:
                raise OSError("financial path has foreign owner or unrestricted ACL")
            # ACL header has a WORD AceCount at byte offset 4.
            count = ctypes.c_ushort.from_address(dacl.value + 4).value
            for index in range(count):
                ace = ctypes.c_void_p()
                self._check(self.security.GetAce(dacl, index, ctypes.byref(ace)))
                address = int(ace.value or 0)
                kind, flags = ctypes.string_at(address, 2)
                if kind == 1 or flags & 8:  # deny or inherit-only ACE
                    continue
                if kind != 0:
                    raise OSError("unqualified financial access-control entry")
                mask = wintypes.DWORD.from_address(address + 4).value
                sid = ctypes.c_void_p(address + 8)
                if (
                    not self.security.EqualSid(sid, self.sid)
                    and not any(self.security.EqualSid(sid, allowed) for allowed in trusted)
                    and mask & (0xFFFFFFFF if private else 0x500D0156)
                ):
                    raise OSError("financial ACL grants access to another principal")
        finally:
            for sid in trusted:
                self.kernel.LocalFree(sid)
            self.kernel.LocalFree(descriptor)

    def qualify_fd(self, fd: int, *, private: bool) -> None:
        """Check the actual native lock handle after acquisition."""
        import msvcrt

        handle = cast("Any", msvcrt).get_osfhandle(fd)
        information = (wintypes.DWORD * 2)()
        self._check(
            self.kernel.GetFileInformationByHandleEx(
                handle, 9, information, ctypes.sizeof(information)
            )
        )
        if information[0] & 0x410:
            raise OSError("financial transition handle is a reparse point or directory")
        self._check_acl(handle, private=private)

    def open(self, name: str, *, create: bool, private: bool) -> int:
        import msvcrt

        handle = self._open(self.path / name, create=create)
        try:
            self._check_acl(handle, private=private)
            return int(
                cast("Any", msvcrt).open_osfhandle(handle, os.O_RDWR | cast("Any", os).O_BINARY)
            )
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise

    def lock(self, fd: int) -> None:
        import msvcrt

        self._check(
            self.kernel.LockFileEx(
                cast("Any", msvcrt).get_osfhandle(fd), 3, 0, 1, 0, ctypes.byref(_Overlapped())
            )
        )

    def replace(self, temporary: str, name: str) -> None:
        descriptor = self._descriptor()
        try:
            try:
                fd = self.open(name, create=False, private=False)
            except FileNotFoundError:
                self._check(
                    self.kernel.MoveFileExW(str(self.path / temporary), str(self.path / name), 8)
                )
            else:
                import msvcrt

                try:
                    present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
                    self._check(
                        self.security.GetSecurityDescriptorDacl(
                            descriptor,
                            ctypes.byref(present),
                            ctypes.byref(dacl),
                            ctypes.byref(defaulted),
                        )
                    )
                    error = self.security.SetSecurityInfo(
                        cast("Any", msvcrt).get_osfhandle(fd), 1, 0x80000004, None, None, dacl, None
                    )
                    if error:
                        raise OSError(error, "cannot protect financial target ACL")
                finally:
                    os.close(fd)
                self._check(
                    self.kernel.ReplaceFileW(
                        str(self.path / name), str(self.path / temporary), None, 0, None, None
                    )
                )
            fd = self.open(name, create=False, private=True)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            self.kernel.LocalFree(descriptor)

    def close(self) -> None:
        for handle in self.handles:
            self.kernel.CloseHandle(handle)
        self.handles.clear()
