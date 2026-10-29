# ruff: noqa: RUF001
"""macOS generic-password items through Security.framework; no secret in argv or files."""

from __future__ import annotations

import ctypes
import sys
from contextlib import contextmanager

from daedalus.errors import DaedalusError


class SecureCredentialError(DaedalusError):
    code = "secure_credential_unavailable"


class MacOSKeychain:
    backend = "macos_keychain"

    def __init__(self, service: str):
        self.service = service
        self.supported = False
        if sys.platform != "darwin":
            return
        try:
            self.cf = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            )
            self.sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
            signatures = {
                "CFStringCreateWithCString": (
                    [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32],
                    ctypes.c_void_p,
                ),
                "CFDataCreate": (
                    [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long],
                    ctypes.c_void_p,
                ),
                "CFDictionaryCreateMutable": (
                    [ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p],
                    ctypes.c_void_p,
                ),
                "CFDictionarySetValue": ([ctypes.c_void_p] * 3, None),
                "CFRelease": ([ctypes.c_void_p], None),
                "CFDataGetLength": ([ctypes.c_void_p], ctypes.c_long),
                "CFDataGetBytePtr": ([ctypes.c_void_p], ctypes.c_void_p),
                "CFGetTypeID": ([ctypes.c_void_p], ctypes.c_ulong),
                "CFDataGetTypeID": ([], ctypes.c_ulong),
            }
            for name, (args, result) in signatures.items():
                function = getattr(self.cf, name)
                function.argtypes, function.restype = args, result
            for name, args in {
                "SecItemAdd": [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                "SecItemCopyMatching": [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                "SecItemDelete": [ctypes.c_void_p],
            }.items():
                function = getattr(self.sec, name)
                function.argtypes, function.restype = args, ctypes.c_int32
            self.supported = True
        except (OSError, AttributeError):
            pass

    def _constant(self, name, library=None):
        try:
            return ctypes.c_void_p.in_dll(library or self.sec, name).value
        except ValueError:
            raise SecureCredentialError("系统钥匙串接口不可用，未保存密钥") from None

    def _status(self, status):
        if status == 0:
            return
        messages = {
            -25300: "系统钥匙串中没有此连接的凭证，请重新保存模型设置",
            -25308: "系统钥匙串已锁定或需要授权，请先解锁并允许后端访问",
            -25293: "系统钥匙串访问未获授权，请检查系统授权",
            -25291: "系统钥匙串服务不可用，未使用明文文件保存凭证",
            -25299: "系统钥匙串条目已存在，请重新保存连接",
            -128: "系统钥匙串操作已取消，模型设置未保存",
        }
        raise SecureCredentialError(
            messages.get(status, "系统钥匙串操作失败，请检查系统授权"), os_status=status
        )

    @contextmanager
    def _query(self, account: str):
        if not self.supported:
            raise SecureCredentialError("当前系统不支持此安全凭证存储，未使用明文文件替代")
        owned = []
        key_callbacks = ctypes.addressof(
            ctypes.c_byte.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks")
        )
        value_callbacks = ctypes.addressof(
            ctypes.c_byte.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks")
        )
        query = self.cf.CFDictionaryCreateMutable(None, 0, key_callbacks, value_callbacks)
        if not query:
            raise SecureCredentialError("无法创建系统钥匙串请求")

        def string(text):
            value = self.cf.CFStringCreateWithCString(None, text.encode(), 0x08000100)
            if not value:
                raise SecureCredentialError("无法创建系统钥匙串请求")
            owned.append(value)
            return value

        def set_value(key, value):
            self.cf.CFDictionarySetValue(query, self._constant(key), value)

        try:
            set_value("kSecClass", self._constant("kSecClassGenericPassword"))
            set_value("kSecAttrService", string(self.service))
            set_value("kSecAttrAccount", string(account))
            # Classic login keychain, not iCloud synchronisation or a custom crypto file.
            set_value("kSecAttrSynchronizable", self._constant("kCFBooleanFalse", self.cf))
            yield query, set_value, owned
        finally:
            self.cf.CFRelease(query)
            for value in reversed(owned):
                self.cf.CFRelease(value)

    def put(self, account: str, payload: str):
        raw = payload.encode()
        if len(raw) > 65536:
            raise SecureCredentialError("凭证记录超过安全存储大小限制")
        with self._query(account) as (query, set_value, owned):
            data = self.cf.CFDataCreate(None, ctypes.c_char_p(raw), len(raw))
            if not data:
                raise SecureCredentialError("无法创建系统凭证记录")
            owned.append(data)
            set_value("kSecValueData", data)
            self._status(self.sec.SecItemAdd(query, None))

    def get(self, account: str) -> str:
        with self._query(account) as (query, set_value, _):
            set_value("kSecReturnData", self._constant("kCFBooleanTrue", self.cf))
            set_value("kSecMatchLimit", self._constant("kSecMatchLimitOne"))
            # Unattended calls must fail promptly instead of waiting for a password dialog.
            set_value("kSecUseAuthenticationUI", self._constant("kSecUseAuthenticationUIFail"))
            result = ctypes.c_void_p()
            self._status(self.sec.SecItemCopyMatching(query, ctypes.byref(result)))
            try:
                if not result.value or self.cf.CFGetTypeID(result) != self.cf.CFDataGetTypeID():
                    raise SecureCredentialError("系统凭证记录类型无效")
                length = self.cf.CFDataGetLength(result)
                if not 0 <= length <= 65536:
                    raise SecureCredentialError("系统凭证记录大小无效")
                return ctypes.string_at(self.cf.CFDataGetBytePtr(result), length).decode()
            finally:
                if result.value:
                    self.cf.CFRelease(result)

    def delete(self, account: str):
        with self._query(account) as (query, _, _):
            status = self.sec.SecItemDelete(query)
            if status != -25300:
                self._status(status)
