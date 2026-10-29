# ruff: noqa: RUF001
"""Restart-safe model profiles, with secrets and endpoint bindings in the OS keychain."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

from daedalus.application.model_settings import build
from daedalus.infrastructure.keychain import MacOSKeychain, SecureCredentialError
from daedalus.infrastructure.knowledge import atomic_json

FIELDS = (
    "base_url",
    "model",
    "timeout_sec",
    "role",
    "acknowledged_remote",
    "api_format",
    "provider",
    "api_key_env",
    "request_options",
)


def profile_settings(candidate):
    return {name: getattr(candidate, name) for name in FIELDS}


def binding(settings):
    raw = json.dumps(settings, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


class SavedModelProfiles:
    def __init__(self, workspace: Path, *, vault=None):
        workspace = workspace.resolve()
        self.directory = workspace / ".model-settings"
        self.path = self.directory / "connections.json"
        service = (
            "ai.daedalus.models.v1." + hashlib.sha256(str(workspace).encode()).hexdigest()[:32]
        )
        self.vault = vault if vault is not None else MacOSKeychain(service)
        self._lock = threading.RLock()
        self.restore_error = ""

    def _read(self):
        if self.directory.is_symlink() or self.path.is_symlink():
            raise SecureCredentialError("已保存模型配置的路径无效，请检查工作区")
        if not self.path.exists():
            return {"version": 1, "profiles": {}}
        try:
            if self.path.stat().st_size > 256 * 1024:
                raise ValueError("oversized")
            value = json.loads(self.path.read_text())
            if value["version"] != 1 or not isinstance(value["profiles"], dict):
                raise ValueError("schema")
            if len(value["profiles"]) > 16:
                raise ValueError("roles")
            return value
        except (OSError, ValueError, KeyError, TypeError):
            raise SecureCredentialError("已保存模型配置损坏，自动恢复已停止") from None

    def _write(self, document):
        if self.directory.is_symlink() or self.path.is_symlink():
            raise SecureCredentialError("已保存模型配置的路径无效，请检查工作区")
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        atomic_json(self.path, document)

    def load(self):
        with self._lock:
            try:
                result = {}
                for role, entry in self._read()["profiles"].items():
                    settings = entry["settings"]
                    if set(settings) != set(FIELDS) or settings["role"] != role:
                        raise ValueError("profile")
                    ref = entry["credential_ref"]
                    if not isinstance(ref, str) or not re_full_ref(ref):
                        raise ValueError("reference")
                    candidate = build(**settings)
                    result[role] = replace(
                        candidate,
                        persisted=True,
                        credential_ref=ref,
                        credential_fingerprint=str(entry.get("key_fingerprint", ""))[:12],
                    )
                self.restore_error = ""
                return result
            except Exception:  # noqa: BLE001 - never echo secret-bearing metadata in status
                self.restore_error = "已保存模型配置无效，请重新保存或清除连接"
                return {}

    def resolve(self, candidate):
        if not re_full_ref(candidate.credential_ref):
            raise SecureCredentialError("已保存凭证引用无效，请重新保存连接")
        try:
            record = json.loads(self.vault.get(candidate.credential_ref))
            if record["binding"] != binding(profile_settings(candidate)):
                raise ValueError("binding")
            key = record["api_key"]
            if not isinstance(key, str):
                raise ValueError("type")
            return key
        except SecureCredentialError:
            raise
        except (ValueError, TypeError, KeyError):
            raise SecureCredentialError(
                "已保存凭证与连接不匹配，已阻止调用；请重新保存连接"
            ) from None

    def save(self, candidates):
        if not self.vault.supported:
            raise SecureCredentialError("系统安全凭证存储不可用，请取消安全保存后使用临时连接")
        with self._lock:
            document = self._read()
            profiles = dict(document["profiles"])
            if "" in candidates:
                profiles.clear()
            created, result = [], {}
            try:
                for role, candidate in candidates.items():
                    key = self.resolve(candidate) if candidate.credential_ref else candidate.api_key
                    settings = profile_settings(candidate)
                    if key and key in json.dumps(settings, ensure_ascii=False):
                        raise SecureCredentialError(
                            "密钥只能填写在 API Key 字段，不能包含在连接配置中"
                        )
                    ref = uuid.uuid4().hex
                    self.vault.put(ref, json.dumps({"binding": binding(settings), "api_key": key}))
                    created.append(ref)
                    fingerprint = hashlib.sha256(key.encode()).hexdigest()[:12] if key else ""
                    profiles[role] = {
                        "settings": settings,
                        "credential_ref": ref,
                        "key_fingerprint": fingerprint,
                    }
                    result[role] = replace(
                        candidate,
                        api_key="",
                        credential_ref=ref,
                        persisted=True,
                        credential_fingerprint=fingerprint,
                    )
                old_refs = {entry["credential_ref"] for entry in document["profiles"].values()}
                new_refs = {entry["credential_ref"] for entry in profiles.values()}
                self._write({"version": 1, "profiles": profiles})
            except Exception as error:  # noqa: BLE001 - rollback and redact storage errors
                for ref in created:
                    with suppress(Exception):
                        self.vault.delete(ref)
                status = getattr(error, "context", {}).get("os_status")
                suffix = f"（钥匙串状态 {status}）" if type(status) is int else ""
                raise SecureCredentialError(
                    "安全保存失败，请确认系统钥匙串已解锁并允许后端访问；"
                    "原有模型配置保持有效，未写入明文密钥" + suffix
                ) from None
            for ref in old_refs - new_refs:
                with suppress(SecureCredentialError):
                    self.vault.delete(ref)
            self.restore_error = ""
            return result

    def forget(self, role=""):
        with self._lock:
            try:
                document = self._read()
            except SecureCredentialError:
                if role or self.directory.is_symlink() or self.path.is_symlink():
                    raise
                # Corrupt metadata cannot be trusted to identify keychain items. Clearing
                # it restores a usable console; unknown orphan items stay in the keychain.
                self._write({"version": 1, "profiles": {}})
                self.restore_error = ""
                return
            profiles = document["profiles"]
            removed = [entry for name, entry in profiles.items() if not role or name == role]
            kept = {name: entry for name, entry in profiles.items() if role and name != role}
            if removed:
                for entry in removed:
                    if isinstance(entry, dict) and re_full_ref(entry.get("credential_ref")):
                        self.vault.delete(entry["credential_ref"])
                self._write({"version": 1, "profiles": kept})
            self.restore_error = ""

    def describe(self):
        return {
            "backend": self.vault.backend,
            "supported": self.vault.supported,
            "restore_error": self.restore_error,
            "secrets_in_metadata": False,
        }


def re_full_ref(value):
    return (
        isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)
    )
