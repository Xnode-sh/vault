# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""Encrypted store: config, index and data blobs on disk."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from . import crypto
from .crypto import VaultError, WrongPassword

CONFIG_NAME = "config.json"
INDEX_NAME = "index.enc"
DATA_DIR = "data"
VERSION = 1
DIR_MODE = 0o700
FILE_MODE = 0o600


def default_root() -> Path:
    root = os.environ.get("VAULT_DIR")
    if root:
        return Path(root).expanduser()
    return Path.home() / ".vault"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, FILE_MODE)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _read_config(root: Path) -> dict:
    try:
        with open(root / CONFIG_NAME, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise VaultError(f"хранилище не найдено: {root}") from exc


def is_initialized(root: Path) -> bool:
    return (root / CONFIG_NAME).is_file()


class Vault:
    """Открытое хранилище. Ключ и индекс держатся в памяти."""

    def __init__(self, root: Path, key: bytes, config: dict, index: dict):
        self.root = root
        self.key = key
        self.config = config
        self.index = index

    @property
    def data_dir(self) -> Path:
        return self.root / DATA_DIR

    @classmethod
    def init(cls, root: Path, password: str) -> "Vault":
        if is_initialized(root):
            raise VaultError(f"хранилище уже существует: {root}")
        salt = crypto.new_salt()
        config = {
            "magic": "VAULT",
            "version": VERSION,
            "kdf": dict(crypto.DEFAULT_KDF),
            "salt": crypto.b64e(salt),
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        key = crypto.derive_key(password.encode("utf-8"), salt, config["kdf"])
        root.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        os.chmod(root, DIR_MODE)
        vault = cls(root, key, config, {"entries": {}})
        vault._save_config()
        vault.save()
        return vault

    @classmethod
    def open(cls, root: Path, password: str) -> "Vault":
        config = _read_config(root)
        if config.get("magic") != "VAULT":
            raise VaultError("не файл хранилища")
        salt = crypto.b64d(config["salt"])
        key = crypto.derive_key(password.encode("utf-8"), salt, config["kdf"])
        try:
            index = cls._decode_index(root, key)
        except WrongPassword:
            raise
        os.chmod(root, DIR_MODE)
        return cls(root, key, config, index)

    @staticmethod
    def _decode_index(root: Path, key: bytes) -> dict:
        path = root / INDEX_NAME
        if not path.is_file():
            return {"entries": {}}
        plain = crypto.decrypt(key, path.read_bytes())
        return json.loads(plain.decode("utf-8"))

    def _save_config(self) -> None:
        raw = json.dumps(self.config, ensure_ascii=False, indent=2).encode("utf-8")
        _write_private(self.root / CONFIG_NAME, raw)

    def save(self) -> None:
        raw = json.dumps(self.index, ensure_ascii=False).encode("utf-8")
        _write_private(self.root / INDEX_NAME, crypto.encrypt(self.key, raw))

    def _blob_path(self, entry_id: str) -> Path:
        return self.data_dir / f"{entry_id}.enc"

    def put(self, name: str, data: bytes, note: str = "") -> dict:
        entries = self.index["entries"]
        meta = entries.get(name)
        if meta:
            entry_id = meta["id"]
        else:
            entry_id = uuid.uuid4().hex
        _write_private(self._blob_path(entry_id), crypto.encrypt(self.key, data))
        now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        entry = {
            "id": entry_id,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "created": (meta or {}).get("created", now),
            "modified": now,
            "note": note or (meta or {}).get("note", ""),
        }
        entries[name] = entry
        self.save()
        return entry

    def get(self, name: str) -> tuple[bytes, dict]:
        meta = self.index["entries"].get(name)
        if not meta:
            raise VaultError(f"нет записи: {name}")
        path = self._blob_path(meta["id"])
        if not path.is_file():
            raise VaultError(f"данные записи потеряны: {name}")
        return crypto.decrypt(self.key, path.read_bytes()), meta

    def listing(self) -> list[tuple[str, dict]]:
        return sorted(self.index["entries"].items())

    def remove(self, name: str) -> dict:
        meta = self.index["entries"].pop(name, None)
        if not meta:
            raise VaultError(f"нет записи: {name}")
        path = self._blob_path(meta["id"])
        if path.is_file():
            path.unlink()
        self.save()
        return meta

    def passwd(self, new_password: str) -> None:
        salt = crypto.new_salt()
        new_key = crypto.derive_key(new_password.encode("utf-8"), salt, self.config["kdf"])
        for meta in self.index["entries"].values():
            path = self._blob_path(meta["id"])
            if not path.is_file():
                continue
            plain = crypto.decrypt(self.key, path.read_bytes())
            _write_private(path, crypto.encrypt(new_key, plain))
        self.config["salt"] = crypto.b64e(salt)
        self.key = new_key
        self._save_config()
        self.save()

    def info(self) -> dict:
        return {
            "root": str(self.root),
            "version": self.config.get("version"),
            "kdf": self.config.get("kdf"),
            "created": self.config.get("created"),
            "entries": len(self.index["entries"]),
            "bytes": sum(m["size"] for m in self.index["entries"].values()),
        }

    def export(self, dest: Path) -> Path:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(self.root, arcname=".vault")
        os.chmod(dest, FILE_MODE)
        return dest

    @classmethod
    def import_archive(cls, archive: Path, password: str, root: Path | None = None) -> "Vault":
        archive = Path(archive)
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            for member in members:
                if member.name.startswith("/") or ".." in Path(member.name).parts:
                    raise VaultError(f"небезопасный путь в архиве: {member.name}")
            tmp = Path(tempfile.mkdtemp(prefix="vault-import-"))
            try:
                tar.extractall(tmp, filter="data")
                src = tmp / ".vault"
                if not is_initialized(src):
                    raise VaultError("в архиве нет хранилища")
                target = Path(root) if root else cls.default_target(src)
                if target.exists():
                    raise VaultError(f"цель уже существует: {target}")
                shutil.move(str(src), str(target))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        return cls.open(target, password)

    @staticmethod
    def default_target(src: Path) -> Path:
        return default_root()
