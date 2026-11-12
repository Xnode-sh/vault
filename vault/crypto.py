# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""Key derivation and authenticated encryption for vault."""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"VAULT1"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
MAXMEM = 256 * 1024 * 1024

DEFAULT_KDF = {"name": "scrypt", "n": 2 ** 15, "r": 8, "p": 1, "dklen": KEY_BYTES}


class VaultError(Exception):
    """Ошибка vault."""


class WrongPassword(VaultError):
    """Неверный пароль или повреждённые данные."""


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def derive_key(password: bytes, salt: bytes, kdf: dict) -> bytes:
    return hashlib.scrypt(
        password,
        salt=salt,
        n=int(kdf["n"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
        dklen=int(kdf["dklen"]),
        maxmem=MAXMEM,
    )


def encrypt(key: bytes, plaintext: bytes, aad: bytes = MAGIC) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = MAGIC) -> bytes:
    if len(blob) < NONCE_BYTES + 16:
        raise VaultError("повреждённый контейнер")
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise WrongPassword("неверный пароль или повреждённые данные") from exc


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)
