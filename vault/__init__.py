# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""vault — приватное шифрованное хранилище для Termux."""
from .crypto import VaultError, WrongPassword
from .store import Vault, default_root, is_initialized

__all__ = ["Vault", "VaultError", "WrongPassword", "default_root", "is_initialized"]
__version__ = "0.1.0"
