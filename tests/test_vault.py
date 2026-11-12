# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
import os
import stat
import tempfile
import unittest
from pathlib import Path

from vault import crypto, store
from vault.crypto import VaultError, WrongPassword
from vault.store import Vault


class CryptoTest(unittest.TestCase):
    def test_roundtrip(self):
        key = crypto.derive_key(b"pw", crypto.new_salt(), crypto.DEFAULT_KDF)
        blob = crypto.encrypt(key, b"secret data")
        self.assertNotIn(b"secret data", blob)
        self.assertEqual(crypto.decrypt(key, blob), b"secret data")

    def test_wrong_key(self):
        salt = crypto.new_salt()
        key1 = crypto.derive_key(b"one", salt, crypto.DEFAULT_KDF)
        key2 = crypto.derive_key(b"two", salt, crypto.DEFAULT_KDF)
        blob = crypto.encrypt(key1, b"x")
        with self.assertRaises(WrongPassword):
            crypto.decrypt(key2, blob)

    def test_tamper_detected(self):
        key = crypto.derive_key(b"pw", crypto.new_salt(), crypto.DEFAULT_KDF)
        blob = bytearray(crypto.encrypt(key, b"payload"))
        blob[-1] ^= 0x01
        with self.assertRaises(WrongPassword):
            crypto.decrypt(key, bytes(blob))


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "vault"
        self.vault = Vault.init(self.root, "пароль")

    def tearDown(self):
        self.tmp.cleanup()

    def test_put_get(self):
        self.vault.put("note", b"hello world", note="привет")
        data, meta = self.vault.get("note")
        self.assertEqual(data, b"hello world")
        self.assertEqual(meta["note"], "привет")
        self.assertEqual(meta["size"], 11)

    def test_overwrite_keeps_id(self):
        first = self.vault.put("k", b"one")
        second = self.vault.put("k", b"two")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(self.vault.get("k")[0], b"two")

    def test_reopen_with_password(self):
        self.vault.put("k", b"data")
        reopened = Vault.open(self.root, "пароль")
        self.assertEqual(reopened.get("k")[0], b"data")

    def test_reopen_wrong_password(self):
        with self.assertRaises(WrongPassword):
            Vault.open(self.root, "неверный")

    def test_listing_and_remove(self):
        self.vault.put("a", b"1")
        self.vault.put("b", b"22")
        self.assertEqual([n for n, _ in self.vault.listing()], ["a", "b"])
        self.vault.remove("a")
        self.assertEqual([n for n, _ in self.vault.listing()], ["b"])
        with self.assertRaises(VaultError):
            self.vault.get("a")

    def test_missing_entry(self):
        with self.assertRaises(VaultError):
            self.vault.get("nope")

    def test_passwd(self):
        self.vault.put("k", b"data")
        self.vault.passwd("новый")
        with self.assertRaises(WrongPassword):
            Vault.open(self.root, "пароль")
        self.assertEqual(Vault.open(self.root, "новый").get("k")[0], b"data")

    def test_init_twice_fails(self):
        with self.assertRaises(VaultError):
            Vault.init(self.root, "x")

    def test_blob_not_plaintext(self):
        self.vault.put("k", b"topsecretmarker")
        blobs = list((self.root / store.DATA_DIR).glob("*.enc"))
        self.assertEqual(len(blobs), 1)
        self.assertNotIn(b"topsecretmarker", blobs[0].read_bytes())
        self.assertNotIn(b"topsecretmarker", (self.root / store.INDEX_NAME).read_bytes())

    def test_permissions(self):
        self.vault.put("k", b"data")
        root_mode = stat.S_IMODE(os.stat(self.root).st_mode)
        self.assertEqual(root_mode, 0o700)
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, path)

    def test_export_import(self):
        self.vault.put("k", b"payload")
        archive = self.vault.export(Path(self.tmp.name) / "backup.tar.gz")
        self.assertTrue(archive.is_file())
        new_root = Path(self.tmp.name) / "restored"
        restored = Vault.import_archive(archive, "пароль", new_root)
        self.assertEqual(restored.get("k")[0], b"payload")

    def test_import_rejects_existing(self):
        self.vault.put("k", b"payload")
        archive = self.vault.export(Path(self.tmp.name) / "backup.tar.gz")
        with self.assertRaises(VaultError):
            Vault.import_archive(archive, "пароль", self.root)


if __name__ == "__main__":
    unittest.main()
