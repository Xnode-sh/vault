# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""Command line interface for vault."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import store
from .crypto import VaultError, WrongPassword


def read_password(prompt: str = "Пароль vault: ", confirm: bool = False) -> str:
    env = os.environ.get("VAULT_PASSWORD")
    if env is not None:
        return env
    if not sys.stdin.isatty():
        raise VaultError("нет tty: задайте VAULT_PASSWORD или вводите интерактивно")
    password = getpass.getpass(prompt)
    if confirm:
        again = getpass.getpass("Повтор: ")
        if password != again:
            raise VaultError("пароли не совпадают")
    return password


def _root(args) -> Path:
    if getattr(args, "vault", None):
        return Path(args.vault).expanduser()
    return store.default_root()


def _human(size: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def cmd_init(args) -> int:
    root = _root(args)
    password = read_password(confirm=True)
    store.Vault.init(root, password)
    print(f"хранилище создано: {root}")
    return 0


def cmd_put(args) -> int:
    root = _root(args)
    password = read_password()
    if args.path and args.path != "-":
        data = Path(args.path).read_bytes()
    else:
        if sys.stdin.isatty():
            print("Введите содержимое, затем Ctrl-D:", file=sys.stderr)
        data = sys.stdin.buffer.read()
    vault = store.Vault.open(root, password)
    meta = vault.put(args.name, data, note=args.note or "")
    print(f"записано: {args.name}  {_human(meta['size'])}")
    return 0


def cmd_get(args) -> int:
    root = _root(args)
    password = read_password()
    vault = store.Vault.open(root, password)
    data, _ = vault.get(args.name)
    if args.path and args.path != "-":
        dest = Path(args.path)
        dest.write_bytes(data)
        os.chmod(dest, 0o600)
        print(f"извлечено: {args.name} -> {dest}  {_human(len(data))}")
    else:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    return 0


def cmd_cat(args) -> int:
    root = _root(args)
    password = read_password()
    vault = store.Vault.open(root, password)
    data, _ = vault.get(args.name)
    sys.stdout.write(data.decode("utf-8", errors="replace"))
    if not data.endswith(b"\n"):
        sys.stdout.write("\n")
    return 0


def cmd_ls(args) -> int:
    root = _root(args)
    password = read_password()
    vault = store.Vault.open(root, password)
    items = vault.listing()
    if args.json:
        print(json.dumps({name: meta for name, meta in items}, ensure_ascii=False, indent=2))
        return 0
    if not items:
        print("(пусто)")
        return 0
    width = max(len(name) for name, _ in items)
    for name, meta in items:
        note = f"  # {meta['note']}" if meta.get("note") else ""
        print(f"{name:<{width}}  {_human(meta['size']):>9}  {meta['modified']}{note}")
    return 0


def cmd_rm(args) -> int:
    root = _root(args)
    password = read_password()
    vault = store.Vault.open(root, password)
    meta = vault.remove(args.name)
    print(f"удалено: {args.name}  {_human(meta['size'])}")
    return 0


def cmd_passwd(args) -> int:
    root = _root(args)
    current = read_password("Текущий пароль: ")
    vault = store.Vault.open(root, current)
    new = read_password("Новый пароль: ", confirm=True)
    vault.passwd(new)
    print("пароль обновлён")
    return 0


def cmd_info(args) -> int:
    root = _root(args)
    password = read_password()
    vault = store.Vault.open(root, password)
    print(json.dumps(vault.info(), ensure_ascii=False, indent=2))
    return 0


def cmd_export(args) -> int:
    root = _root(args)
    password = read_password()
    vault = store.Vault.open(root, password)
    dest = vault.export(Path(args.path))
    print(f"экспортировано: {dest}")
    return 0


def cmd_import(args) -> int:
    password = read_password("Пароль архива: ")
    root = Path(args.vault).expanduser() if args.vault else None
    vault = store.Vault.import_archive(Path(args.path), password, root)
    print(f"импортировано: {vault.root}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Приватное шифрованное хранилище для Termux")
    parser.add_argument("--vault", help="каталог хранилища (по умолчанию $VAULT_DIR или ~/.vault)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="создать хранилище").set_defaults(func=cmd_init)

    put = sub.add_parser("put", help="положить запись")
    put.add_argument("name")
    put.add_argument("path", nargs="?", help="файл-источник или - (stdin)")
    put.add_argument("-n", "--note", help="заметка")
    put.set_defaults(func=cmd_put)

    get = sub.add_parser("get", help="достать запись")
    get.add_argument("name")
    get.add_argument("path", nargs="?", help="куда записать или - (stdout)")
    get.set_defaults(func=cmd_get)

    cat = sub.add_parser("cat", help="показать текстовую запись")
    cat.add_argument("name")
    cat.set_defaults(func=cmd_cat)

    ls = sub.add_parser("ls", help="список записей")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=cmd_ls)

    rm = sub.add_parser("rm", help="удалить запись")
    rm.add_argument("name")
    rm.set_defaults(func=cmd_rm)

    sub.add_parser("passwd", help="сменить пароль").set_defaults(func=cmd_passwd)
    sub.add_parser("info", help="сведения о хранилище").set_defaults(func=cmd_info)

    export = sub.add_parser("export", help="экспорт архива")
    export.add_argument("path")
    export.set_defaults(func=cmd_export)

    imp = sub.add_parser("import", help="импорт архива")
    imp.add_argument("path")
    imp.set_defaults(func=cmd_import)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except WrongPassword as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 2
    except VaultError as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ошибка ввода-вывода: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130
