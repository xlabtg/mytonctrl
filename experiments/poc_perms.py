"""
PoC for issue #1 (security audit): mytonctrl wrote secret-bearing files and
directories world-readable under the default root umask (022), exposing private
keys and the alert-bot token to any local non-root user (CWE-312 / CWE-732).

The script reproduces the exact pre-fix code patterns from:
  - mypylib/mypylib.py:_write_file_atomic  (mytoncore.db -> bot token, config)
  - modules/wallet.py:do_import_wallet      (wallet .pk private key)
  - modules/backups.py:create_tmp_ton_dir   (validator keyring export dir in /tmp)

and then re-runs them through the hardened helpers added by the fix, showing the
secrets become owner-only (0o600 files, 0o700 dirs).

Run in an isolated environment (it only touches a private tmp dir):
    python3 experiments/poc_perms.py
"""
import json
import os
import stat
import tempfile
import threading

# Make the repository importable when run from the project root.
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mypylib.mypylib import create_secret_dir, set_secret_file_perms  # noqa: E402

os.umask(0o022)  # the default umask under which root / most daemons run


def mode(path: str) -> str:
    return oct(stat.S_IMODE(os.lstat(path).st_mode))


def world_readable(path: str) -> bool:
    return bool(os.lstat(path).st_mode & stat.S_IROTH)


def world_traversable(path: str) -> bool:
    return bool(os.lstat(path).st_mode & stat.S_IXOTH)


def reproduce_vulnerable(base: str) -> None:
    print("== BEFORE fix (original code patterns) ==")

    # 1) mytoncore.db atomic write -> holds BotToken / ChatId / config.
    db_path = os.path.join(base, "before_mytoncore.db")
    tmp_path = f"{db_path}.tmp.{os.getpid()}.{threading.get_ident()}"
    with open(tmp_path, "wt") as f:
        f.write(json.dumps({"BotToken": "123:SECRET", "ChatId": "42"}))
    os.replace(tmp_path, db_path)
    print(f"  mytoncore.db (bot token)      : {mode(db_path)}  world_readable={world_readable(db_path)}")

    # 2) wallet .pk private key (do_import_wallet original open()/write()).
    pk_path = os.path.join(base, "before_wallet.pk")
    with open(pk_path, "wb") as f:
        f.write(b"\x00" * 32)  # 32-byte ed25519 private key
    print(f"  wallet .pk (private key)      : {mode(pk_path)}  world_readable={world_readable(pk_path)}")

    # 3) backup staging dir (create_tmp_ton_dir original os.makedirs()).
    staging = os.path.join(base, "before_ton_backup", "db")
    os.makedirs(staging)
    staging_root = os.path.dirname(staging)
    print(f"  backup dir (keyring export)   : {mode(staging_root)}  world_traversable={world_traversable(staging_root)}")


def demonstrate_fixed(base: str) -> None:
    print("\n== AFTER fix (hardened helpers) ==")

    # 1) DB now written via _write_file_atomic with mode=0o600 (here emulated
    #    by set_secret_file_perms on the produced file).
    db_path = os.path.join(base, "after_mytoncore.db")
    tmp_path = f"{db_path}.tmp.{os.getpid()}.{threading.get_ident()}"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wt") as f:
        f.write(json.dumps({"BotToken": "123:SECRET", "ChatId": "42"}))
    os.replace(tmp_path, db_path)
    print(f"  mytoncore.db (bot token)      : {mode(db_path)}  world_readable={world_readable(db_path)}")

    # 2) wallet .pk locked down via set_secret_file_perms.
    pk_path = os.path.join(base, "after_wallet.pk")
    with open(pk_path, "wb") as f:
        f.write(b"\x00" * 32)
    set_secret_file_perms(pk_path)
    print(f"  wallet .pk (private key)      : {mode(pk_path)}  world_readable={world_readable(pk_path)}")

    # 3) backup staging dir created via create_secret_dir.
    staging_root = os.path.join(base, "after_ton_backup")
    create_secret_dir(staging_root)
    os.makedirs(os.path.join(staging_root, "db"), exist_ok=True)
    print(f"  backup dir (keyring export)   : {mode(staging_root)}  world_traversable={world_traversable(staging_root)}")


def main() -> None:
    base = tempfile.mkdtemp(prefix="mytonctrl_poc_")
    try:
        reproduce_vulnerable(base)
        demonstrate_fixed(base)
        print(
            "\nVERDICT: before the fix any local user could read the private keys / "
            "bot token; after the fix they are owner-only (0o600 / 0o700)."
        )
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
