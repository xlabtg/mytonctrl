"""Regression tests for the file/directory permission hardening.

Issue #1 (security audit): secrets handled by mytoncore/mytonctrl were created
with the default root umask (022), leaving them world-readable:

  * the config DB (mytoncore.db) — stores the Telegram alert-bot token,
  * wallet/pool/contract private keys (`.pk` files),
  * the backup staging directory that receives `exportallprivatekeys`,
  * auto-backup destination directories,
  * the backup archive produced by scripts/create_backup.sh.

Each test below reproduces the exposure path and asserts that the secret is
now restricted to its owner (no group/other access). CWE-312 / CWE-732.
"""
import base64
import getpass
import json
import os
import shutil
import stat
import subprocess

from modules.backups import BackupModule
from mytoncore.utils import get_package_resource_path


def _mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _assert_owner_only(path: str, expected: int):
    mode = _mode(path)
    assert mode == expected, f"{path}: {oct(mode)} != {oct(expected)}"
    assert mode & 0o077 == 0, f"{path} is group/world accessible: {oct(mode)}"


def test_db_written_owner_only(local):
    # mytoncore.db stores the alert-bot token and liteserver/validator config.
    local.db["BotToken"] = "secret-bot-token"
    local.write_db(local.db)
    assert os.path.isfile(local.db_path)
    _assert_owner_only(local.db_path, 0o600)


def test_db_lock_file_not_world_readable(local):
    local.write_db(local.db)
    lock_path = os.path.realpath(local.db_path) + ".lock"
    assert os.path.isfile(lock_path)
    assert _mode(lock_path) & 0o077 == 0


def test_wallet_pool_contract_dirs_owner_only(ton):
    for directory in (ton.walletsDir, ton.poolsDir, ton.contractsDir):
        _assert_owner_only(directory.rstrip("/"), 0o700)


def test_imported_wallet_pk_owner_only(cli, ton):
    test_addr = "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c"
    test_key = base64.b64encode(b"\x01\x02" * 16).decode()

    output = cli.execute(f"iw {test_addr} {test_key}", no_color=True)
    assert "Wallet name:" in output

    pk_files = [f for f in os.listdir(ton.walletsDir) if f.endswith(".pk")]
    assert pk_files, "no .pk file was created"
    for name in pk_files:
        _assert_owner_only(os.path.join(ton.walletsDir, name), 0o600)


def test_backup_staging_dir_owner_only(ton, monkeypatch):
    config_json = json.dumps({"validator": "config"})

    def fake_run(cmd: str):
        if cmd == "getconfig":
            return f"head---------\n{config_json}\n--------tail"
        # exportallprivatekeys <dir>: emulate the validator dumping a key file.
        keyring_dir = cmd.split()[-1]
        os.makedirs(keyring_dir, exist_ok=True)
        with open(os.path.join(keyring_dir, "key0"), "w") as f:
            f.write("PRIVATE-KEY")
        return "exported"

    monkeypatch.setattr(ton.validatorConsole, "run", fake_run)

    module = BackupModule(ton, ton.local)
    dir_name = module.create_tmp_ton_dir()
    try:
        # The staging dir lives under world-traversable /tmp; it must be 0o700
        # so the exported validator private keys inside are not readable.
        _assert_owner_only(dir_name, 0o700)
        assert os.path.isfile(os.path.join(dir_name, "db", "config.json"))
    finally:
        shutil.rmtree(dir_name, ignore_errors=True)


def test_auto_backup_dir_owner_only(ton, monkeypatch, tmp_path):
    target = str(tmp_path / "auto_backups")
    ton.local.db["auto_backup"] = True
    ton.local.db["auto_backup_path"] = target

    # Don't actually shell out to create_backup.sh in the unit environment.
    monkeypatch.setattr(BackupModule, "create_backup", lambda self, args: 0)

    ton.make_backup(123456)

    assert os.path.isdir(target)
    _assert_owner_only(target, 0o700)


def test_create_backup_script_archive_owner_only(tmp_path):
    # End-to-end test of scripts/create_backup.sh: the produced archive bundles
    # validator/wallet private keys and must be owner-only (0o600).
    ton_dir = tmp_path / "ton"
    (ton_dir / "db" / "keyring").mkdir(parents=True)
    (ton_dir / "db" / "config.json").write_text(json.dumps({"config": 1}))
    (ton_dir / "db" / "keyring" / "k0").write_text("VALIDATOR-PRIVATE-KEY")

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "server").write_text("SERVER-KEY")

    mtc_dir = tmp_path / "mytoncore"
    mtc_dir.mkdir()
    (mtc_dir / "mytoncore.db").write_text(json.dumps({"BotToken": "secret"}))

    dest = tmp_path / "backup.tar.gz"
    user = getpass.getuser()

    with get_package_resource_path("mytonctrl", "scripts/create_backup.sh") as script:
        proc = subprocess.run(
            [
                "bash", str(script),
                "-d", str(dest),
                "-m", str(mtc_dir),
                "-t", str(ton_dir),
                "-k", str(keys_dir),
                "-u", user,
            ],
            capture_output=True, text=True, timeout=60,
        )

    assert dest.is_file(), f"archive not created. stderr:\n{proc.stderr}"
    _assert_owner_only(str(dest), 0o600)
