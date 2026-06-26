"""Unit tests for the secret-permission helpers in mypylib.

These guard the security fix for CWE-312/CWE-732: secrets (private keys,
wallet keys, credentials, backups) must not be created world/group readable
under the default root umask (022).
"""
import os
import stat

from mypylib.mypylib import (
    SECRET_DIR_MODE,
    SECRET_FILE_MODE,
    create_secret_dir,
    set_secret_file_perms,
)


def _mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_secret_mode_constants():
    assert SECRET_FILE_MODE == 0o600
    assert SECRET_DIR_MODE == 0o700


def test_set_secret_file_perms_restricts_to_owner(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_text("data")
    os.chmod(p, 0o644)  # simulate default root-umask perms
    set_secret_file_perms(str(p))
    assert _mode(str(p)) == 0o600
    assert _mode(str(p)) & 0o077 == 0  # no group/other access


def test_set_secret_file_perms_custom_mode(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_text("data")
    set_secret_file_perms(str(p), 0o640)
    assert _mode(str(p)) == 0o640


def test_set_secret_file_perms_is_best_effort(tmp_path):
    # Must not raise on a missing path (e.g. unsupported filesystem / race).
    set_secret_file_perms(str(tmp_path / "does-not-exist"))


def test_create_secret_dir_new(tmp_path):
    d = tmp_path / "keys"
    create_secret_dir(str(d))
    assert d.is_dir()
    assert _mode(str(d)) == 0o700
    assert _mode(str(d)) & 0o077 == 0


def test_create_secret_dir_tightens_existing(tmp_path):
    d = tmp_path / "loose"
    d.mkdir()
    os.chmod(d, 0o755)  # world-traversable, as makedirs would leave it
    create_secret_dir(str(d))
    assert _mode(str(d)) == 0o700


def test_create_secret_dir_nested(tmp_path):
    d = tmp_path / "a" / "b" / "c"
    create_secret_dir(str(d))
    assert d.is_dir()
    assert _mode(str(d)) == 0o700
