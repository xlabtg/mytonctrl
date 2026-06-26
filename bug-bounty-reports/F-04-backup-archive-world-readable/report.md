# [Security] High: full node backup archive is created world-readable in a predictable /tmp path

## Vulnerability Details

**Severity**: High
**CVSS Score**: 7.3
**CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
**Vulnerability Type**: CWE-312 Cleartext Storage of Sensitive Information, CWE-377 Insecure Temporary File, CWE-59 Improper Link Resolution Before File Access
**Affected Component**: `mytonctrl/scripts/create_backup.sh`
**Affected Versions**: `ton-blockchain/mytonctrl` `master` at commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; fixed in PR branch `issue-1-ea829dd5d209`

## Description

`create_backup.sh` packages sensitive node material into a single archive: `config.json`, validator keyring, `/var/ton-work/keys`, `mytoncore.db`, wallet private keys and other MyTonCtrl state. On the affected upstream commit, the script uses a fixed staging directory `/tmp/mytoncore/backupv2`, does not set a restrictive umask, does not quote path variables, and creates the final archive with `tar -zcf $dest ...`. Under the default root umask `022`, the archive is created as `0644`.

The fixed path under `/tmp` also allows local pre-creation and symlink-style attacks against staging paths before the backup runs.

## Impact

A local unprivileged user or low-privileged compromised process on the validator host can read the resulting archive and obtain the complete secret set of the node, including validator keyring material, wallet private keys and the alert bot token. This can lead to wallet fund theft and validator identity compromise. The finding is local-only; no remote network vector was confirmed.

## Proof of Concept (PoC)

### Prerequisites

- Linux or another POSIX filesystem that honors Unix permission bits.
- Default process umask `022`.
- Local isolated clone of `mytonctrl`.
- Synthetic local directories for `ton_dir`, `keys_dir` and `mtc_dir`.
- No mainnet or testnet access is required.

### Steps to Reproduce

1. Run the regression test that executes the real backup script on synthetic data:

```bash
pytest tests/integration/test_security_permissions.py::test_create_backup_script_archive_owner_only -q
```

2. To see the general before/after permission class, also run:

```bash
python3 experiments/poc_perms.py
```

### Expected Result

Backup staging must use an unpredictable owner-only directory and the final archive must be readable only by its owner: `0600`.

### Actual Result

Before the fix, `create_backup.sh` used:

```sh
tmp_dir="/tmp/mytoncore/backupv2"
rm -rf $tmp_dir
mkdir $tmp_dir
tar -zcf $dest -C $tmp_dir .
chown $user:$user $dest
```

With umask `022`, this creates a world-readable archive and a predictable staging path.

### PoC Code

Regression coverage is `tests/integration/test_security_permissions.py::test_create_backup_script_archive_owner_only`.

## Remediation

Set `umask 077` before staging or archive creation, use `mktemp -d` for an unpredictable owner-only staging directory, quote all path variables, force `chmod 600` on the resulting archive before handing it to the target user, and remove the staging directory by its exact quoted path.

### Code Fix

```sh
umask 077
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mytoncore_backup.XXXXXXXX") || exit 1
mkdir "$tmp_dir/db"
tar -zcf "$dest" -C "$tmp_dir" .
chmod 600 "$dest"
chown "$user:$user" "$dest"
rm -rf "$tmp_dir"
```

## Environment Details

- Local isolated test environment only.
- No exploit payloads were sent to mainnet, testnet, Toncenter, public lite servers or real deployed contracts.
- Validated against upstream `ton-blockchain/mytonctrl` commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244` and PR branch `issue-1-ea829dd5d209`.

## References

- https://github.com/ton-blockchain/mytonctrl
- https://github.com/ton-blockchain/bug-bounty
- https://cwe.mitre.org/data/definitions/312.html
- https://cwe.mitre.org/data/definitions/377.html
- https://cwe.mitre.org/data/definitions/59.html

## Self-Check Validation

- [x] Verified the target component is listed in TON Bug Bounty scope as MyTonCtrl validator tools.
- [x] Confirmed the issue is technically reproducible in an isolated local environment.
- [x] PoC tested in isolated environment only, not on mainnet/testnet.
- [x] Impact assessment is limited to the confirmed local attacker model.
- [x] Remediation is practical and implemented in PR branch `issue-1-ea829dd5d209`.
- [ ] TON bounty eligibility confirmed. The official rules warn that issues requiring local-host access are generally out of scope; see `self-check-report.md`.
