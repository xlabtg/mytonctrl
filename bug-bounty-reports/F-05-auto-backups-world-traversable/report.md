# [Security] High: automatic backups are stored in a world-traversable /tmp directory

## Vulnerability Details

**Severity**: High
**CVSS Score**: 7.0
**CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**Vulnerability Type**: CWE-312 Cleartext Storage of Sensitive Information, CWE-732 Incorrect Permission Assignment for Critical Resource
**Affected Component**: `mytoncore/mytoncore.py`, `MyTonCore.make_backup`, `auto_backup_path` handling
**Affected Versions**: `ton-blockchain/mytonctrl` `master` at commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; fixed in PR branch `issue-1-ea829dd5d209`

## Description

When `auto_backup` is enabled, MyTonCtrl creates election-related backups in `self.tempDir + "/auto_backups"` by default, usually under `/tmp/mytoncore/auto_backups`. On the affected upstream commit, `MyTonCore.make_backup()` creates this directory with `os.makedirs(backups_dir, exist_ok=True)`. Under the default root umask `022`, the directory becomes `0755`.

These automatic backups can remain for up to seven days before cleanup and contain the same secret material as manually created backups.

## Impact

A local unprivileged user or low-privileged compromised process on the validator host can traverse the auto-backup directory and read backup archives if archive permissions are also world-readable. Combined with the backup archive issue, this exposes validator keyring material, wallet private keys and the alert bot token on a recurring schedule. The finding is local-only; no remote network vector was confirmed.

## Proof of Concept (PoC)

### Prerequisites

- Linux or another POSIX filesystem that honors Unix permission bits.
- Default process umask `022`.
- Local isolated clone of `mytonctrl`.
- `auto_backup` enabled in a local test configuration.
- No mainnet or testnet access is required.

### Steps to Reproduce

1. Run the regression test:

```bash
pytest tests/integration/test_security_permissions.py::test_auto_backup_dir_owner_only -q
```

2. Optionally run the full permission regression suite:

```bash
pytest tests/unit/test_permissions.py tests/integration/test_security_permissions.py -q
```

### Expected Result

The auto-backup directory must be owner-only: `0700`.

### Actual Result

Before the fix, `make_backup()` used:

```python
backups_dir = self.tempDir + "/auto_backups"
if self.local.db.get("auto_backup_path"):
    backups_dir = self.local.db.get("auto_backup_path")
os.makedirs(backups_dir, exist_ok=True)
```

With umask `022`, this creates a world-traversable directory.

### PoC Code

Regression coverage is `tests/integration/test_security_permissions.py::test_auto_backup_dir_owner_only`.

## Remediation

Create the auto-backup destination directory with owner-only permissions and enforce that mode on pre-existing directories.

### Code Fix

```python
# Before: directory inherits umask and can become 0755.
os.makedirs(backups_dir, exist_ok=True)

# After: directory is owner-only even under umask 022.
create_secret_dir(backups_dir)
```

## Environment Details

- Local isolated test environment only.
- No exploit payloads were sent to mainnet, testnet, Toncenter, public lite servers or real deployed contracts.
- Validated against upstream `ton-blockchain/mytonctrl` commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244` and PR branch `issue-1-ea829dd5d209`.

## References

- https://github.com/ton-blockchain/mytonctrl
- https://github.com/ton-blockchain/bug-bounty
- https://cwe.mitre.org/data/definitions/312.html
- https://cwe.mitre.org/data/definitions/732.html

## Self-Check Validation

- [x] Verified the target component is listed in TON Bug Bounty scope as MyTonCtrl validator tools.
- [x] Confirmed the issue is technically reproducible in an isolated local environment.
- [x] PoC tested in isolated environment only, not on mainnet/testnet.
- [x] Impact assessment is limited to the confirmed local attacker model.
- [x] Remediation is practical and implemented in PR branch `issue-1-ea829dd5d209`.
- [ ] TON bounty eligibility confirmed. The official rules warn that issues requiring local-host access are generally out of scope; see `self-check-report.md`.
