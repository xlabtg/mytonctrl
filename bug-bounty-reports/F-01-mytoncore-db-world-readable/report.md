# [Security] Medium: mytoncore.db is world-readable and exposes the alert bot token

## Vulnerability Details

**Severity**: Medium
**CVSS Score**: 5.5
**CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Vulnerability Type**: CWE-312 Cleartext Storage of Sensitive Information, CWE-732 Incorrect Permission Assignment for Critical Resource
**Affected Component**: `mypylib/mypylib.py`, `MyPyClass._write_file_atomic`, `MyPyClass.write_db`, `MyPyClass.lock_file`
**Affected Versions**: `ton-blockchain/mytonctrl` `master` at commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; fixed in PR branch `issue-1-ea829dd5d209`

## Description

`mytoncore.db` is a JSON configuration database used by MyTonCtrl. It can contain the Telegram alert bot token (`BotToken`), chat identifiers, lite-server settings and validator-console connection settings.

On the affected upstream commit, `MyPyClass._write_file_atomic()` creates the temporary database file with normal `open(tmp_path, 'wt')`, then replaces the target path with `os.replace()`. Under the default root umask `022`, the resulting database file is created as `0644`, readable by every local user. `MyPyClass.lock_file()` also creates the lock file with `0644`.

## Impact

A local unprivileged user or a low-privileged compromised process on the validator host can read `mytoncore.db` and extract the alert bot token and node connection metadata. The bot token can be used to impersonate the alert bot and send forged notifications to the operator. The finding is local-only; no remote network vector was confirmed.

## Proof of Concept (PoC)

### Prerequisites

- Linux or another POSIX filesystem that honors Unix permission bits.
- Default process umask `022`.
- Local isolated clone of `mytonctrl`.
- No mainnet or testnet access is required.

### Steps to Reproduce

1. Run the local PoC:

```bash
python3 experiments/poc_perms.py
```

2. Inspect the `BEFORE fix` section for `mytoncore.db`.
3. Optionally run the regression tests:

```bash
pytest tests/unit/test_permissions.py tests/integration/test_security_permissions.py -q
```

### Expected Result

The configuration database must be readable only by its owner: `0600`.

### Actual Result

Before the fix, the PoC shows:

```text
mytoncore.db (bot token)      : 0o644  world_readable=True
```

### PoC Code

The reproducer is `experiments/poc_perms.py`; the relevant checks are `world_readable()` and `demonstrate_before_fix()`.

## Remediation

Create secret-bearing files with owner-only permissions from the start and enforce permissions before replacing the final database path. Create the lock file with the same owner-only mode.

### Code Fix

```python
# Before: affected by process umask and produces 0644 under umask 022.
with open(tmp_path, 'wt') as file:
    file.write(text)
os.replace(tmp_path, path)

# After: temporary file is created as 0600 before it contains secrets.
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'wt') as file:
    file.write(text)
os.chmod(tmp_path, 0o600)
os.replace(tmp_path, path)
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
