# [Security] High: validator keyring export staging directory is world-traversable

## Vulnerability Details

**Severity**: High
**CVSS Score**: 7.0
**CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**Vulnerability Type**: CWE-377 Insecure Temporary File, CWE-732 Incorrect Permission Assignment for Critical Resource
**Affected Component**: `modules/backups.py`, `BackupModule.create_tmp_ton_dir`, `BackupModule.create_keyring`
**Affected Versions**: `ton-blockchain/mytonctrl` `master` at commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; fixed in PR branch `issue-1-ea829dd5d209`

## Description

When creating a backup, MyTonCtrl exports validator private keys by running `validator-console exportallprivatekeys <dir>`. On the affected upstream commit, the staging path is created below `/tmp` as `self.ton.tempDir + '/ton_backup_<timestamp>/db'` with plain `os.makedirs(dir_name_db)`. Under the default root umask `022`, the staging directories are created as `0755`.

Because the staging root is world-traversable before private keys are exported, other local users can traverse into the backup directory and read keyring files if those files are also readable or if permissions are relaxed by the exporting tool.

## Impact

Exposure of validator keyring material can compromise the validator identity and allow actions under the validator's cryptographic identity. The finding is local-only; no remote network vector was confirmed.

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

2. Inspect the `BEFORE fix` section for `backup dir`.
3. Optionally run the regression tests:

```bash
pytest tests/unit/test_permissions.py tests/integration/test_security_permissions.py -q
```

### Expected Result

Any staging directory that receives validator private keys must be owner-only before secrets are written into it: `0700`.

### Actual Result

Before the fix, the PoC shows:

```text
backup dir (keyring export)   : 0o755  world_traversable=True
```

### PoC Code

The reproducer is `experiments/poc_perms.py`. Regression coverage includes `test_backup_staging_dir_owner_only`, which mocks `validator-console` and checks the staging directory mode.

## Remediation

Create the backup staging root with owner-only permissions before invoking `exportallprivatekeys`. Do not rely on process umask or child tools for secrecy of the parent directory.

### Code Fix

```python
# Before: parent directories inherit umask and can become 0755.
os.makedirs(dir_name_db)
self.create_keyring(dir_name_db)

# After: owner-only staging root exists before secrets are exported.
create_secret_dir(dir_name)
os.makedirs(dir_name_db, exist_ok=True)
self.create_keyring(dir_name_db)
```

## Environment Details

- Local isolated test environment only.
- No exploit payloads were sent to mainnet, testnet, Toncenter, public lite servers or real deployed contracts.
- Validated against upstream `ton-blockchain/mytonctrl` commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244` and PR branch `issue-1-ea829dd5d209`.

## References

- https://github.com/ton-blockchain/mytonctrl
- https://github.com/ton-blockchain/bug-bounty
- https://cwe.mitre.org/data/definitions/377.html
- https://cwe.mitre.org/data/definitions/732.html

## Self-Check Validation

- [x] Verified the target component is listed in TON Bug Bounty scope as MyTonCtrl validator tools.
- [x] Confirmed the issue is technically reproducible in an isolated local environment.
- [x] PoC tested in isolated environment only, not on mainnet/testnet.
- [x] Impact assessment is limited to the confirmed local attacker model.
- [x] Remediation is practical and implemented in PR branch `issue-1-ea829dd5d209`.
- [ ] TON bounty eligibility confirmed. The official rules warn that issues requiring local-host access are generally out of scope; see `self-check-report.md`.
