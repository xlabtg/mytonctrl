# [Security] High: wallet private keys are created world-readable

## Vulnerability Details

**Severity**: High
**CVSS Score**: 7.0
**CVSS Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**Vulnerability Type**: CWE-312 Cleartext Storage of Sensitive Information, CWE-732 Incorrect Permission Assignment for Critical Resource
**Affected Component**: `modules/wallet.py` (`WalletModule.do_import_wallet`, `WalletModule.create_wallet`), `mytoncore/mytoncore.py` (`MyTonCore.__init__`)
**Affected Versions**: `ton-blockchain/mytonctrl` `master` at commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; fixed in PR branch `issue-1-ea829dd5d209`

## Description

MyTonCtrl stores wallet private keys in `<wallet-name>.pk` files under the local `wallets/` directory. On the affected upstream commit, imported keys are written with `open(wallet_path + ".pk", 'wb')` and newly generated keys are produced by `new-wallet*.fif`, both inheriting the process umask. With the default root umask `022`, `.pk` files become `0644`. The `wallets/`, `pools/` and `contracts/` directories are also created with `os.makedirs(..., exist_ok=True)`, resulting in `0755` under the same umask.

## Impact

A local unprivileged user or low-privileged compromised process on the validator host can read wallet private keys. Possession of a `.pk` file allows signing arbitrary wallet transactions and can lead to theft of funds controlled by the wallet. The finding is local-only; no remote network vector was confirmed.

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

2. Inspect the `BEFORE fix` section for `wallet .pk`.
3. Optionally run the regression tests:

```bash
pytest tests/unit/test_permissions.py tests/integration/test_security_permissions.py -q
```

### Expected Result

Wallet private keys must be readable only by their owner: `0600`. Directories containing wallet/private-key material must not be traversable by other users: `0700`.

### Actual Result

Before the fix, the PoC shows:

```text
wallet .pk (private key)      : 0o644  world_readable=True
```

### PoC Code

The reproducer is `experiments/poc_perms.py`. Regression coverage includes `test_imported_wallet_pk_owner_only` and `test_wallet_pool_contract_dirs_owner_only`.

## Remediation

Apply `chmod 0600` immediately after creating or importing a `.pk` file. Create directories that can contain private keys with `0700` and enforce that mode on existing directories.

### Code Fix

```python
# Before: private key inherits umask and can become 0644.
with open(wallet_path + ".pk", 'wb') as file:
    file.write(pk_bytes)

# After: private key is restricted to the owner.
with open(wallet_path + ".pk", 'wb') as file:
    file.write(pk_bytes)
set_secret_file_perms(wallet_path + ".pk")
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
