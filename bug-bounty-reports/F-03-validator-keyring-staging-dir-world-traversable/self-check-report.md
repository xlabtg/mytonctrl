# TON Bug Bounty Self-Check Report

## Short Assessment

DO NOT SEND!!!
Status: out-of-scope but technically valid.
Confidence: 87.
Fit bug bounty confidence: 20.
Component: MyTonCtrl validator tools.
Class: out-of-scope local-only.
Self-check report: bug-bounty-reports/F-03-validator-keyring-staging-dir-world-traversable/self-check-report.md.

## Repository State

- Analysis date UTC: 2026-06-26T10:26:03Z
- Input: bug-bounty-reports/F-03-validator-keyring-staging-dir-world-traversable/report.md
- Bug bounty rules repository: https://github.com/ton-blockchain/bug-bounty
- Bug bounty rules commit: `52db73b98ffd3173ecdbb21da770f15540e413c0`
- Repositories analyzed:
  - https://github.com/ton-blockchain/mytonctrl, branch `master`, commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`, submodules not present
- Local modification warnings: upstream source clone was clean; local PR branch was used only to validate the proposed remediation and generated report artifacts.
- Fetch/build limitations: local package install for PR validation required `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` because this workspace only has Python 3.14.6, while the project CI targets Python 3.8-3.13; validation used static analysis, PoC and local pytest regression tests.

## Scope Validation

- Target component: MyTonCtrl validator tools.
- In scope: yes, component is listed under Python/MyTonCtrl in the current TON bug bounty rules.
- Eligible category: no/uncertain, because the exploit requires local access to the validator host.
- Redirect required: none.
- Relevant exclusions or warnings: current TON rules say issues requiring the attacker to already control the local host, local files, environment or trusted operator inputs are generally out of scope unless there is a clear escalation to normal network/service impact.

## Technical Finding Summary

The report claims that the backup staging directory used for `validator-console exportallprivatekeys` is created under `/tmp` with mode `0755`, making the path traversable by other local users before validator private keys are exported.

## Vulnerability Existence

- Exact files/functions: `modules/backups.py`, `BackupModule.create_tmp_ton_dir`, `BackupModule.create_keyring`.
- Verified code path: upstream `master` builds `self.ton.tempDir + '/ton_backup_<timestamp>/db'` and calls `os.makedirs(dir_name_db)` before `exportallprivatekeys`.
- Attacker-controlled input path: no remote attacker-controlled input path; exploitation is a local filesystem traversal/read opportunity during backup creation.
- Assumptions: the host uses Unix permissions and default umask `022`; another local user or compromised low-privileged process exists on the validator host; exported key files are readable or otherwise accessible through the traversable parent.
- Already fixed: no in upstream `master` commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; yes in PR branch `issue-1-ea829dd5d209`.

## Reproducibility

- Reproduced: yes.
- Reproduction method: static analysis plus local PoC `python3 experiments/poc_perms.py` and pytest regression tests with mocked `validator-console`.
- Reproduction confidence: 88.
- Missing reproduction evidence: no real validator-console export was executed in this environment; the directory permission issue itself is reproduced.
- Live-target testing avoided: yes, the issue was validated only in a local isolated environment.

## Bug Bounty Eligibility

- Technical validity: valid.
- Bounty eligibility: not eligible/uncertain under current rules because the attack requires local host access.
- Realistic attacker prerequisites: realistic for a multi-user or partially compromised host; not realistic as a remote TON network attacker.
- Security impact: verified local exposure window for validator keyring staging path; validator key compromise impact is inferred from key material exposure.
- Low-priority notes: local-only private data exposure, no demonstrated normal network/service impact.

## Severity and Claim Validation

- Claimed impact/severity: High, local validator keyring exposure risk.
- Validated impact: High for local-host threat model; no remote impact validated.
- Overclaiming or downgrade notes: no validator-to-validator attack, consensus issue or remote crash path is demonstrated.

## Report Completeness Check

- Title: present.
- Summary: present.
- Affected component: present.
- Affected commit: present.
- Affected files/functions: present.
- Attack prerequisites: present.
- Trigger conditions: present.
- Reproduction steps: present.
- Expected result: present.
- Actual result: present.
- Proof of concept or evidence: present.
- Security impact: present.
- Suggested remediation: present.
- Environment details: present.

## Common Error Scan

Detected local-only prerequisite and partially inferred key-read impact from a world-traversable staging parent. No RCE claim, no critical overclaim, no malformed network input path, no mainnet/testnet testing, and no hallucinated files/functions detected.

## Final Verdict

Final verdict: REJECTED

Detailed reasoning: The staging directory permission issue is technically real and reproduced locally, but the current TON bug bounty rules generally exclude issues that require the attacker to already have local host access. The report should not be submitted to the TON bounty bot as an eligible bounty claim in its current form.

Submission guidance: do not send unless the program owner explicitly confirms that local-host MyTonCtrl permission findings are accepted.

Note: This self-check is not an official TON triage decision and does not guarantee a bounty. Invalid or low-quality reports may reduce reviewer trust and review priority.
