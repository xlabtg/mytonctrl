# TON Bug Bounty Self-Check Report

## Short Assessment

DO NOT SEND!!!
Status: out-of-scope but technically valid.
Confidence: 90.
Fit bug bounty confidence: 20.
Component: MyTonCtrl validator tools.
Class: out-of-scope local-only.
Self-check report: bug-bounty-reports/F-04-backup-archive-world-readable/self-check-report.md.

## Repository State

- Analysis date UTC: 2026-06-26T10:26:03Z
- Input: bug-bounty-reports/F-04-backup-archive-world-readable/report.md
- Bug bounty rules repository: https://github.com/ton-blockchain/bug-bounty
- Bug bounty rules commit: `52db73b98ffd3173ecdbb21da770f15540e413c0`
- Repositories analyzed:
  - https://github.com/ton-blockchain/mytonctrl, branch `master`, commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`, submodules not present
- Local modification warnings: upstream source clone was clean; local PR branch was used only to validate the proposed remediation and generated report artifacts.
- Fetch/build limitations: local package install for PR validation required `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` because this workspace only has Python 3.14.6, while the project CI targets Python 3.8-3.13; validation used static analysis and local pytest regression tests.

## Scope Validation

- Target component: MyTonCtrl validator tools.
- In scope: yes, component is listed under Python/MyTonCtrl in the current TON bug bounty rules.
- Eligible category: no/uncertain, because the exploit requires local access to the validator host.
- Redirect required: none.
- Relevant exclusions or warnings: current TON rules say issues requiring the attacker to already control the local host, local files, environment or trusted operator inputs are generally out of scope unless there is a clear escalation to normal network/service impact.

## Technical Finding Summary

The report claims that `create_backup.sh` stages all node secrets in a fixed `/tmp/mytoncore/backupv2` path and creates the final backup archive as world-readable under umask `022`.

## Vulnerability Existence

- Exact files/functions: `mytonctrl/scripts/create_backup.sh`.
- Verified code path: upstream `master` sets `tmp_dir="/tmp/mytoncore/backupv2"`, runs unquoted `rm -rf`, `mkdir`, `cp`, then `tar -zcf $dest -C $tmp_dir .` without `umask 077` or `chmod 600`.
- Attacker-controlled input path: no remote attacker-controlled input path; exploitation is a local filesystem read or local pre-creation/symlink-style interference with predictable staging paths.
- Assumptions: the host uses Unix permissions and default umask `022`; another local user or compromised low-privileged process exists on the validator host.
- Already fixed: no in upstream `master` commit `9520ad2fade1c996b3f3083b2daf6cdaf8085244`; yes in PR branch `issue-1-ea829dd5d209`.

## Reproducibility

- Reproduced: yes.
- Reproduction method: static analysis plus local pytest regression test executing the real script against synthetic data.
- Reproduction confidence: 92.
- Missing reproduction evidence: none for archive mode; symlink/pre-creation risk is derived from the fixed path and unquoted shell operations, not separately weaponized.
- Live-target testing avoided: yes, the issue was validated only in a local isolated environment.

## Bug Bounty Eligibility

- Technical validity: valid.
- Bounty eligibility: not eligible/uncertain under current rules because the attack requires local host access.
- Realistic attacker prerequisites: realistic for a multi-user or partially compromised host; not realistic as a remote TON network attacker.
- Security impact: verified local exposure of backup archives containing validator keys, wallet private keys and configuration secrets; integrity/availability impact from predictable staging path is limited and local.
- Low-priority notes: local-only private data exposure, no demonstrated normal network/service impact.

## Severity and Claim Validation

- Claimed impact/severity: High, full backup secret exposure and local staging path risk.
- Validated impact: High for local-host threat model; no remote impact validated.
- Overclaiming or downgrade notes: do not present the fixed `/tmp` path as remote arbitrary file overwrite or RCE.

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

Detected local-only prerequisite. Symlink/pre-creation impact is local and should not be overstated. No RCE claim, no critical overclaim, no malformed network input path, no mainnet/testnet testing, and no hallucinated files/functions detected.

## Final Verdict

Final verdict: REJECTED

Detailed reasoning: The backup archive permission issue is technically real and reproduced locally, but the current TON bug bounty rules generally exclude issues that require the attacker to already have local host access. The report should not be submitted to the TON bounty bot as an eligible bounty claim in its current form.

Submission guidance: do not send unless the program owner explicitly confirms that local-host MyTonCtrl permission findings are accepted.

Note: This self-check is not an official TON triage decision and does not guarantee a bounty. Invalid or low-quality reports may reduce reviewer trust and review priority.
