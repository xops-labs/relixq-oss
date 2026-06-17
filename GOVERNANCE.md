# Governance

Relix-Q OSS is an Apache-2.0 open-source project under `xops-labs`. This
document describes how decisions are made today and how the process can grow as
the contributor base grows.

## Status

Governance is intentionally lightweight. The project is early, and process
should help contributors move safely without pretending there is a large
committee behind every decision.

## Principles

1. **Evidence over positioning.** Claims about scanner coverage, safety, or
   public readiness should be backed by code, tests, fixtures, or docs.
2. **Security tools need extra honesty.** Do not overstate what the OSS scanner
   detects, what the web app protects, or what is out of scope for this repo.
3. **Detection changes need fixtures.** New rules and detector behavior should
   include examples, tests, or validation-corpus coverage.
4. **Public by default.** Technical decisions happen in issues, discussions,
   and pull requests whenever possible.
5. **Small reversible changes move faster.** Large, hard-to-reverse changes get
   a short public design discussion first.

## Roles

- **Contributors** open issues, discussions, and pull requests.
- **Committers** help triage and review once maintainers grant repository
  permissions.
- **Maintainers** can merge PRs, manage releases, and approve changes to public
  contracts.
- **Project lead** is the final tie-breaker for unresolved technical or process
  decisions.

Current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Day-to-day changes

Bug fixes, documentation updates, rule examples, small UI changes, and CI
updates need one maintainer approval before merge.

## Larger changes

Open an issue or discussion at least 72 hours before merge for changes that:

- Alter public CLI flags, JSON/SARIF shape, or API endpoints.
- Add or remove major scanner language coverage.
- Change severity, scoring, or `quantum_safety` semantics.
- Change release, signing, governance, license, or security policy.
- Add a dependency with meaningful runtime or supply-chain risk.

The proposal can be short: problem, proposed change, alternatives considered,
and acceptance criteria. Full RFCs can live under `docs/rfcs/` if a topic grows.

## Releases

- Version tags use `vMAJOR.MINOR.PATCH`.
- `CHANGELOG.md` is updated before a release tag is pushed.
- `.github/workflows/release.yml` builds release artifacts and scanner images.
- Security fixes may be released outside any regular cadence.

## Disagreements

Start in the issue or pull request. If maintainers cannot converge, the project
lead records the decision and rationale publicly. Conduct concerns follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), not this technical process.

## Foundation status

Relix-Q OSS is not currently affiliated with an open-source foundation. A
foundation move should be discussed publicly only when there are multiple active
maintainers from unrelated organizations and a clear neutrality or adoption
reason.

## Amending this document

Changes to governance should follow the larger-change process. Editorial fixes
do not need a waiting period.
