# Roadmap

This roadmap describes likely directions for Relix-Q OSS. It is not a delivery
promise. Priorities can change based on user feedback, standards movement,
scanner evidence, security needs, and maintainer availability.

## Current focus

- Reliable OSS scanner for source, dependency manifests, certificate/key files,
  config-layer crypto, and TLS endpoints.
- Low-friction local evaluation through released CLI archives, Docker scanner
  image, GitHub Action, and Docker Compose web UI.
- Strong validation corpus and rule example tests for public scanner claims.
- Honest separation between in-scope OSS detection/scoring and out-of-scope
  orchestration or external rule-pack enrichment.

## Near term

- Public launch hygiene: governance files, issue templates, CI, docs, and
  repeatable first-clone workflows.
- More troubleshooting and demo walkthrough documentation.
- Cleaner public release story for unsigned/notarization status and platform
  package channels.
- More validation-corpus coverage for high-signal languages and file formats.
- More documented examples for baselines, SARIF upload, dependency scans, and
  TLS scans.

## Future ideas

- More AST-tier detectors and fixture-backed rules.
- Additional dependency ecosystems and package knowledge-base entries.
- Better rule-browser and finding-explanation UX in the OSS web app.
- Optional SBOM artifacts in release automation.
- More GitHub Action examples for monorepos and new-findings-only gates.
- Community adopter stories and real-world tuning notes.

## Non-goals

- Replacing cryptographic review by domain experts.
- Guaranteeing absence of weak or quantum-vulnerable cryptography.
- Bundling an external migration-enrichment overlay in this OSS repository.
- Multi-tenant hosted SaaS governance, SSO/RLS, fleet orchestration, or runtime
  telemetry in the OSS app.
- Automatically sending source code, findings, or telemetry to an external
  service.
