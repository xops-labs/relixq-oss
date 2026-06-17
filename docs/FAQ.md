# FAQ

## Does Relix-Q OSS send my code to the cloud?

No. The compose stack runs locally, and the standalone scanner reads local files. Git repository scans clone into the API container; uploaded archives stay in the Docker `uploads` volume.

## What does the OSS scanner cover?

It detects quantum-vulnerable and classically weak cryptography across source code, dependency manifests, TLS endpoints, certificate/key files, and selected config formats such as OpenSSH and nginx. The Go scanner includes the community rule packs under `packages/go/rules-community`.

## Do I need an external rule-pack overlay?

No. OSS findings are complete enough to identify vulnerable cryptography and weak-crypto baselines. An optional external rule-pack overlay can add curated migration context on top of findings, but it is not required.

## What is the scope of this repo?

This repo contains the single-tenant OSS web app, local auth, scanner engine, CLI, dependency scan, TLS scan, GitHub Action, and shared OSS packages. Out of scope here: multi-tenant orchestration, SSO/RLS, cloud posture scanning, fleet-scale ownership workflows, runtime telemetry, hosted LLM providers, and the migration-enrichment overlay content.

## Can I scan private repositories?

Yes. In the web app, repository projects can include an optional personal access token for clone access. Use a short-lived, read-only token. It is sent to git as an HTTP auth header for clone operations and is not returned by the API.

## Can scans modify my source code?

The scanner is read-only. Local path scans mount the source folder read-only in Docker. The scanner emits findings and optional output files; it does not rewrite scanned code.

## Why do I see different results between Docker and a plain local build?

The Docker image builds the scanner with CGO and bundles the C# Roslyn helper, so full AST support is available. A plain local `go build` runs the regex floor plus pure-Go AST paths unless you enable CGO and provide the relevant helper binaries.

## Are findings a migration plan?

No. Findings are an inventory and risk signal. They identify where quantum-vulnerable or weak cryptography appears, with rule-level recommendations where available. A production migration still needs application context, compatibility testing, key/certificate rotation planning, and owner approval.

## Why is there a validation corpus with crypto-looking fixtures?

The validation corpus intentionally contains synthetic examples that prove the scanner detects risky patterns and avoids false positives on PQC-safe code. Private-key fixtures are marker-only and do not contain real key material.

## What should I run before opening a PR?

Run the same checks as PR CI when your change touches those areas:

```bash
cd packages/go && go test ./...
dotnet build apps/api/RelixQ.OssApi.csproj --configuration Release
npm ci
npm audit --omit=dev --audit-level=high
npm run build:packages
npm run build:web
```

For documentation-only changes, link checks and a careful stale-claim review are usually enough.
