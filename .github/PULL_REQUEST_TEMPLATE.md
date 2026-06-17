## Summary

- 

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Scanner rule / detector change
- [ ] Documentation
- [ ] CI / packaging / release
- [ ] Security hardening

## Validation

Check every command you ran:

- [ ] `cd packages/go && go test ./...`
- [ ] `dotnet build apps/api/RelixQ.OssApi.csproj --configuration Release`
- [ ] `npm ci`
- [ ] `npm audit --omit=dev --audit-level=high`
- [ ] `npm run build:packages`
- [ ] `npm run build:web`

If any command was not run, explain why:

## Scanner behavior

For scanner, detector, rule, scoring, SARIF, or export changes:

- [ ] Added or updated rule examples, fixtures, or validation-corpus entries.
- [ ] Confirmed expected findings are not weakened just to make tests pass.
- [ ] Noted any intentional output/schema changes.

## Security and public repo hygiene

- [ ] No secrets, tokens, private source paths, or real key material were added.
- [ ] No external `rules-rulepack/` overlay content was added.
- [ ] Docs were updated if behavior changed.

## Screenshots / output

Add screenshots or short command output if useful.
