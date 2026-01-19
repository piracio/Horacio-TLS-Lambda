# Conventional Commits Guide (Recommended)

This repository supports (and encourages) using **Conventional Commits** for commit messages.

Conventional Commits is a lightweight convention that makes commit history:

- easier to read and review
- easier to automate (release notes, changelogs, semantic versioning)
- easier to navigate when debugging

This guide is written for engineers who want **practical rules**, not bureaucracy.

---

## 1) The Format

A Conventional Commit message follows this structure:

```text
<type>(<scope>): <summary>

[optional body]

[optional footer(s)]
```

### Examples

```text
feat(tls): accept base64-encoded CA and intermediate certificates
fix(local): correct revocationSoftFail parsing on macOS
docs(readme): add PowerShell ExecutionPolicy troubleshooting note
chore(tools): add helper scripts for PEM/JSON/Base64 and PKI generation
refactor(tls): split waterfall rendering into reusable methods
test(tls): add regression test for TLS handshake timeout
```

---

## 2) Types (the “why” of the change)

Types tell the reader what kind of change this is.

### Most common types

| Type | Meaning | When to use |
|------|---------|-------------|
| `feat` | Feature | Adds new behavior/functionality |
| `fix` | Bug fix | Fixes incorrect behavior or a defect |
| `docs` | Documentation | Only documentation changes |
| `chore` | Maintenance | Tooling changes, cleanup, build scripts |
| `refactor` | Refactor | Code structure improved but behavior stays the same |
| `test` | Tests | Adds/updates tests without product changes |
| `perf` | Performance | Improves performance without new behavior |
| `build` | Build system | Build configuration changes (csproj, CI, packaging) |
| `ci` | CI changes | GitHub Actions / pipelines changes |
| `style` | Formatting | Only formatting (no logic changes) |

---

## 3) Scope (optional, but very useful)

Scope is a short label that indicates what area of the repo is affected.

Examples of good scopes in this repo:

- `tls`
- `revocation`
- `local`
- `lambda`
- `tools`
- `readme`
- `makefile`
- `docs`

### Examples

```text
feat(revocation): support Offline mode with strict failure
fix(local): avoid printing JSON output by default
docs(tools): document Unblock-File requirement on Windows
chore(makefile): add run-online-soft target
```

If you don’t want to use scope, this is also fine:

```text
fix: handle unexpected EOF in HTTP response
```

---

## 4) Summary rules (keep it clean)

The summary should be:

✅ short  
✅ clear  
✅ present tense  
✅ describing what the commit *does*  

### Good

```text
fix(tls): show CRL/AIA URLs when available
feat(local): add --resolve host:443:ip support
docs(readme): add examples for base64 CA input
```

### Avoid

```text
fixed stuff
update
changes
trying to fix...
WIP
```

---

## 5) Body (optional, but good for complex changes)

Use the body to explain:

- what changed
- why it changed
- any side effects
- how to test

Example:

```text
fix(local): correct revocationSoftFail parsing on macOS

macOS bash Makefile targets were passing revocationSoftFail=false but the CLI parser
was treating it as "missing" and using the default value (true).

Tested with:
- make run-online-strict URL=https://example.com
- make run-online-soft URL=https://example.com
```

---

## 6) Footers (optional)

Footers are useful for:

- linking issues/tickets
- breaking changes
- security notes

### Breaking changes

```text
feat(tls)!: change default revocation mode to Online

BREAKING CHANGE: Default behavior is now Online instead of NoCheck.
```

Or:

```text
feat(tls): change default revocation mode to Online

BREAKING CHANGE: Default behavior is now Online instead of NoCheck.
```

---

## 7) Why this helps (real benefits)

### A) Better `git log`
Your history becomes self-documenting:

```bash
git log --oneline
```

Example output:

```text
docs(readme): add PowerShell ExecutionPolicy troubleshooting note
feat(tls): accept base64-encoded CA and intermediate certificates
chore(tools): add helper scripts for PEM/JSON/Base64 and PKI generation
fix(local): disable JSON output by default
```

### B) Easier code review
Reviewers immediately understand intent and risk:

- `fix(...)` → risk: medium
- `feat(...)` → risk: higher
- `docs(...)` → risk: low

### C) Enables automation (optional)
Tools like:

- semantic-release
- release-please
- changelog generators

can use your commit history to generate version numbers and release notes.

---

## 8) Suggested commit messages for this project

### Feature examples

```text
feat(tls): accept base64-encoded CA and intermediate certificates
feat(local): add --json flag to output full result payload
feat(revocation): support Online soft-fail mode
```

### Fix examples

```text
fix(local): handle boolean parsing for revocationSoftFail
fix(tls): avoid premature EOF when reading response body
fix(waterfall): align bars for tiny phases like XFER
```

### Docs examples

```text
docs(readme): add base64 certificate input examples
docs(tools): add Windows Unblock-File instructions
docs(conventional-commits): add commit message guide
```

### Maintenance examples

```text
chore(gitignore): ignore generated PKI/cert artifacts
chore(makefile): simplify run targets to single-line commands
refactor(tls): extract waterfall renderer into helper method
```

---

## 9) Quick cheatsheet

If you don’t want to overthink it:

- **feat** = adds new behavior
- **fix** = fixes behavior
- **docs** = documentation only
- **chore** = tooling/maintenance

Examples:

```text
feat(tls): ...
fix(local): ...
docs(readme): ...
chore(tools): ...
```

---

## 10) FAQ

### Q: Do I have to use this?
No. Git accepts any message format. This is recommended for clarity and teamwork.

### Q: Can I change the scope names?
Yes. The scope list is just guidance.

### Q: What if I’m not sure between `chore` and `fix`?
- If behavior was wrong and now correct → **fix**
- If you changed tooling/scripts/docs → **chore**
- If you added something new → **feat**

---

## License note
This guide is included under the same repository license (GPLv2).
