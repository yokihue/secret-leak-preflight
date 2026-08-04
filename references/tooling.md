# Tooling Reference

Use existing tools before writing custom scanning logic. The skill's own scanner (`scripts/leak-scan.mjs`) is the first line of defense; external tools are optional enhancements.

## Baseline Checks

```bash
git status --short
git remote -v
git log --oneline -n 5
ls -la
```

List likely risky files without printing secret values:

```bash
find . -type f \( -name ".env*" -o -name "*.key" -o -name "*.pem" -o -name "config*.json" \) -not -path "./node_modules/*" -not -path "./.git/*"
```

Never dump full `.env`, key, token, or config contents into chat.

## Skill Scanner (primary)

```bash
# Scan a local repo (default: current directory)
node scripts/leak-scan.mjs <path>

# Block on medium-risk filenames too
node scripts/leak-scan.mjs <path> --strict

# Machine-readable output for CI
node scripts/leak-scan.mjs <path> --json

# Also scan git staged changes (pre-commit use)
node scripts/leak-scan.mjs <path> --staged

# Also scan full git history (slow, explicit)
node scripts/leak-scan.mjs <path> --history

# Skip external tool calls
node scripts/leak-scan.mjs <path> --no-external
```

Exit codes: `0` pass / `2` block publish / `1` scan error.

## Gitleaks

Preferred scan (redacts values by default):

```bash
gitleaks detect --source . --redact --no-banner
```

Pre-commit staging check:

```bash
gitleaks protect --staged --redact --no-banner
```

Install:

```bash
# Windows
winget install Gitleaks.Gitleaks
# macOS
brew install gitleaks
# Linux
# download release binary from https://github.com/gitleaks/gitleaks/releases
```

## TruffleHog

Verified-only findings:

```bash
trufflehog git file://. --only-verified --no-update
```

> Windows 注意：用相对路径 `file://.`（在仓库目录内执行），不要用 `file:///` 或 `file:///C:/...` 绝对形式——trufflehog 会把 `file:///` 解析成 `C:\.git` 导致 "failed to stat .git" 失败。扫描器已按此形式调用（`cwd: <target>`）。

For GitHub targets:

```bash
trufflehog github --repo https://github.com/OWNER/REPO --only-verified --no-update
```

Install:

```bash
# Windows
winget install TruffleSecurity.TruffleHog
# macOS
brew install trufflehog
# Python
pip install trufflehog
```

## GitHub CLI

Verify auth without printing tokens:

```bash
gh auth status
gh api user --jq '.login'
```

Browser login:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
gh auth status
```

Never ask the user to paste a token into chat or write it into files.

## GitHub Built-ins

Use GitHub Secret Scanning and Push Protection when the account/repo supports them. If the user lacks permissions, report that as a required owner/admin action.

Official references:

- GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning
- GitHub CLI auth: https://cli.github.com/manual/gh_auth_login
- Gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
