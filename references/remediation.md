# Remediation Reference

> 泄漏后的补救流程。先轮换，再清理。顺序错误会导致清理白做。

## First Rule

If a secret may have been public, treat it as compromised. Rotate or revoke it at the provider before relying on repository cleanup.

## Severity

- Critical: live-looking key in public repo, public history, client bundle, public build log, issue, screenshot, or shared artifact.
- High: live-looking key in private repo history or team-visible CI logs.
- Medium: secret-like value in ignored local files, weak ignore rules, or missing push protection.
- Low: obvious fake placeholder such as `sk-example`, `your-api-key-here`, or documentation-only dummy values.

## Provider Actions

Tell the user exactly which dashboard to open when identifiable:

- OpenAI: revoke exposed project/user key and create a new key.
- GitHub: revoke exposed PAT, fine-grained token, OAuth token, or deploy key.
- Cloud providers (AWS/Azure/GCP): disable or rotate access keys; review recent usage and billing.
- Database/SaaS vendors (Stripe/Slack/SendGrid/etc.): rotate service tokens and inspect audit logs.

Never ask the user to paste the new key into chat.

## Local Fixes

Replace hardcoded secrets with environment variables:

```text
OPENAI_API_KEY=...
GITHUB_TOKEN=...
DATABASE_URL=...
```

Add common ignore rules:

```gitignore
.env
.env.*
!.env.example
*.key
*.pem
*.p12
*.pfx
secrets.*
config.local.*
```

Create or update `.env.example` with placeholder values only:

```text
OPENAI_API_KEY=your-api-key-here
```

## Git History

Only after rotation, decide whether history cleanup is needed. Explain that history rewriting can disrupt collaborators and requires explicit user approval before commands such as force-push.

Potential tools:

- `git filter-repo`
- BFG Repo-Cleaner
- GitHub support or repository secret scanning alerts

## Prevention

Prefer layered prevention:

- GitHub Secret Scanning and Push Protection
- `gitleaks protect --staged` before commits
- pre-commit hook
- CI scan on pull requests
- provider-side key restrictions when available
- environment variables or managed secret stores instead of client-side keys

## 使用本 skill 的扫描结果

扫描器输出的每个 finding 含 `file`、`line`、`rule`、`severity`——不打印匹配值。处理顺序：

1. 对每个 `Critical`/`High` finding，判断该值是否可能已公开（git 历史、CI 日志、截图、已推送分支）。
2. 若可能已公开 → 先轮换，再清理。
3. 清理：从代码/配置移除硬编码值 → 移入环境变量或 secret manager → 补 `.gitignore`。
4. 历史泄漏：轮换后与用户确认是否重写历史（破坏性操作，需显式批准）。
5. 复扫确认：`node scripts/leak-scan.mjs <path>` 重新跑，直到 exit 0。
