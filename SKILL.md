---
name: secret-leak-preflight
description: Check local repositories, git projects, and AI coding projects for possible API key, token, secret, .env, private key, and config leaks before publishing. Use when the user asks to scan for leaked keys, exposed credentials, pre-publish security review, open-source release gate, GitHub secret scanning, gitleaks, trufflehog, .gitignore hardening, push protection, API key rotation, or remediation after accidentally committing secrets.
---

# Secret Leak Preflight

发布前秘密泄漏预检。在任何项目开源、推 GitHub、发压缩包或交给别人之前，先挡一遍常见的 API Key / Token / `.env` / 私钥 / 配置文件泄漏风险。

## Purpose

本 skill 提供安全优先的发布前密钥泄漏检查、补救工作流与阻断门。核心原则：

- **优先使用现有工具**：不要从零造扫描器——先用本 skill 自带的 `leak-scan.mjs`，再叠加 `gitleaks` / `trufflehog` / GitHub 内置能力。
- **泄漏即沦陷**：任何进入公开仓库、公开 issue、公开构建日志、共享截图或已部署客户端 bundle 的密钥，都应视为已泄露。删除文件不够，必须在服务商后台撤销或轮换。
- **永不打印密钥值**：所有输出只含文件名、行号、规则名，绝不含匹配到的密钥值。

## Fast Workflow

1. **识别目标**：本地仓库路径、GitHub URL、owner/repo、用户名或组织。
2. **安全检查纪律**：绝不让用户往对话里粘贴密钥、密码、cookie、token 或原始凭证。
3. **扫描前检查仓库状态**：
   - `git status --short`
   - `git remote -v`
   - `.gitignore`、`.env*`、`config*.json`、`*.key`、`*.pem`、CI 文件、部署文件
4. **运行扫描器**（核心，零依赖 Node CLI）：
   ```bash
   node <skill目录>/scripts/leak-scan.mjs <repo-path>
   # 严格模式：中风险文件名也阻断
   node <skill目录>/scripts/leak-scan.mjs <repo-path> --strict
   # 结构化 JSON 输出（CI / agent 解析用）
   node <skill目录>/scripts/leak-scan.mjs <repo-path> --json
   # 深度检测：git 暂存区 / git 全历史
   node <skill目录>/scripts/leak-scan.mjs <repo-path> --staged --history
   ```
5. **外部工具增强**（检测到才调用，缺失不报错）：
   - `gitleaks detect --source . --redact --no-banner`（本地 git 仓库）
   - `trufflehog git file://. --only-verified --no-update`（可用时）
   - GitHub 已认证时用 `gh` 与 GitHub 网页端/Secret Scanning
6. **解读退出码**：
   - `0`：未发现阻断级风险
   - `2`：发现疑似泄漏，先不要发布，处理完再重跑
   - 其他非 0：检查过程出错，修好后重跑
7. **按序补救**（见 references/remediation.md）：
   - 先在服务商后台撤销/轮换已暴露密钥
   - 从代码与配置中移除硬编码密钥
   - 运行期值改环境变量或密钥管理器
   - 加固 `.gitignore` 与 pre-commit/CI 扫描
   - **只有轮换之后**才讨论 git 历史重写，且破坏性/force-push 步骤必须用户显式批准
8. **输出模板**（见文末）。

## Findings 分级

- **Critical**：公开仓库/历史/构建日志/客户端 bundle 中的疑似活密钥
- **High**：疑似密钥、私钥文件、`.env` 文件、私有仓库历史
- **Medium**：可疑文件名（secrets.*/credentials.*/含 secret|credential|token 的文件名）、JWT、弱 `.gitignore`
- **Low**：带明确 fake 标记的文档示例（`sk-example`、`your-api-key-here`）

## 安装矩阵（兼容主流 AI Agent）

本 skill 本体是开放规范目录（`SKILL.md` + scripts/rules/references/test），任何能读 SKILL.md 的 agent 都能装载。按你的宿主选择安装方式：

| 宿主 | 安装方式 |
|------|---------|
| Claude Code | 复制整个目录到 `~/.claude/skills/secret-leak-preflight/` |
| Codex | 复制到 `~/.codex/skills/secret-leak-preflight/` |
| Cursor | 复制到 `~/.cursor/skills/` 或项目 `.cursor/skills/` |
| Gemini CLI | 复制到 skills 目录（按 CLI 文档） |
| 天枢 (Rivet) | 复制到项目 `.rivet/skills/` 或用户级 `~/.rivet/skills/` |
| 通用通道 | `npx skills add <仓库> -l --full-depth` / `uvx skillsmd add <仓库> -l` / `gh skill install <owner>/<repo> <skill>` |

依赖：仅需 Node.js（≥18，测试用内置 `node:test`）。扫描器零第三方依赖，无 npm install 步骤。

## 触发场景

- "帮我检查这个仓库有没有 API Key 泄漏"
- "开源前先审查一下"
- "这个项目能不能推 GitHub"
- "帮我补 `.gitignore`，别把密钥传上去"
- "我好像把 key 提交了，怎么办"

## 输出模板

```markdown
## API Key Leak Check

Checked:
- Local repo:
- Remote:
- Tools:

Findings:
- Critical:
- High:
- Medium:
- Low:

Required user actions:
- Rotate/revoke:
- Provider dashboards:

Local hardening:
- .gitignore:
- Environment variables:
- Pre-commit/CI:

Residual risk:
- Git history:
- Public forks/caches:
```

## 安全纪律

- 输出永不包含密钥值（redact 是硬不变量，测试也断言这一点）
- 不执行任意代码：扫描器只读文件 + 调用 git/gitleaks/trufflehog 子进程
- 外部工具失败降级：缺失或非 git 仓库时跳过并记录 tools 状态，不误报不阻断
- 本 skill 的测试夹具含格式仿真假值（正例测试值），对 skill 自身目录运行扫描会检出它们——这是正例测试的设计使然（被检出正是扫描器正常工作的证据），不属于真实泄漏；集成测试夹具统一带 `test`/`TEST` 前缀

## 测试

```bash
cd <skill目录> && node --test
# Windows 下不要用 `node --test test/`（会把目录误当模块路径）；用默认发现机制
```
