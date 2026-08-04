# Secret Leak Preflight

发布前秘密泄漏预检。在任何项目开源、推 GitHub、发压缩包或交给别人之前，先挡一遍常见的 API Key / Token / `.env` / 私钥 / 配置文件泄漏风险。

兼容 Claude Code、Codex、Cursor、Gemini CLI、天枢等主流 AI Agent，也支持命令行直接使用。

## 为什么做这个

AI 让写代码变容易了，但很多新手不知道密钥不能直接写进代码，更不能推到公开仓库。一旦 key 进了公开 GitHub，就应该当作已经泄漏——只删除文件不够，必须去服务商后台撤销或轮换。

## 能做什么

*   检查 `.env`、私钥、证书、可疑配置文件是否准备被发布。
*   检查 26 种常见密钥形状：OpenAI、Anthropic、GitHub、AWS、Google、Stripe、Slack、npm、Docker Hub、Telegram、HuggingFace、SendGrid、Twilio、Mailgun、GitLab、Azure、Datadog、阿里云、JWT、通用 secret 等。
*   `--staged` 检查 git 暂存区，`--history` 检查 git 全历史（原版缺失的深度检测）。
*   检测到本机已安装 `gitleaks` / `trufflehog` 时自动叠加增强扫描；未安装时静默降级，不误报不阻断。
*   发现 `Critical` 或 `High` 风险时用退出码 `2` 阻断发布。
*   输出文件名、行号和规则名，**绝不打印密钥值**。
*   规则库自带 26 组正例/反例单测，新增规则防回归。

## 快速使用

需要 Node.js ≥ 18（零第三方依赖，无需 npm install）。

```bash
# 扫描当前目录
node scripts/leak-scan.mjs

# 扫描指定仓库路径
node scripts/leak-scan.mjs /path/to/repo

# 严格模式：中风险文件名也作为阻断项
node scripts/leak-scan.mjs /path/to/repo --strict

# 结构化 JSON 输出（CI / agent 解析用）
node scripts/leak-scan.mjs /path/to/repo --json

# 深度检测：git 暂存区 / git 全历史
node scripts/leak-scan.mjs /path/to/repo --staged --history
```

退出码：

*   `0`：没有发现阻断级风险
*   `2`：发现疑似泄漏风险，先不要上传
*   `1`：扫描过程出错（目标不存在/非目录/未知参数/深度扫描失败）

## 作为 AI Agent Skill 安装

本 skill 是开放规范目录（`SKILL.md` + scripts/rules/references/test），任何读 `SKILL.md` 的 agent 都能装载：

| 宿主 | 安装方式 |
|------|---------|
| Claude Code | 复制整个目录到 `~/.claude/skills/secret-leak-preflight/` |
| Codex | 复制到 `~/.codex/skills/secret-leak-preflight/` |
| Cursor | 复制到 `~/.cursor/skills/` 或项目 `.cursor/skills/` |
| Gemini CLI | 复制到 skills 目录（按 CLI 文档） |
| 天枢 (Rivet) | 复制到项目 `.rivet/skills/` 或用户级 `~/.rivet/skills/` |
| 通用通道 | `npx skills add <仓库> -l --full-depth` / `uvx skillsmd add <仓库> -l` / `gh skill install <owner>/<repo> <skill>` |

## 运行测试

```bash
cd <skill目录> && node --test
```

> Windows 注意：不要用 `node --test test/`（会把目录误当模块路径），用默认发现机制 `node --test`。

## 推荐搭配

*   GitHub Secret Scanning 与 Push Protection
*   `gitleaks`（`winget install Gitleaks.Gitleaks`）
*   `trufflehog`（GitHub release 二进制；Windows 下用 `file://.` 相对形式调用）
*   `.gitignore` 加固
*   GitHub Actions / pre-commit hook

## 注意

这个工具不能保证发现所有秘密，也不能替你撤销已经泄漏的 key。只要密钥曾经公开出现过，请立刻去对应服务商后台撤销或轮换（详见 `references/remediation.md`）。

## 项目结构

```
secret-leak-preflight/
├── SKILL.md                  # skill 入口：触发场景、工作流、安装矩阵
├── scripts/leak-scan.mjs     # 核心扫描器（零依赖 Node CLI）
├── rules/rules.mjs           # 26 条密钥规则库
├── references/
│   ├── tooling.md            # 外部工具安装/使用
│   └── remediation.md        # 泄漏后补救流程
└── test/                     # node:test 自测（15 用例）
```
