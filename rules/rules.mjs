/**
 * secret-leak-preflight — 规则库
 *
 * 每条规则结构：
 * {
 *   id: string,            // 唯一标识（kebab-case）
 *   name: string,          // 人类可读名称
 *   severity: string,      // 'Critical' | 'High' | 'Medium' | 'Low'
 *   regex: RegExp,         // 匹配密钥形状的正则
 *   description: string,   // 规则说明（出现在输出中）
 *   remediation: string,   // 补救指引（出现在输出中）
 * }
 *
 * 设计纪律：
 * - 正则会命中"真实格式的假值"（测试用），也会命中真密钥——输出层负责 redact，本模块只负责判定
 * - 伪阳性过滤（example/fake/placeholder）不在本模块，由扫描器的行级过滤处理
 * - 新增规则时同步在 test/rules.test.mjs 添加正例 + 反例断言
 */
export const rules = [
  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    severity: 'Critical',
    regex: /sk-(?!proj-|ant-)[A-Za-z0-9_-]{20,}/,
    description: 'OpenAI API key (sk-...) found. Treat as compromised if ever public.',
    remediation: 'Revoke in OpenAI dashboard and rotate. Remove from code, use env var or secret manager.',
  },
  {
    id: 'openai-project-key',
    name: 'OpenAI Project Key',
    severity: 'Critical',
    regex: /sk-proj-[A-Za-z0-9_-]{20,}/,
    description: 'OpenAI project-scoped API key (sk-proj-...) found.',
    remediation: 'Revoke in OpenAI dashboard project settings and rotate.',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    severity: 'Critical',
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/,
    description: 'Anthropic API key (sk-ant-...) found.',
    remediation: 'Revoke in Anthropic console and rotate.',
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    severity: 'Critical',
    regex: /gh[pousr]_[A-Za-z0-9_]{20,}/,
    description: 'GitHub personal access token (ghp_/gho_/ghu_/ghs_/ghr_) found.',
    remediation: 'Revoke in GitHub settings > Developer settings > Tokens and rotate.',
  },
  {
    id: 'github-fine-grained',
    name: 'GitHub Fine-Grained Token',
    severity: 'Critical',
    regex: /github_pat_[A-Za-z0-9_]{20,}/,
    description: 'GitHub fine-grained personal access token (github_pat_...) found.',
    remediation: 'Revoke in GitHub settings and rotate.',
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    severity: 'Critical',
    regex: /AKIA[0-9A-Z]{16}/,
    description: 'AWS access key ID (AKIA...) found.',
    remediation: 'Deactivate in AWS IAM, review usage, rotate the pair.',
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    severity: 'High',
    regex: /AIza[0-9A-Za-z_-]{20,}/,
    description: 'Google API key (AIza...) found.',
    remediation: 'Regenerate in Google Cloud Console credentials page.',
  },
  {
    id: 'google-oauth-secret',
    name: 'Google OAuth Client Secret',
    severity: 'High',
    regex: /GOCSPX-[A-Za-z0-9_-]{20,}/,
    description: 'Google OAuth client secret (GOCSPX-...) found.',
    remediation: 'Regenerate the OAuth client secret in Google Cloud Console.',
  },
  {
    id: 'stripe-live',
    name: 'Stripe Live Secret Key',
    severity: 'Critical',
    regex: /sk_live_[A-Za-z0-9]{20,}/,
    description: 'Stripe live secret key (sk_live_...) found.',
    remediation: 'Rotate in Stripe dashboard; live keys have real billing impact.',
  },
  {
    id: 'stripe-test',
    name: 'Stripe Test Key',
    severity: 'High',
    regex: /sk_test_[A-Za-z0-9]{20,}/,
    description: 'Stripe test secret key (sk_test_...) found.',
    remediation: 'Rotate in Stripe dashboard.',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    severity: 'High',
    regex: /xox[baprs]-[A-Za-z0-9-]{10,}/,
    description: 'Slack token (xoxb-/xoxa-/xoxp-/xoxr-/xoxs-) found.',
    remediation: 'Revoke in Slack API apps page and rotate.',
  },
  {
    id: 'npm-token',
    name: 'npm Access Token',
    severity: 'Critical',
    regex: /npm_[A-Za-z0-9]{20,}/,
    description: 'npm access token (npm_...) found.',
    remediation: 'Revoke in npmjs.com access tokens page and rotate.',
  },
  {
    id: 'docker-hub',
    name: 'Docker Hub Personal Access Token',
    severity: 'Critical',
    regex: /dckr_pat_[A-Za-z0-9_-]{20,}/,
    description: 'Docker Hub personal access token (dckr_pat_...) found.',
    remediation: 'Revoke in Docker Hub account security settings and rotate.',
  },
  {
    id: 'telegram-bot',
    name: 'Telegram Bot Token',
    severity: 'High',
    regex: /[0-9]{8,10}:[A-Za-z0-9_-]{30,}/,
    description: 'Telegram bot token (digits:alphanumeric) found.',
    remediation: 'Revoke via @BotFather /revoke and generate a new token.',
  },
  {
    id: 'huggingface',
    name: 'Hugging Face Token',
    severity: 'High',
    regex: /hf_[A-Za-z0-9]{20,}/,
    description: 'Hugging Face access token (hf_...) found.',
    remediation: 'Revoke in Hugging Face settings > Access Tokens and rotate.',
  },
  {
    id: 'sendgrid',
    name: 'SendGrid API Key',
    severity: 'Critical',
    regex: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
    description: 'SendGrid API key (SG.xxx.yyy) found.',
    remediation: 'Revoke in SendGrid API keys settings and rotate.',
  },
  {
    id: 'twilio',
    name: 'Twilio API Key',
    severity: 'High',
    regex: /SK[0-9a-fA-F]{32}/,
    description: 'Twilio API key (SK + 32 hex) found.',
    remediation: 'Revoke in Twilio console and rotate.',
  },
  {
    id: 'mailgun',
    name: 'Mailgun API Key',
    severity: 'High',
    regex: /key-[0-9a-fA-F]{32}/,
    description: 'Mailgun API key (key- + 32 hex) found.',
    remediation: 'Rotate in Mailgun dashboard.',
  },
  {
    id: 'jwt-token',
    name: 'JWT Token',
    severity: 'Medium',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    description: 'JWT (eyJ... three segments) found; may carry auth claims.',
    remediation: 'Inspect the token; if it is a real session/access token, revoke or rotate at the issuer.',
  },
  {
    id: 'private-key-pem',
    name: 'Private Key (PEM)',
    severity: 'Critical',
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    description: 'Private key block (PEM) found.',
    remediation: 'Never publish private keys. Rotate the keypair if the private key was ever exposed.',
  },
  {
    id: 'generic-secret',
    name: 'Generic Secret Assignment',
    severity: 'High',
    regex: /(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[^'"\s]{16,}/i,
    description: 'Generic secret-like assignment (api_key/secret/token/password = long value).',
    remediation: 'Move to environment variable or secret manager; rotate if ever public.',
  },
  {
    id: 'gitlab-pat',
    name: 'GitLab Personal Access Token',
    severity: 'Critical',
    regex: /glpat-[A-Za-z0-9_-]{20,}/,
    description: 'GitLab personal access token (glpat-...) found.',
    remediation: 'Revoke in GitLab user settings and rotate.',
  },
  {
    id: 'azure-storage',
    name: 'Azure Storage Account Key',
    severity: 'High',
    regex: /AccountKey=[A-Za-z0-9+/=]{40,}/i,
    description: 'Azure Storage account key (AccountKey=...) found.',
    remediation: 'Rotate in Azure portal storage account access keys.',
  },
  {
    id: 'datadog-api',
    name: 'Datadog API Key',
    severity: 'High',
    regex: /(DD_API_KEY|DATADOG_API_KEY)\s*[:=]\s*['"]?[A-Za-z0-9]{32}/i,
    description: 'Datadog API key (DD_API_KEY=...) found.',
    remediation: 'Rotate in Datadog Organization Settings > API Keys.',
  },
  {
    id: 'alibaba-access',
    name: 'Alibaba Cloud AccessKey ID',
    severity: 'High',
    regex: /LTAI[A-Za-z0-9]{12,}/,
    description: 'Alibaba Cloud AccessKey ID (LTAI...) found.',
    remediation: 'Disable in Alibaba Cloud RAM console and rotate the pair.',
  },
  {
    id: 'generic-jwt-secret',
    name: 'JWT/Session Secret',
    severity: 'High',
    regex: /(jwt|session)[_-]?(secret|key)\s*[:=]\s*['"][A-Za-z0-9+/=]{32,}['"]/i,
    description: 'JWT or session signing secret assigned as a long string.',
    remediation: 'Move to environment variable or secret manager; rotate the signing secret.',
  },
];

export const RULE_SCHEMA_KEYS = ['id', 'name', 'severity', 'regex', 'description', 'remediation'];
