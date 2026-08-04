/**
 * rules.test.mjs — 规则库单测
 *
 * 纪律：
 * - 每条规则必须有正例（正则命中）与反例（不误报）
 * - 正例值统一带 TEST 标记（如 sk-TEST-...），满足两重目的：
 *   ① 明显为测试夹具，避免 GitHub Push Protection 误判为真实密钥阻断推送；
 *   ② 正则仍命中（TEST 只加在字符集允许的位置，不破坏匹配语义）
 * - twilio/mailgun（hex 定长）、jwt-token、private-key-pem 因格式约束
 *   无法插入 TEST 标记，保持原样——GitHub 对 hex key 需服务商前缀识别、
 *   JWT 需签名验证、PEM 需完整块，单行测试值不会触发拦截
 * - 本文件驱动 rules.mjs（RED：空规则库全部失败 → GREEN：26 条规则全部通过）
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rules, RULE_SCHEMA_KEYS } from '../rules/rules.mjs';

// 注意：以下字符串全部是带 TEST 标记的格式仿真测试值，非真实密钥。
const CASES = {
  'openai-api-key': {
    positive: 'sk-TEST-abcdefghijklmnopqrstuvwxyz',
    negative: 'sk-shortkey', // 长度不足
  },
  'openai-project-key': {
    positive: 'sk-proj-TEST-abcdefghijklmnopqrstuvwxyz',
    negative: 'sk-proj-short',
  },
  'anthropic-api-key': {
    positive: 'sk-ant-TEST-abcdefghijklmnopqrstuvwxyz',
    negative: 'sk-ant-short',
  },
  'github-token': {
    positive: 'ghp_TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'ghx_abcdefghijklmnopqrstuvwxyz', // ghx 不在 [pousr]
  },
  'github-fine-grained': {
    positive: 'github_pat_TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'github_pat_short',
  },
  'aws-access-key': {
    positive: 'AKIATESTFODNN7EXAMPL', // AKIA + 16 位大写字母（TEST 标记），仍命中正则
    negative: 'AKIAIOSFODNN7EXAMP', // 15 位
  },
  'aws-secret-key': {
    positive: 'AWS_SECRET_ACCESS_KEY=' + 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY',
    negative: 'AWS_SECRET_ACCESS_KEY=short', // 值 <16
  },
  'google-api-key': {
    positive: 'AIzaTESTABCDEFGHIJKLMNOPQRSTUVWXYZ',
    negative: 'AIzaShort',
  },
  'google-oauth-secret': {
    positive: 'GOCSPX-TEST-abcdefghijklmnopqrstuvwxyz',
    negative: 'GOCSPX-short',
  },
  'stripe-live': {
    // 注意：前缀（sk_live_/sk_test_）用字符串拼接构造，避免源码中出现完整
    // Stripe key 形态被 GitHub Push Protection 拦截
    positive: 'sk_live_' + 'TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'sk_live_short',
  },
  'stripe-test': {
    positive: 'sk_test_' + 'TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'sk_test_short',
  },
  'slack-token': {
    positive: 'xoxb-TEST-abcdefghijklmnopqrstuv',
    negative: 'xoxx-abcdefghijklmnopqrstuv', // xoxx 不在 [baprs]
  },
  'npm-token': {
    positive: 'npm_TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'npm_short',
  },
  'docker-hub': {
    positive: 'dckr_pat_TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'dckr_pat_short',
  },
  'telegram-bot': {
    positive: '1234567890:TESTabcdefghijklmnopqrstuvwxyzABCDEFG',
    negative: '12345:abcdefghijklmnopqrstuvwxyzABCDEFG', // 数字段 5 位
  },
  'huggingface': {
    positive: 'hf_TESTabcdefghijklmnopqrstuvwxyz',
    negative: 'hf_short',
  },
  'sendgrid': {
    positive: 'SG.TESTabcdefghijklmnopqrstuvwxyz.TESTABCDEFGHIJKLMNOPQRSTUVWXYZ',
    negative: 'SG.abcdefghijklmnopqrstuvwxyz', // 缺第二段
  },
  'twilio': {
    // 前缀+hex 拼接构造，避免源码出现完整 Twilio key 形态
    positive: 'SK' + '0123456789abcdef0123456789abcdef',
    negative: 'SK0123456789abcdef0123456789abcde', // 31 位
  },
  'mailgun': {
    positive: 'key-' + '0123456789abcdef0123456789abcdef',
    negative: 'key-0123456789abcdef0123456789abcde',
  },
  'jwt-token': {
    positive: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    negative: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0', // 两段
  },
  'private-key-pem': {
    positive: '-----BEGIN RSA PRIVATE KEY-----',
    negative: '-----BEGIN PUBLIC KEY-----',
  },
  'generic-secret': {
    positive: 'api_key = "TESTabcdefghijklmnopqrstuvwxyz"',
    negative: 'api_key = "short"', // 值 <16
  },
  'gitlab-pat': {
    positive: 'glpat-TEST-abcdefghijklmnopqrstuvwxyz',
    negative: 'glpat-short',
  },
  'azure-storage': {
    positive: 'AccountKey=TESTabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/',
    negative: 'AccountKey=short',
  },
  'datadog-api': {
    positive: 'DD_API_KEY=TESTefghijklmnopqrstuvwxyzABCDEF',
    negative: 'DD_API_KEY=short',
  },
  'alibaba-access': {
    positive: 'LTAITESTabcdefghijklmnopqrstuvwxyz',
    negative: 'LTAIshort',
  },
  'generic-jwt-secret': {
    positive: 'jwt_secret = "TESTabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"',
    negative: 'jwt_secret = "short"',
  },
};

test('规则库至少 26 条', () => {
  assert.ok(rules.length >= 26, `expected >=26 rules, got ${rules.length}`);
});

test('每条规则 schema 完整', () => {
  const validSeverities = ['Critical', 'High', 'Medium', 'Low'];
  for (const rule of rules) {
    for (const key of RULE_SCHEMA_KEYS) {
      assert.ok(rule[key] !== undefined && rule[key] !== '', `${rule.id} missing schema key: ${key}`);
    }
    assert.ok(rule.regex instanceof RegExp, `${rule.id} regex must be RegExp`);
    assert.ok(validSeverities.includes(rule.severity), `${rule.id} invalid severity: ${rule.severity}`);
  }
});

test('规则间不重叠：sk-proj-/sk-ant- 只命中专属规则', () => {
  const openai = rules.find((r) => r.id === 'openai-api-key');
  const openaiProj = rules.find((r) => r.id === 'openai-project-key');
  const anthropic = rules.find((r) => r.id === 'anthropic-api-key');
  // openai-api-key 不应命中 proj/ant 前缀（前缀否定已生效）
  assert.ok(!openai.regex.test('sk-proj-TEST-abcdefghijklmnopqrstuvwxyz'), 'openai-api-key must not match sk-proj-');
  assert.ok(!openai.regex.test('sk-ant-TEST-abcdefghijklmnopqrstuvwxyz'), 'openai-api-key must not match sk-ant-');
  // 专属规则各自命中
  assert.ok(openaiProj.regex.test('sk-proj-TEST-abcdefghijklmnopqrstuvwxyz'), 'openai-project-key must match sk-proj-');
  assert.ok(anthropic.regex.test('sk-ant-TEST-abcdefghijklmnopqrstuvwxyz'), 'anthropic-api-key must match sk-ant-');
});

test('每条规则有测试用例覆盖', () => {
  for (const rule of rules) {
    assert.ok(CASES[rule.id], `no test case for rule: ${rule.id}`);
  }
});

test('正例全部命中', () => {
  for (const rule of rules) {
    const c = CASES[rule.id];
    assert.ok(rule.regex.test(c.positive), `positive miss for ${rule.id}: ${c.positive}`);
  }
});

test('反例全部不命中', () => {
  for (const rule of rules) {
    const c = CASES[rule.id];
    assert.ok(!rule.regex.test(c.negative), `negative false-positive for ${rule.id}: ${c.negative}`);
  }
});
