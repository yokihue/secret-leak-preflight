/**
 * leak-scan.test.mjs — 集成测试
 *
 * 覆盖：
 * - 含假 .env 的临时目录 → exit 2 且 stdout 无密钥值（redact 硬不变量）
 * - 干净临时目录 → exit 0
 * - --json 输出可 JSON.parse，含 blocked/findings/tools/skipped/scanErrors 字段
 * - staged 场景：临时 git repo 中 git add 含假 key 文件 → --staged 检出（验证 staged 通道本身，非工作树扫描）
 * - 未知 CLI 参数 → exit 1（fail-loud）
 * - 目标为单文件 → exit 1（必须目录）
 *
 * 纪律：所有假密钥值带 TEST 或 test 前缀，明显为假；测试断言不打印匹配值。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCRIPT = join(import.meta.dirname, '..', 'scripts', 'leak-scan.mjs');

function runScan(args, cwd) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd, encoding: 'utf8' });
}

function makeTempDir() {
  return mkdtempSync(join(tmpdir(), 'slp-test-'));
}

function cleanup(dir) {
  rmSync(dir, { recursive: true, force: true });
}

test('含假 .env 的目录 → exit 2，stdout 无密钥值', () => {
  const dir = makeTempDir();
  try {
    // 假值带 test 前缀，明显非真实密钥；文件名 .env 触发文件名规则
    writeFileSync(join(dir, '.env'), 'TEST_OPENAI_API_KEY=sk-test-abcdefghijklmnopqrstuvwxyz\n');
    const res = runScan([dir, '--no-external'], process.cwd());
    assert.equal(res.status, 2, `expected exit 2, got ${res.status}\n${res.stdout}`);
    // redact 硬不变量：输出不含匹配值
    assert.ok(!res.stdout.includes('sk-test-abcdefghijklmnopqrstuvwxyz'), 'stdout leaked secret value');
    // 含文件名与规则名
    assert.ok(res.stdout.includes('.env'), 'stdout missing filename');
  } finally {
    cleanup(dir);
  }
});

test('干净目录 → exit 0', () => {
  const dir = makeTempDir();
  try {
    writeFileSync(join(dir, 'README.md'), '# hello\nplain content\n');
    const res = runScan([dir, '--no-external'], process.cwd());
    assert.equal(res.status, 0, `expected exit 0, got ${res.status}\n${res.stdout}`);
  } finally {
    cleanup(dir);
  }
});

test('--json 输出结构：blocked/findings/tools/skipped/scanErrors', () => {
  const dir = makeTempDir();
  try {
    const secret = 'sk-test-abcdefghijklmnopqrstuvwxyz';
    writeFileSync(join(dir, '.env'), `TEST_OPENAI_API_KEY=${secret}\n`);
    const res = runScan([dir, '--json', '--no-external'], process.cwd());
    assert.equal(res.status, 2);
    const parsed = JSON.parse(res.stdout);
    assert.equal(typeof parsed.blocked, 'boolean');
    assert.ok(Array.isArray(parsed.findings));
    assert.ok(parsed.findings.length > 0);
    assert.ok(parsed.tools && typeof parsed.tools === 'object');
    assert.ok(parsed.target);
    assert.ok(parsed.skipped && typeof parsed.skipped.files === 'number');
    assert.ok(Array.isArray(parsed.scanErrors));
    // redact 硬不变量：JSON 序列化结果不得含密钥值（agent 消费主通道）
    assert.ok(!res.stdout.includes(secret), 'JSON output leaked secret value');
  } finally {
    cleanup(dir);
  }
});

test('--json 干净目录：blocked=false', () => {
  const dir = makeTempDir();
  try {
    writeFileSync(join(dir, 'README.md'), '# hello\n');
    const res = runScan([dir, '--json', '--no-external'], process.cwd());
    assert.equal(res.status, 0);
    const parsed = JSON.parse(res.stdout);
    assert.equal(parsed.blocked, false);
    assert.equal(parsed.scanErrors.length, 0);
  } finally {
    cleanup(dir);
  }
});

test('staged 场景：--staged 通道产出带 staged 标识的真实文件名', () => {
  const dir = makeTempDir();
  try {
    // 初始化临时 git repo
    const init = spawnSync('git', ['init', '-q'], { cwd: dir, encoding: 'utf8' });
    assert.equal(init.status, 0, `git init failed: ${init.stderr}`);
    // 内容里含假 key（文件名不敏感，测内容规则 + staged 通道）
    writeFileSync(join(dir, 'config.json'), '{"api_key": "sk-test-abcdefghijklmnopqrstuvwxyz"}\n');
    const add = spawnSync('git', ['add', 'config.json'], { cwd: dir, encoding: 'utf8' });
    assert.equal(add.status, 0, `git add failed: ${add.stderr}`);
    // --staged --json：staged 通道产出的 finding 应带 staged 标识与真实文件名
    const secret = 'sk-test-abcdefghijklmnopqrstuvwxyz';
    const staged = runScan([dir, '--staged', '--json', '--no-external'], process.cwd());
    assert.equal(staged.status, 2, `staged scan expected exit 2, got ${staged.status}`);
    const parsed = JSON.parse(staged.stdout);
    const stagedFindings = parsed.findings.filter((f) => f.message.includes('staged'));
    assert.ok(stagedFindings.length > 0, 'no findings from staged channel');
    // file 应为解析出的真实文件名（来自 +++ b/config.json），而非常量标签
    assert.ok(stagedFindings.every((f) => f.file === 'config.json'), `staged finding file wrong: ${stagedFindings.map((f) => f.file).join(',')}`);
    // line 应 > 0（hunk 行号已解析）
    assert.ok(stagedFindings.every((f) => f.line > 0), 'staged finding line must be > 0');
    // redact 硬不变量：staged 通道的 JSON 输出也不得含密钥值
    assert.ok(!staged.stdout.includes(secret), 'staged JSON output leaked secret value');
  } finally {
    cleanup(dir);
  }
});

test('伪阳性：example 值不阻断', () => {
  const dir = makeTempDir();
  try {
    writeFileSync(join(dir, 'config.js'), 'const apiKey = "sk-example-abcdefghijklmnopqrstuvwxyz";\n');
    const res = runScan([dir, '--no-external'], process.cwd());
    // example 值应被值级伪阳性过滤跳过；config.js 文件名不触发文件名规则
    assert.equal(res.status, 0, `expected exit 0, got ${res.status}\n${res.stdout}`);
  } finally {
    cleanup(dir);
  }
});

test('未知 CLI 参数 → exit 1（fail-loud）', () => {
  const dir = makeTempDir();
  try {
    writeFileSync(join(dir, 'README.md'), '# hello\n');
    const res = runScan([dir, '--stric'], process.cwd());
    assert.equal(res.status, 1, `expected exit 1, got ${res.status}`);
    assert.ok(res.stderr.includes('unknown option'), 'stderr missing unknown option warning');
  } finally {
    cleanup(dir);
  }
});

test('目标为单文件 → exit 1（必须目录）', () => {
  const dir = makeTempDir();
  try {
    const f = join(dir, 'single.txt');
    writeFileSync(f, 'plain\n');
    const res = runScan([f], process.cwd());
    assert.equal(res.status, 1, `expected exit 1, got ${res.status}`);
    assert.ok(res.stderr.includes('must be a directory'), 'stderr missing directory requirement');
  } finally {
    cleanup(dir);
  }
});

test('--history 在非 git 目录 → scanErrors 告警且 exit 1（不静默假通过）', () => {
  const dir = makeTempDir();
  try {
    writeFileSync(join(dir, 'README.md'), '# hello\n');
    // 非 git 仓库：请求 --history 但 gitRepo=false → 必须告警（scanErrors 非空）并 exit 1，
    // 不允许静默跳过假装"扫过且干净"
    const res = runScan([dir, '--history', '--json', '--no-external'], process.cwd());
    assert.equal(res.status, 1, `expected exit 1, got ${res.status}\n${res.stdout}`);
    const parsed = JSON.parse(res.stdout);
    assert.ok(parsed.scanErrors.length > 0, 'non-git history skip must produce a scanError');
    assert.ok(parsed.scanErrors.some((e) => e.includes('not a git repository')), 'scanErrors must explain the skip');
  } finally {
    cleanup(dir);
  }
});

test('gitleaks 外部工具：安装且检出时产生 finding（不静默）', () => {
  const dir = makeTempDir();
  try {
    // 初始化 git repo 并提交一个 gitleaks 能识别的 AWS key（AKIA 格式）
    const init = spawnSync('git', ['init', '-q'], { cwd: dir, encoding: 'utf8' });
    assert.equal(init.status, 0, `git init failed: ${init.stderr}`);
    writeFileSync(join(dir, 'creds.txt'), 'aws_access_key_id=AKIATESTFODNN7EXAMPL\n');
    spawnSync('git', ['add', 'creds.txt'], { cwd: dir });
    const commit = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init'], { cwd: dir });
    assert.equal(commit.status, 0, `git commit failed: ${commit.stderr}`);
    // 不带 --no-external：gitleaks 已装时真实调用。若未装则降级跳过（测试不失败）
    const res = runScan([dir, '--json'], process.cwd());
    const parsed = JSON.parse(res.stdout);
    if (parsed.tools.gitleaks) {
      // gitleaks 可用：应产生 gitleaks finding 或 scanErrors（工具报错），而非静默
      const hasGitleaksSignal = parsed.findings.some((f) => f.rule === 'gitleaks') || parsed.scanErrors.some((e) => e.includes('gitleaks'));
      assert.ok(hasGitleaksSignal, 'gitleaks available but produced no signal (silent)');
    }
  } finally {
    cleanup(dir);
  }
});
