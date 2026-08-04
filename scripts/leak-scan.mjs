#!/usr/bin/env node
/**
 * leak-scan.mjs — secret-leak-preflight 核心扫描器
 *
 * 零依赖纯 Node ESM（fs/path/child_process），跨平台（Windows/macOS/Linux）。
 * 任何 AI agent 宿主都可通过 bash/工具调用本脚本做发布前秘密泄漏预检。
 *
 * 用法：
 *   node leak-scan.mjs <path> [--strict] [--json] [--staged] [--history] [--no-external]
 *
 * 退出码：
 *   0  通过（无阻断级风险，且无扫描错误）
 *   2  阻断（发现 Critical/High，--strict 时含 Medium）
 *   1  扫描过程出错（目标不存在/非目录/未知参数/任一深度扫描失败）
 *
 * 安全不变量（硬性）：
 *   - 输出（人类表格与 JSON）只含 file:line:rule，绝不含匹配到的密钥值
 *   - remote URL 中的 userinfo（user:pass@）在输出前被 redact
 *   - 不执行任意代码（无 eval）；只读文件 + 调 git/gitleaks/trufflehog 子进程
 *   - 外部工具缺失时降级跳过；外部工具运行出错时告警不阻断（exit 1 泄漏除外）
 *   - 任一深度扫描（--staged/--history）失败或超时时写入 scanErrors 并 exit 1，
 *     不允许静默假通过
 */
import { readFileSync, statSync, readdirSync, existsSync } from 'node:fs';
import { join, relative, sep, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { rules } from '../rules/rules.mjs';

// ---------- 常量 ----------

// 注意：不把 test/ 加入 SKIP_DIRS——真实项目的 test 目录也可能含真密钥，
// 全局跳过会造成漏报。skill 自身测试夹具被检出是正例测试的设计使然。
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '.next', 'target', '.cache']);
const MAX_FILE_BYTES = 1024 * 1024; // >1MB 跳过
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

// 伪阳性判定（值级）：仅当"匹配值本身"含示例/占位特征时跳过。
// 不做整行丢弃——同一行其他规则或同一规则的其他匹配不受影响。
function isPlaceholder(matchText) {
  // 赋值形态（api_key = "xxx" / token: 'xxx'）取等号/冒号后的值段判定；
  // 非赋值形态（裸 sk-... 等）对整个匹配串判定。
  const eq = /[:=]\s*['"]?([^'"\s]+)/i.exec(matchText);
  const value = eq ? eq[1] : matchText;
  return /(example|placeholder|dummy|fake|xxxx+|your[-_ ]?api[-_ ]?key)/i.test(value);
}

// 文件名规则：匹配返回 { severity, rule, message }
function filenameFinding(name) {
  if (/^\.env(\..+)?$/.test(name) && !/^\.env\.example$/.test(name)) {
    return { severity: 'High', rule: 'risky-env-file', message: 'Environment file would be unsafe to publish unless it is intentionally ignored and never committed.' };
  }
  if (/\.(key|pem|p12|pfx)$/i.test(name)) {
    return { severity: 'High', rule: 'private-key-file', message: 'Private key or certificate-like file found.' };
  }
  if (/^(secrets?|credentials?)\./i.test(name) || /(secret|credential|token)/i.test(name)) {
    return { severity: 'Medium', rule: 'risky-secret-filename', message: 'File name suggests sensitive material; inspect before publishing.' };
  }
  return null;
}

// ---------- 工具 ----------

function runCmd(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: 'utf8', timeout: 30000, windowsHide: true, ...opts });
  if (res.error) return { ok: false, error: res.error, code: null, stdout: '', stderr: '' };
  return { ok: res.status === 0, code: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function commandExists(cmd) {
  const res = runCmd(process.platform === 'win32' ? 'where' : 'which', [cmd], { shell: true });
  return res.ok && res.stdout.trim().length > 0;
}

// remote URL 输出前剥离 userinfo 段（user:pass@ → ***@），防止内嵌凭据进输出
function redactRemote(url) {
  return url.replace(/(\/\/)([^/@]+)@/, '$1***@');
}

// ---------- 扫描 ----------

function walkFiles(root, findings, skipped) {
  const out = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      skipped.dirs += 1;
      continue; // 无权限目录跳过并计数
    }
    for (const ent of entries) {
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      const rel = relative(root, full).split(sep).join('/');
      const f = filenameFinding(ent.name);
      if (f) findings.push({ severity: f.severity, rule: f.rule, file: rel, line: 0, message: f.message });
      out.push({ full, rel });
    }
  }
  return out;
}

function scanFile(file, findings, skipped) {
  let st;
  try {
    st = statSync(file.full);
  } catch {
    return;
  }
  if (st.size > MAX_FILE_BYTES) {
    skipped.files += 1;
    return;
  }
  let content;
  try {
    content = readFileSync(file.full, 'utf8');
  } catch {
    return; // 二进制/编码失败跳过
  }
  if (content.includes('\u0000')) return; // 二进制
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of rules) {
      const m = rule.regex.exec(line);
      if (m && !isPlaceholder(m[0])) {
        findings.push({
          severity: rule.severity,
          rule: rule.id,
          file: file.rel,
          line: i + 1,
          message: `${rule.name}. Value redacted; rotate if this was ever committed or published.`,
        });
      }
    }
  }
}

/**
 * scanText — 扫描 git diff 输出（--staged / --history 共用）。
 * 解析 `+++ b/<file>` 文件头与 `@@ -a,n +b,m @@` hunk 头，
 * 还原真实文件名与源文件行号（new-side 起始行 + 新增行计数）。
 * 无法解析时回退到标签（staged/history）+ diff 行索引。
 */
function scanText(text, label, findings) {
  let currentFile = null;
  let addLine = 0; // 当前 hunk 的新文件起始行号
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fileHdr = /^\+\+\+ b\/(.*)$/.exec(line);
    if (fileHdr) {
      currentFile = fileHdr[1];
      addLine = 0;
      continue;
    }
    const hunkHdr = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunkHdr) {
      addLine = parseInt(hunkHdr[1], 10);
      continue;
    }
    if (!line.startsWith('+')) continue; // 只看新增行（含 hunk 上下文之外的 + 行）
    const content = line.slice(1);
    for (const rule of rules) {
      const m = rule.regex.exec(content);
      if (m && !isPlaceholder(m[0])) {
        findings.push({
          severity: rule.severity,
          rule: rule.id,
          file: currentFile || label,
          line: addLine,
          message: `${rule.name} in ${label}. Value redacted; rotate if this was ever committed or published.`,
        });
      }
    }
    addLine += 1;
  }
}

// ---------- 外部工具 ----------

function runExternalTools(target, gitRepo, findings, tools, scanErrors) {
  // gitleaks：exit 1 = 发现泄漏（阻断）；其他非零 = 工具错误（告警不阻断）
  tools.gitleaks = commandExists('gitleaks');
  if (tools.gitleaks && gitRepo) {
    const res = runCmd('gitleaks', ['detect', '--source', target, '--redact', '--no-banner'], { cwd: target });
    if (res.code === 1) {
      findings.push({ severity: 'High', rule: 'gitleaks', file: '.', line: 0, message: 'Gitleaks reported possible secrets. Re-run gitleaks locally for redacted detail.' });
    } else if (res.code !== 0 && res.code !== null) {
      scanErrors.push(`gitleaks detect failed (exit ${res.code}): ${res.stderr.trim().slice(0, 200) || 'see gitleaks output'}`);
    }
  }
  // trufflehog：用相对路径 file://.（对齐 tooling.md 已文档化的可用形式；
  // file:/// 绝对形式在 Windows 会被解析成 C:\.git 而失败——实测确认）
  tools.trufflehog = commandExists('trufflehog');
  if (tools.trufflehog && gitRepo) {
    const res = runCmd('trufflehog', ['git', 'file://.', '--only-verified', '--no-update'], { cwd: target, timeout: 120000 });
    if (res.ok && res.stdout.trim().length > 0) {
      findings.push({ severity: 'Critical', rule: 'trufflehog-verified', file: '.', line: 0, message: 'TruffleHog reported verified secrets. Rotate affected credentials immediately.' });
    } else if (!res.ok && res.code !== null) {
      scanErrors.push(`trufflehog git failed (exit ${res.code}): ${res.stderr.trim().slice(0, 200) || 'see trufflehog output'}`);
    }
  }
}

// ---------- 输出 ----------

function severityRank(s) {
  return { Critical: 0, High: 1, Medium: 2, Low: 3 }[s] ?? 9;
}

function formatHuman(result) {
  const lines = [];
  lines.push('API Key Leak Pre-Publish Check');
  lines.push(`Target: ${result.target}`);
  lines.push(`Git repo: ${result.gitRepo}`);
  if (result.remote) lines.push(`Remote: ${redactRemote(result.remote)}`);
  lines.push(`Blocked: ${result.blocked}`);
  if (result.scanErrors.length > 0) {
    lines.push(`Scan errors (${result.scanErrors.length}):`);
    for (const e of result.scanErrors) lines.push(`  - ${e}`);
  }
  lines.push(`Skipped: ${result.skipped.files} files (${MAX_FILE_BYTES / 1024}KB+), ${result.skipped.dirs} dirs (unreadable)`);
  lines.push('');
  if (result.findings.length === 0) {
    lines.push('No blocking secret indicators found.');
  } else {
    const sorted = [...result.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.file.localeCompare(b.file));
    lines.push('SEVERITY  RULE                    FILE:LINE  MESSAGE');
    for (const f of sorted) {
      const loc = f.line > 0 ? `${f.file}:${f.line}` : f.file;
      lines.push(`${f.severity.padEnd(9)} ${f.rule.padEnd(22)} ${loc}  ${f.message}`);
    }
  }
  return lines.join('\n');
}

// ---------- main ----------

function parseArgs(argv, scanErrors) {
  const opts = { path: '.', strict: false, json: false, staged: false, history: false, noExternal: false };
  for (const a of argv) {
    if (a === '--strict') opts.strict = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--staged') opts.staged = true;
    else if (a === '--history') opts.history = true;
    else if (a === '--no-external') opts.noExternal = true;
    else if (a.startsWith('-')) scanErrors.push(`unknown option: ${a}`);
    else opts.path = a;
  }
  return opts;
}

function main() {
  const scanErrors = [];
  const opts = parseArgs(process.argv.slice(2), scanErrors);
  if (scanErrors.length > 0) {
    for (const e of scanErrors) process.stderr.write(`Error: ${e}\n`);
    process.exit(1);
  }

  const target = resolve(opts.path);
  if (!existsSync(target)) {
    process.stderr.write(`Error: path does not exist: ${target}\n`);
    process.exit(1);
  }
  if (!statSync(target).isDirectory()) {
    process.stderr.write(`Error: target must be a directory, got file: ${target}\n`);
    process.exit(1);
  }

  const findings = [];
  const skipped = { files: 0, dirs: 0 };
  const tools = { git: commandExists('git'), gitleaks: false, trufflehog: false };

  // 探测 git repo
  let gitRepo = false;
  let remote = '';
  if (tools.git) {
    const probe = runCmd('git', ['-C', target, 'rev-parse', '--is-inside-work-tree']);
    if (probe.ok && probe.stdout.trim() === 'true') {
      gitRepo = true;
      const rm = runCmd('git', ['-C', target, 'remote', 'get-url', 'origin']);
      if (rm.ok) remote = rm.stdout.trim().split('\n')[0];
    }
  }

  // 文件系统扫描
  const files = walkFiles(target, findings, skipped);
  for (const f of files) scanFile(f, findings, skipped);

  // staged 深度检测：失败/超时 → 记入 scanErrors（不静默假通过）
  if (opts.staged && gitRepo) {
    const res = runCmd('git', ['-C', target, 'diff', '--cached']);
    if (res.ok) {
      scanText(res.stdout, 'staged', findings);
    } else {
      scanErrors.push(`git diff --cached failed${res.code !== null ? ` (exit ${res.code})` : ` (${res.error.message})`}`);
    }
  }

  // history 深度检测：同上
  if (opts.history && gitRepo) {
    const res = runCmd('git', ['-C', target, 'log', '-p', '--all'], { timeout: 120000 });
    if (res.ok) {
      scanText(res.stdout, 'history', findings);
    } else {
      scanErrors.push(`git log -p --all ${res.code !== null ? `(exit ${res.code})` : `(${res.error.message})`} — history scan incomplete`);
    }
  }

  // 外部工具
  if (!opts.noExternal) runExternalTools(target, gitRepo, findings, tools, scanErrors);

  // 分级与阻断
  const blocking = new Set(['Critical', 'High']);
  if (opts.strict) blocking.add('Medium');
  const blocked = findings.some((f) => blocking.has(f.severity));

  const result = {
    target,
    gitRepo,
    remote: redactRemote(remote),
    tools,
    strict: opts.strict,
    blocked,
    scanErrors,
    skipped,
    findings,
  };

  if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(formatHuman(result) + '\n');
  }

  // 退出码：扫描出错优先（fail-closed，不允许假通过）
  if (scanErrors.length > 0) process.exit(1);
  process.exit(blocked ? 2 : 0);
}

main();
