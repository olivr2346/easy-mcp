#!/usr/bin/env node
/*
 * Easy MCP — server
 *
 * A small, dependency-free MCP server that exposes one local project folder
 * to web AI clients, plus a plain web dashboard for the human running it.
 *
 * Routes (all token-gated except none):
 *   POST /mcp            JSON-RPC 2.0 (initialize, tools/list, tools/call, ping)
 *   GET  /sse            MCP SSE transport (endpoint event -> /messages)
 *   POST /messages       MCP SSE transport messages
 *   POST /call           { name, arguments } convenience tool call
 *   GET  /               dashboard page
 *   GET  /api/dashboard  dashboard JSON
 *   POST /api/set-project { path }
 *   POST /api/set-public-url { url }   (called by the launcher)
 *   POST /api/stop-job   { id }
 *
 * Auth: Authorization: Bearer <token>, x-easy-mcp-token header, or ?token=.
 * Binds 127.0.0.1 only; remote access goes through the tunnel.
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync, execFile } = require('child_process');
const os = require('os');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
function argValue(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}
const PORT = Number(process.env.EASY_MCP_PORT || argValue('--port', '9494'));
let TOKEN = process.env.EASY_MCP_TOKEN || argValue('--token', '');
// Fail closed: never run unauthenticated. If no token was passed in (direct
// `node server.js` run), load or create the persistent one the launcher uses.
if (!TOKEN) {
  const tokenFile = path.join(os.homedir(), '.easy-mcp', 'token');
  try { TOKEN = fs.readFileSync(tokenFile, 'utf8').trim(); } catch {}
  if (!TOKEN) {
    TOKEN = crypto.randomBytes(24).toString('hex');
    try {
      fs.mkdirSync(path.dirname(tokenFile), { recursive: true, mode: 0o700 });
      fs.writeFileSync(tokenFile, TOKEN + '\n', { mode: 0o600 });
    } catch {}
  }
}
// Per-process secret for the local dashboard control plane (/api/*). Embedded
// in the dashboard HTML, which is only served to loopback requests.
const ADMIN_SECRET = crypto.randomBytes(32).toString('hex');
function sha256hex(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return ba.length === bb.length && ba.length > 0 && crypto.timingSafeEqual(ba, bb);
}
let DISABLE_SHELL = args.includes('--disable-shell') || process.env.EASY_MCP_DISABLE_SHELL === '1';
let READ_ONLY = args.includes('--read-only') || process.env.EASY_MCP_READ_ONLY === '1';
let SKIP_JAIL = args.includes('--dangerously-skip-jail') || process.env.EASY_MCP_SKIP_JAIL === '1';
let projectRoot = path.resolve(process.env.EASY_MCP_PROJECT || args.find(a => !a.startsWith('--')) || process.cwd());
let publicUrl = (process.env.EASY_MCP_PUBLIC_URL || '').replace(/\/+$/, '');

// ---------------------------------------------------------------------------
// Tunnel manager — Cloudflare quick tunnel (default) or Tailscale Funnel
// (persistent link). Mode persists in ~/.easy-mcp/config.json.
// ---------------------------------------------------------------------------
const easyMcpHome = path.join(os.homedir(), '.easy-mcp');
const configFile = path.join(easyMcpHome, 'config.json');
function loadConfig() { try { return JSON.parse(fs.readFileSync(configFile, 'utf8')); } catch { return {}; } }
function saveConfig(patch) {
  try {
    fs.mkdirSync(easyMcpHome, { recursive: true });
    fs.writeFileSync(configFile, JSON.stringify({ ...loadConfig(), ...patch }, null, 2) + '\n');
  } catch {}
}
let tunnelMode = process.env.EASY_MCP_TUNNEL || loadConfig().tunnel || 'cloudflare';
if (!['cloudflare', 'funnel', 'none'].includes(tunnelMode)) tunnelMode = 'cloudflare';
let tunnelProc = null;
let tunnelError = '';

function cloudflaredPath() {
  return path.join(easyMcpHome, 'bin', process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared');
}
function ensureCloudflared() {
  const bin = cloudflaredPath();
  if (fs.existsSync(bin)) return Promise.resolve(bin);
  const base = 'https://github.com/cloudflare/cloudflared/releases/latest/download/';
  const name = process.platform === 'win32' ? 'cloudflared-windows-amd64.exe'
    : process.platform === 'darwin' ? (process.arch === 'arm64' ? 'cloudflared-darwin-arm64.tgz' : 'cloudflared-darwin-amd64.tgz')
    : (process.arch === 'arm64' ? 'cloudflared-linux-arm64' : 'cloudflared-linux-amd64');
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  const tmp = bin + '.tmp';
  return new Promise((resolve, reject) => {
    const get = (url) => https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) return get(res.headers.location);
      if (res.statusCode !== 200) return reject(new Error('cloudflared download failed: HTTP ' + res.statusCode));
      const out = fs.createWriteStream(tmp);
      res.pipe(out);
      out.on('finish', () => { fs.renameSync(tmp, bin); if (process.platform !== 'win32') fs.chmodSync(bin, 0o755); resolve(bin); });
      out.on('error', reject);
    }).on('error', reject);
    get(base + name);
  });
}

function stopTunnel() {
  if (tunnelProc) { try { tunnelProc.kill(); } catch {} tunnelProc = null; }
  // Note: Funnel is left ON in tailscaled when switching away — turning it off
  // requires the Tailscale owner's session, and it proxies the same port anyway.
  publicUrl = '';
}

async function startTunnel(mode) {
  tunnelError = '';
  if (mode === 'none') { tunnelMode = 'none'; return; }
  if (mode === 'funnel') {
    try { spawnSync('tailscale', ['funnel', '--bg', String(PORT)], { stdio: 'ignore', timeout: 20000 }); } catch {}
    let dns = '';
    try {
      const st = spawnSync('tailscale', ['status', '--json'], { encoding: 'utf8', timeout: 15000 });
      dns = JSON.parse(st.stdout || '{}').Self?.DNSName?.replace(/\.$/, '') || '';
    } catch {}
    dns = dns || process.env.EASY_MCP_FUNNEL_HOST || '';
    if (!dns) {
      tunnelError = 'Tailscale not found or not signed in. Install: https://tailscale.com/download';
      tunnelMode = 'funnel';
      return;
    }
    tunnelMode = 'funnel';
    publicUrl = 'https://' + dns;
    console.log(`MCP link:  ${publicUrl}/mcp/${TOKEN}`);
    return;
  }
  // cloudflare
  tunnelMode = 'cloudflare';
  const bin = await ensureCloudflared();
  tunnelProc = spawn(bin, ['tunnel', '--url', `http://127.0.0.1:${PORT}`], { stdio: ['ignore', 'pipe', 'pipe'] });
  const onData = (d) => {
    const m = String(d).match(/https:\/\/(?!api\.)[a-z0-9-]+\.trycloudflare\.com/);
    if (m && !publicUrl) {
      publicUrl = m[0];
      console.log(`MCP link:  ${publicUrl}/mcp/${TOKEN}`);
    }
  };
  tunnelProc.stdout.on('data', onData);
  tunnelProc.stderr.on('data', onData);
  tunnelProc.on('exit', () => { tunnelProc = null; if (!publicUrl) tunnelError = 'Cloudflare tunnel failed to start (no internet route?)'; });
}

async function setTunnel(mode) {
  if (!['cloudflare', 'funnel', 'none'].includes(mode)) throw new Error('Unknown tunnel mode: ' + mode);
  stopTunnel();
  saveConfig({ tunnel: mode });
  await startTunnel(mode);
}
const startedAt = Date.now();
const recentFile = path.join(require('os').homedir(), '.easy-mcp', 'recent-projects.json');
function loadRecents() {
  try {
    const list = JSON.parse(fs.readFileSync(recentFile, 'utf8'));
    return Array.isArray(list) ? list.filter(x => typeof x === 'string') : [];
  } catch { return []; }
}
function saveRecents() {
  try {
    fs.mkdirSync(path.dirname(recentFile), { recursive: true });
    fs.writeFileSync(recentFile, JSON.stringify(recentProjects.slice(0, 10), null, 2));
  } catch {}
}
const recentProjects = [...new Set([projectRoot, ...loadRecents()])].slice(0, 10);

// ---------------------------------------------------------------------------
// Stats / activity
// ---------------------------------------------------------------------------

let totalCalls = 0;
let totalErrors = 0;
const recentCalls = []; // { ts, tool, ok, ms }
function recordCall(tool, ok, ms) {
  totalCalls++;
  if (!ok) totalErrors++;
  recentCalls.unshift({ ts: new Date().toISOString(), tool, ok, ms });
  if (recentCalls.length > 100) recentCalls.length = 100;
}

// ---------------------------------------------------------------------------
// Path jail
// ---------------------------------------------------------------------------

function realpathOrAncestor(abs) {
  let cur = abs;
  for (;;) {
    try { return fs.realpathSync(cur); } catch {}
    const parent = path.dirname(cur);
    if (parent === cur) return cur;
    cur = parent;
  }
}
function resolveInProject(p) {
  const abs = path.resolve(projectRoot, String(p || '.'));
  if (SKIP_JAIL) return abs; // --dangerously-skip-jail: any path on the machine
  const root = realpathOrAncestor(projectRoot);
  const rel = path.relative(root, abs);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Path escapes project folder: ${p}`);
  }
  // Symlink escape: the real location must also stay inside the project.
  const real = realpathOrAncestor(abs);
  const realRel = path.relative(root, real);
  if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
    throw new Error(`Path escapes project folder: ${p}`);
  }
  return abs;
}
// When the shell is disabled, writes into .git internals could smuggle command
// execution back in through git itself (config keys, hooks). Block those.
function assertNotGitInternal(abs) {
  if (!DISABLE_SHELL) return;
  const rel = path.relative(realpathOrAncestor(projectRoot), realpathOrAncestor(abs)).split(path.sep).join('/');
  if (rel === '.gitmodules' || rel === '.git/config' || rel.startsWith('.git/hooks/')) {
    throw new Error('Writing git internals is blocked while the shell is disabled');
  }
}
function relOf(abs) {
  const r = path.relative(projectRoot, abs);
  if (r.startsWith('..') || path.isAbsolute(r)) return abs.split(path.sep).join('/');
  return r === '' ? '.' : r.split(path.sep).join('/');
}

// ---------------------------------------------------------------------------
// Background jobs
// ---------------------------------------------------------------------------

const jobs = new Map(); // id -> { id, command, pid, startedAt, status, exitCode, log }
let jobSeq = 0;

function shellCommand(command) {
  return process.platform === 'win32'
    ? { file: 'cmd.exe', args: ['/d', '/s', '/c', command] }
    : { file: '/bin/sh', args: ['-c', command] };
}

function startJob(command) {
  const id = `job-${++jobSeq}`;
  const { file, args: sargs } = shellCommand(command);
  const child = spawn(file, sargs, { cwd: projectRoot, windowsHide: true });
  const job = { id, command, pid: child.pid, startedAt: new Date().toISOString(), status: 'running', exitCode: null, log: '' };
  const push = d => { job.log += d.toString(); if (job.log.length > 200000) job.log = job.log.slice(-200000); };
  child.stdout.on('data', push);
  child.stderr.on('data', push);
  child.on('close', code => { job.status = 'exited'; job.exitCode = code; });
  child.on('error', err => { job.status = 'error'; job.log += `\n${err.message}`; });
  jobs.set(id, job);
  return job;
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '__pycache__']);

function walkFiles(dir, out = [], depth = 0) {
  if (depth > 12 || out.length > 5000) return out;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.isDirectory() && SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkFiles(full, out, depth + 1);
    else if (e.isFile()) out.push(full);
  }
  return out;
}

function readTextFile(abs) {
  const buf = fs.readFileSync(abs);
  if (buf.includes(0)) throw new Error('Binary file, cannot read as text');
  return buf.toString('utf8');
}

function runCommand(command, timeoutMs = 120000) {
  return new Promise((resolve) => {
    const { file, args: sargs } = shellCommand(command);
    const child = spawn(file, sargs, { cwd: projectRoot, windowsHide: true });
    let out = '';
    const push = d => { out += d.toString(); if (out.length > 300000) out = out.slice(-300000); };
    child.stdout.on('data', push);
    child.stderr.on('data', push);
    const timer = setTimeout(() => { child.kill(); out += '\n[timed out]'; }, timeoutMs);
    child.on('close', code => { clearTimeout(timer); resolve({ exitCode: code, output: out.trim() }); });
    child.on('error', err => { clearTimeout(timer); resolve({ exitCode: -1, output: err.message }); });
  });
}

// git runs WITHOUT a shell (argv array), so tool input can never become a
// command. Anti-execution flags stop git config/attributes from spawning
// external programs (pager, fsmonitor, external diff drivers).
function runGit(gitArgs, timeoutMs = 30000) {
  const safeArgs = ['--no-pager', '-c', 'core.pager=cat', '-c', 'core.fsmonitor=false', '-c', 'diff.external=', ...gitArgs];
  const env = { ...process.env };
  if (!SKIP_JAIL) env.GIT_CEILING_DIRECTORIES = path.dirname(realpathOrAncestor(projectRoot));
  return new Promise((resolve) => {
    execFile('git', safeArgs, { cwd: projectRoot, shell: false, windowsHide: true, timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024, env }, (err, stdout, stderr) => {
      if (err && err.code === 'ENOENT') return resolve({ exitCode: -1, output: 'git not found on this machine' });
      resolve({ exitCode: err ? (typeof err.code === 'number' ? err.code : -1) : 0, output: ((stdout || '') + (stderr || '')).trim() });
    });
  });
}

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    if (!/^https:\/\//.test(url)) return reject(new Error('Only https:// URLs are allowed'));
    https.get(url, { headers: { 'User-Agent': 'easy-mcp' }, timeout: 20000 }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        return resolve(fetchUrl(new URL(res.headers.location, url).toString()));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', d => { body += d; if (body.length > 300000) res.destroy(); });
      res.on('end', () => resolve(body.slice(0, 300000)));
    }).on('error', reject);
  });
}

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read a UTF-8 text file from the project folder. Returns line-numbered content.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
    run: ({ path: p }) => {
      const abs = resolveInProject(p);
      const lines = readTextFile(abs).split('\n');
      return `File: ${relOf(abs)} (${lines.length} lines)\n\n` + lines.map((l, i) => `${String(i + 1).padStart(4)} | ${l}`).join('\n');
    }
  },
  {
    name: 'read_files',
    description: 'Read several text files at once.',
    inputSchema: { type: 'object', properties: { paths: { type: 'array', items: { type: 'string' } } }, required: ['paths'] },
    run: ({ paths }) => paths.map(p => {
      try { return `===== ${p} =====\n${readTextFile(resolveInProject(p))}`; }
      catch (e) { return `===== ${p} =====\n[error] ${e.message}`; }
    }).join('\n\n')
  },
  {
    name: 'write_file',
    description: 'Create or overwrite a text file in the project folder.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
    write: true,
    run: ({ path: p, content }) => {
      const abs = resolveInProject(p);
      assertNotGitInternal(abs);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content, 'utf8');
      return `Wrote ${relOf(abs)} (${Buffer.byteLength(content)} bytes)`;
    }
  },
  {
    name: 'write_files',
    description: 'Create or overwrite several text files at once.',
    inputSchema: { type: 'object', properties: { files: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] } } }, required: ['files'] },
    write: true,
    run: ({ files }) => files.map(f => {
      const abs = resolveInProject(f.path);
      assertNotGitInternal(abs);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, f.content, 'utf8');
      return `Wrote ${relOf(abs)}`;
    }).join('\n')
  },
  {
    name: 'edit_file',
    description: 'Replace an exact text snippet in a file. Fails if old_text is not found or not unique.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, old_text: { type: 'string' }, new_text: { type: 'string' } }, required: ['path', 'old_text', 'new_text'] },
    write: true,
    run: ({ path: p, old_text, new_text }) => {
      const abs = resolveInProject(p);
      assertNotGitInternal(abs);
      const text = readTextFile(abs);
      const first = text.indexOf(old_text);
      if (first < 0) throw new Error('old_text not found');
      if (text.indexOf(old_text, first + 1) >= 0) throw new Error('old_text is not unique');
      fs.writeFileSync(abs, text.slice(0, first) + new_text + text.slice(first + old_text.length), 'utf8');
      return `Edited ${relOf(abs)}`;
    }
  },
  {
    name: 'list_directory',
    description: 'List files and folders in a project directory.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
    run: ({ path: p }) => {
      const abs = resolveInProject(p || '.');
      const entries = fs.readdirSync(abs, { withFileTypes: true });
      const lines = entries.map(e => {
        const full = path.join(abs, e.name);
        if (e.isDirectory()) return `[DIR]  ${e.name}/`;
        let size = 0; try { size = fs.statSync(full).size; } catch {}
        return `[FILE] ${e.name} (${size} bytes)`;
      });
      return `Directory: ${relOf(abs)}\n\n${lines.join('\n') || '(empty)'}`;
    }
  },
  {
    name: 'search_files',
    description: 'Search file contents for a text query across the project (skips node_modules/.git and binary files).',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, path: { type: 'string' } }, required: ['query'] },
    run: ({ query, path: p }) => {
      const base = resolveInProject(p || '.');
      const files = fs.statSync(base).isDirectory() ? walkFiles(base) : [base];
      const hits = [];
      for (const f of files) {
        let text; try { text = readTextFile(f); } catch { continue; }
        text.split('\n').forEach((line, i) => {
          if (line.includes(query) && hits.length < 200) hits.push(`${relOf(f)}:${i + 1}: ${line.trim().slice(0, 200)}`);
        });
      }
      return hits.length ? hits.join('\n') : 'No matches.';
    }
  },
  {
    name: 'get_file_info',
    description: 'Get size, type and timestamps for a file or folder.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
    run: ({ path: p }) => {
      const abs = resolveInProject(p);
      const st = fs.statSync(abs);
      return JSON.stringify({ path: relOf(abs), type: st.isDirectory() ? 'directory' : 'file', size: st.size, modified: st.mtime.toISOString(), created: st.birthtime.toISOString() }, null, 2);
    }
  },
  {
    name: 'execute_command',
    description: 'Run a shell command inside the project folder (cmd on Windows, sh elsewhere). Returns exit code and output.',
    inputSchema: { type: 'object', properties: { command: { type: 'string' }, timeout_ms: { type: 'number' } }, required: ['command'] },
    shell: true,
    run: async ({ command, timeout_ms }) => {
      const r = await runCommand(command, Math.min(Number(timeout_ms) || 120000, 600000));
      return `Exit code: ${r.exitCode}\n\n${r.output || '(no output)'}`;
    }
  },
  {
    name: 'start_job',
    description: 'Start a long-running background command (dev server, watcher). Returns a job id.',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
    shell: true,
    run: ({ command }) => {
      const job = startJob(command);
      return `Started ${job.id} (pid ${job.pid}): ${command}`;
    }
  },
  {
    name: 'job_status',
    description: 'Check a background job status and recent output.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
    run: ({ id }) => {
      const job = jobs.get(id);
      if (!job) throw new Error(`Unknown job: ${id}`);
      return `${job.id}: ${job.status}${job.exitCode !== null ? ` (exit ${job.exitCode})` : ''}\nCommand: ${job.command}\nStarted: ${job.startedAt}\n\n${job.log.slice(-4000) || '(no output yet)'}`;
    }
  },
  {
    name: 'stop_job',
    description: 'Stop a background job.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
    run: ({ id }) => {
      const job = jobs.get(id);
      if (!job) throw new Error(`Unknown job: ${id}`);
      try { process.kill(job.pid); } catch {}
      job.status = 'stopped';
      return `Stopped ${id}`;
    }
  },
  {
    name: 'list_jobs',
    description: 'List background jobs.',
    inputSchema: { type: 'object', properties: {} },
    run: () => jobs.size
      ? [...jobs.values()].map(j => `${j.id}: ${j.status} — ${j.command}`).join('\n')
      : 'No jobs.'
  },
  {
    name: 'git_status',
    description: 'Run git status in the project folder.',
    inputSchema: { type: 'object', properties: {} },
    run: async () => (await runGit(['status', '--short', '--branch'])).output || '(clean)'
  },
  {
    name: 'git_diff',
    description: 'Run git diff in the project folder (optionally for one path).',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
    run: async ({ path: p }) => {
      const args = ['diff', '--no-ext-diff', '--no-textconv'];
      if (p) {
        if (String(p).includes('\0')) throw new Error('Invalid path');
        const abs = resolveInProject(p);
        const rel = path.relative(realpathOrAncestor(projectRoot), abs).split(path.sep).join('/');
        if (!rel || rel.startsWith('..') || path.isAbsolute(rel) || rel.startsWith(':')) throw new Error(`Path escapes project folder: ${p}`);
        args.push('--', rel);
      }
      return (await runGit(args)).output || '(no diff)';
    }
  },
  {
    name: 'fetch_url',
    description: 'Fetch an https URL (documentation, API reference) and return its text.',
    inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
    run: ({ url }) => fetchUrl(url)
  },
  {
    name: 'get_current_project',
    description: 'Return the current project folder.',
    inputSchema: { type: 'object', properties: {} },
    run: () => projectRoot
  },
  {
    name: 'set_project',
    description: 'Switch the project folder all tools operate on.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
    run: ({ path: p }) => { setProject(p); return `Project folder: ${projectRoot}`; }
  }
];

function setProject(p) {
  const abs = path.resolve(String(p));
  if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new Error(`Not a folder: ${p}`);
  projectRoot = abs;
  const i = recentProjects.indexOf(abs);
  if (i >= 0) recentProjects.splice(i, 1);
  recentProjects.unshift(abs);
  if (recentProjects.length > 10) recentProjects.length = 10;
  saveRecents();
}

const READ_ONLY_TOOLS = new Set(['read_file', 'read_files', 'list_directory', 'search_files', 'get_file_info', 'job_status', 'list_jobs', 'git_status', 'git_diff', 'fetch_url', 'get_current_project']);
function toolList() {
  // The AI must not move its own jail: set_project is hidden while the folder
  // jail is on (the human switches projects in the dashboard instead).
  return TOOLS.filter(t => SKIP_JAIL || t.name !== 'set_project').map(t => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
    annotations: READ_ONLY_TOOLS.has(t.name)
      ? { readOnlyHint: true, destructiveHint: false, openWorldHint: t.name === 'fetch_url' }
      : { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }));
}

async function callTool(name, toolArgs) {
  const tool = TOOLS.find(t => t.name === name);
  if (!tool) throw new Error(`Unknown tool: ${name}`);
  if (name === 'set_project' && !SKIP_JAIL) throw new Error('set_project is disabled while the folder jail is on; switch projects in the Easy MCP dashboard');
  if (READ_ONLY && tool.write) throw new Error('Server is read-only');
  if (DISABLE_SHELL && tool.shell) throw new Error('Shell is disabled on this server');
  const t0 = Date.now();
  try {
    const result = await tool.run(toolArgs || {});
    recordCall(name, true, Date.now() - t0);
    return String(result);
  } catch (err) {
    recordCall(name, false, Date.now() - t0);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC
// ---------------------------------------------------------------------------

async function handleRpc(msg) {
  const { id, method, params } = msg || {};
  const reply = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  switch (method) {
    case 'initialize':
      return reply({
        protocolVersion: params?.protocolVersion || '2025-03-26',
        capabilities: { tools: {} },
        serverInfo: { name: 'Easy MCP', version: '2.2.1' }
      });
    case 'notifications/initialized':
      return null;
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: toolList() });
    case 'tools/call': {
      try {
        const text = await callTool(params?.name, params?.arguments);
        return reply({ content: [{ type: 'text', text }], isError: false });
      } catch (err) {
        return reply({ content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true });
      }
    }
    default:
      return id === undefined ? null : fail(-32601, `Method not found: ${method}`);
  }
}

// ---------------------------------------------------------------------------
// SSE sessions
// ---------------------------------------------------------------------------

const sseSessions = new Map(); // sessionId -> res (legacy SSE transport)
const sseSessionTokens = new Map(); // sessionId -> per-session token sent in SSE endpoint URLs (never the master TOKEN)
const mcpSessions = new Map(); // sessionId -> { createdAt } (Streamable HTTP)

// ---------------------------------------------------------------------------
// Native folder picker (server runs on the user's own machine)
// ---------------------------------------------------------------------------

function pickFolderNative() {
  return new Promise((resolve) => {
    let file, sargs;
    if (process.platform === 'win32') {
      file = 'powershell.exe';
      sargs = ['-NoProfile', '-STA', '-Command',
        "Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = 'Select project folder'; $d.ShowNewFolderButton = $true; if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }"];
    } else if (process.platform === 'darwin') {
      file = 'osascript';
      sargs = ['-e', 'POSIX path of (choose folder with prompt "Select project folder")'];
    } else {
      file = 'zenity';
      sargs = ['--file-selection', '--directory', '--title=Select project folder'];
    }
    const child = spawn(file, sargs, { windowsHide: false });
    let out = '';
    child.stdout.on('data', d => { out += d.toString(); });
    const timer = setTimeout(() => { try { child.kill(); } catch {} resolve(null); }, 180000);
    child.on('close', () => { clearTimeout(timer); const p = out.trim(); resolve(p || null); });
    child.on('error', () => { clearTimeout(timer); resolve(null); });
  });
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req, maxBytes = 10_000_000) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', d => { body += d; if (body.length > maxBytes) req.destroy(); });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}
const PUBLIC_PATHS = new Set([
  '/.well-known/oauth-authorization-server',
  '/.well-known/openid-configuration',
  '/.well-known/oauth-protected-resource',
  '/oauth/register',
  '/oauth/authorize',
  '/oauth/token'
]);
function isPublicPath(p) {
  return PUBLIC_PATHS.has(p) || p.startsWith('/.well-known/oauth-protected-resource/');
}
function bearerOf(req, url) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7)
    : (req.headers['x-easy-mcp-token'] || url.searchParams.get('token') || req._pathToken || '');
}
function authorized(req, url) {
  if (!TOKEN) return false; // fail closed
  const given = bearerOf(req, url);
  if (!given) return false;
  if (safeEqual(given, TOKEN)) return true;
  const sid = url.searchParams.get('sessionId');
  if (sid && sseSessionTokens.has(sid) && safeEqual(given, sseSessionTokens.get(sid))) return true;
  const rec = oauthTokens.get(sha256hex(given));
  return !!(rec && rec.type === 'access' && (!rec.exp || rec.exp > Date.now()));
}
// Dashboard control plane: loopback Host + no tunnel/proxy headers. (Both
// cloudflared and Tailscale Funnel proxy from 127.0.0.1, so the socket IP
// alone cannot tell local from remote — Host + proxy headers can.)
function isLoopbackHost(host) {
  const h = String(host || '').toLowerCase();
  return h === `127.0.0.1:${PORT}` || h === `localhost:${PORT}` || h === `[::1]:${PORT}` || h === '127.0.0.1' || h === 'localhost' || h === '[::1]';
}
function hasTunnelHeaders(req) {
  const h = req.headers;
  return !!(h['cf-connecting-ip'] || h['cf-ray'] || h['x-forwarded-for'] || h['x-forwarded-host'] || h['forwarded'] || h['tailscale-user-login']);
}
function isLocalAdminRequest(req) {
  return isLoopbackHost(req.headers.host) && !hasTunnelHeaders(req);
}
function hostAllowed(req) {
  if (isLoopbackHost(req.headers.host)) return true;
  if (publicUrl) {
    try { return String(req.headers.host || '').toLowerCase() === new URL(publicUrl).host.toLowerCase(); } catch {}
  }
  return false;
}

function dashboardData() {
  const q = TOKEN ? `?token=${TOKEN}` : '';
  return {
    status: 'online',
    project: projectRoot,
    recentProjects,
    readOnly: READ_ONLY,
    disableShell: DISABLE_SHELL,
    skipJail: SKIP_JAIL,
    toolsCount: TOOLS.length,
    toolNames: TOOLS.map(t => t.name),
    sseSessions: sseSessions.size,
    uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
    startedAt: new Date(startedAt).toISOString(),
    totalCalls,
    totalErrors,
    jobs: [...jobs.values()].map(j => ({ id: j.id, command: j.command, status: j.status, startedAt: j.startedAt })),
    publicUrl: publicUrl || null,
    tunnelMode,
    tunnelError: tunnelError || null,
    mcpUrl: publicUrl ? `${publicUrl}/mcp${TOKEN ? '/' + TOKEN : ''}` : null,
    dashboardUrl: `http://127.0.0.1:${PORT}/`,
    recentCalls
  };
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Easy MCP — Dashboard</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg%20xmlns=%22http://www.w3.org/2000/svg%22%20viewBox=%220%200%2064%2064%22%20fill=%22none%22%3E%3Crect%20width=%2264%22%20height=%2264%22%20rx=%2216%22%20fill=%22%2318191C%22/%3E%3Crect%20x=%221%22%20y=%221%22%20width=%2262%22%20height=%2262%22%20rx=%2215%22%20stroke=%22%23FFFFFF%22%20stroke-opacity=%220.12%22%20stroke-width=%222%22/%3E%3Cpath%20d=%22M26%2017H19C14.58%2017%2011%2020.58%2011%2025V39C11%2043.42%2014.58%2047%2019%2047H26%22%20stroke=%22%23E3E3E3%22%20stroke-width=%224.5%22%20stroke-linecap=%22round%22/%3E%3Cpath%20d=%22M38%2017H45C49.42%2017%2053%2020.58%2053%2025V39C53%2043.42%2049.42%2047%2045%2047H38%22%20stroke=%22%23A8C7FA%22%20stroke-width=%224.5%22%20stroke-linecap=%22round%22/%3E%3Cpath%20d=%22M23%2032H41%22%20stroke=%22%2381C995%22%20stroke-width=%224.5%22%20stroke-linecap=%22round%22/%3E%3Ccircle%20cx=%2223%22%20cy=%2232%22%20r=%223.5%22%20fill=%22%23E3E3E3%22/%3E%3Ccircle%20cx=%2241%22%20cy=%2232%22%20r=%223.5%22%20fill=%22%23A8C7FA%22/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root,
  [data-theme="dark"] {
    --bg: #131314;
    --surface: #1e1f20;
    --surface-2: #282a2c;
    --surface-hover: #303235;
    --input-bg: #131314;
    --border: rgba(255, 255, 255, 0.08);
    --border-strong: rgba(255, 255, 255, 0.14);
    --text: #e3e3e3;
    --text-secondary: #c4c7c5;
    --muted: #8e918f;
    --accent: #a8c7fa;
    --accent-solid: #8ab4f8;
    --accent-on-solid: #062e6f;
    --accent-soft: rgba(168, 199, 250, 0.14);
    --accent-border: rgba(168, 199, 250, 0.32);
    --ok: #81c995;
    --ok-soft: rgba(129, 201, 149, 0.14);
    --warn: #fdd663;
    --warn-soft: rgba(253, 214, 99, 0.14);
    --err: #f28b82;
    --err-solid: #ea4335;
    --err-soft: rgba(242, 139, 130, 0.12);
    --err-border: rgba(242, 139, 130, 0.35);
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.35), 0 12px 32px rgba(0, 0, 0, 0.35);
    --modal-backdrop: rgba(0, 0, 0, 0.68);
    --switch-track: #3c4043;
    --switch-thumb: #c4c7c5;
    --switch-checked-thumb: #062e6f;
  }

  [data-theme="oled"] {
    --bg: #000000;
    --surface: #0e0e10;
    --surface-2: #17181b;
    --surface-hover: #212226;
    --input-bg: #000000;
    --border: rgba(255, 255, 255, 0.09);
    --border-strong: rgba(255, 255, 255, 0.16);
    --text: #ececec;
    --text-secondary: #c4c7c5;
    --muted: #8a8d91;
    --accent: #a8c7fa;
    --accent-solid: #8ab4f8;
    --accent-on-solid: #062e6f;
    --accent-soft: rgba(168, 199, 250, 0.14);
    --accent-border: rgba(168, 199, 250, 0.32);
    --ok: #81c995;
    --ok-soft: rgba(129, 201, 149, 0.14);
    --warn: #fdd663;
    --warn-soft: rgba(253, 214, 99, 0.14);
    --err: #f28b82;
    --err-solid: #ea4335;
    --err-soft: rgba(242, 139, 130, 0.12);
    --err-border: rgba(242, 139, 130, 0.35);
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.6), 0 12px 32px rgba(0, 0, 0, 0.55);
    --modal-backdrop: rgba(0, 0, 0, 0.82);
    --switch-track: #2c2e33;
    --switch-thumb: #c4c7c5;
    --switch-checked-thumb: #062e6f;
  }

  [data-theme="light"] {
    --bg: #ffffff;
    --surface: #f0f4f9;
    --surface-2: #e3e9f2;
    --surface-hover: #d8e2f0;
    --input-bg: #ffffff;
    --border: rgba(31, 31, 31, 0.08);
    --border-strong: rgba(31, 31, 31, 0.15);
    --text: #1f1f1f;
    --text-secondary: #444746;
    --muted: #5e5e5e;
    --accent: #0b57d0;
    --accent-solid: #0b57d0;
    --accent-on-solid: #ffffff;
    --accent-soft: #d3e3fd;
    --accent-border: rgba(11, 87, 208, 0.28);
    --ok: #146c2e;
    --ok-soft: #c4eed0;
    --warn: #8c5a00;
    --warn-soft: #ffefc3;
    --err: #b3261e;
    --err-solid: #b3261e;
    --err-soft: #f9dedc;
    --err-border: rgba(179, 38, 30, 0.28);
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.06), 0 12px 28px rgba(11, 87, 208, 0.08);
    --modal-backdrop: rgba(15, 23, 42, 0.42);
    --switch-track: #c4c7c5;
    --switch-thumb: #ffffff;
    --switch-checked-thumb: #ffffff;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    font-family: 'Inter', 'Google Sans', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg);
    color: var(--text);
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
    line-height: 1.5;
    transition: background-color 0.2s ease, color 0.2s ease;
  }

  .app-shell {
    max-width: 1040px;
    margin: 0 auto;
    padding: 20px 20px 64px;
  }

  /* Top Navigation Bar */
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 6px 0 20px;
    flex-wrap: wrap;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
  }

  .brand-mark {
    width: 34px;
    height: 34px;
    border-radius: 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .brand-text {
    display: flex;
    align-items: baseline;
    gap: 10px;
    flex-wrap: wrap;
  }

  .brand-title {
    font-size: 20px;
    font-weight: 500;
    letter-spacing: -0.02em;
    color: var(--text);
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 4px 12px;
    border-radius: 9999px;
    background: var(--surface);
    border: 1px solid var(--border);
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 0 3px var(--ok-soft);
    flex-shrink: 0;
  }

  .status-dot.danger {
    background: var(--err);
    box-shadow: 0 0 0 3px var(--err-soft);
  }

  .topbar-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .uptime-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: 9999px;
    background: var(--surface);
    border: 1px solid var(--border);
    font-size: 12px;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }

  .theme-switch {
    display: inline-flex;
    align-items: center;
    padding: 3px;
    border-radius: 9999px;
    background: var(--surface);
    border: 1px solid var(--border);
    gap: 2px;
  }

  .theme-btn {
    border: none;
    background: transparent;
    color: var(--muted);
    font-family: inherit;
    font-size: 12px;
    font-weight: 500;
    padding: 5px 11px;
    border-radius: 9999px;
    cursor: pointer;
    transition: background-color 0.15s ease, color 0.15s ease;
  }

  .theme-btn:hover {
    color: var(--text);
  }

  .theme-btn.active {
    background: var(--surface-2);
    color: var(--text);
  }

  /* Active Policy Chips Row */
  .policy-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }

  .policy-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 11px;
    border-radius: 9999px;
    font-size: 12px;
    font-weight: 500;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-secondary);
  }

  .policy-chip.accent {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .policy-chip.warn {
    background: var(--warn-soft);
    border-color: transparent;
    color: var(--warn);
  }

  .policy-chip.danger {
    background: var(--err-soft);
    border-color: var(--err-border);
    color: var(--err);
  }

  /* Danger Banner */
  .danger-banner {
    display: none;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 14px 18px;
    border-radius: 20px;
    background: var(--err-soft);
    border: 1px solid var(--err-border);
    color: var(--text);
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  .danger-banner.visible {
    display: flex;
  }

  .danger-banner-body {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    font-size: 13px;
    line-height: 1.45;
  }

  .danger-banner-body svg {
    color: var(--err);
    flex-shrink: 0;
    margin-top: 2px;
  }

  .danger-banner strong {
    color: var(--err);
    font-weight: 600;
  }

  /* Main Layout Grid */
  .grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }

  .span-full {
    grid-column: 1 / -1;
  }

  /* Surface Cards */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 20px 22px;
    transition: border-color 0.2s ease, background-color 0.2s ease;
  }

  .card:hover {
    border-color: var(--border-strong);
  }

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  .card-header.compact-collapsed {
    margin-bottom: 0;
  }

  .card-title-group {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .card-icon {
    width: 32px;
    height: 32px;
    border-radius: 10px;
    background: var(--surface-2);
    color: var(--accent);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .card-title {
    font-size: 15px;
    font-weight: 500;
    color: var(--text);
    letter-spacing: -0.01em;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .card-subtitle {
    font-size: 12px;
    color: var(--muted);
  }

  .count-badge {
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 9999px;
    background: var(--accent-soft);
    color: var(--accent);
    font-variant-numeric: tabular-nums;
  }

  .count-badge.ok {
    background: var(--ok-soft);
    color: var(--ok);
  }

  /* Inputs & Buttons */
  .endpoint-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 6px 6px 14px;
    border-radius: 9999px;
    background: var(--input-bg);
    border: 1px solid var(--border-strong);
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .endpoint-bar:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }

  .endpoint-input {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    outline: none;
  }

  .input-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .text-input {
    flex: 1;
    min-width: 0;
    padding: 10px 14px;
    border-radius: 14px;
    background: var(--input-bg);
    border: 1px solid var(--border-strong);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    outline: none;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .text-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }

  .search-input {
    flex: 1;
    min-width: 180px;
    padding: 8px 14px;
    border-radius: 9999px;
    background: var(--input-bg);
    border: 1px solid var(--border-strong);
    color: var(--text);
    font-family: inherit;
    font-size: 12.5px;
    outline: none;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .search-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    padding: 8px 15px;
    border-radius: 9999px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text);
    font-family: inherit;
    font-size: 12.5px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    transition: background-color 0.15s ease, border-color 0.15s ease, transform 0.1s ease;
  }

  .btn:hover {
    background: var(--surface-hover);
  }

  .btn:active {
    transform: scale(0.98);
  }

  .btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  .btn-primary {
    background: var(--accent-solid);
    border-color: transparent;
    color: var(--accent-on-solid);
    font-weight: 600;
  }

  .btn-primary:hover {
    filter: brightness(1.06);
    background: var(--accent-solid);
  }

  .btn-danger {
    background: var(--err-solid);
    border-color: transparent;
    color: #ffffff;
    font-weight: 600;
  }

  .btn-danger:hover {
    filter: brightness(1.08);
    background: var(--err-solid);
  }

  .btn-ghost {
    background: transparent;
    border-color: var(--border);
    color: var(--text-secondary);
  }

  .btn-sm {
    padding: 6px 12px;
    font-size: 12px;
  }

  .icon-close {
    width: 32px;
    height: 32px;
    border-radius: 9999px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
    line-height: 1;
    transition: background-color 0.15s ease, color 0.15s ease;
  }

  .icon-close:hover {
    background: var(--surface-2);
    color: var(--text);
  }

  /* Tunnel & Connectors (inside Endpoint Modal) */
  .tunnel-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-top: 14px;
    flex-wrap: wrap;
  }

  .tunnel-left {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .field-label {
    font-size: 12px;
    color: var(--muted);
    font-weight: 500;
  }

  .segmented {
    display: inline-flex;
    padding: 3px;
    border-radius: 9999px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    gap: 2px;
  }

  .seg-btn {
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-family: inherit;
    font-size: 12px;
    font-weight: 500;
    padding: 5px 12px;
    border-radius: 9999px;
    cursor: pointer;
    transition: background-color 0.15s ease, color 0.15s ease;
  }

  .seg-btn:hover {
    color: var(--text);
  }

  .seg-btn.active {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .error-inline {
    font-size: 12px;
    color: var(--err);
  }

  .connectors-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-top: 18px;
  }

  .connector-card {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 12px;
    border-radius: 16px;
    background: var(--surface-2);
    border: 1px solid transparent;
    color: var(--text);
    text-decoration: none;
    transition: background-color 0.15s ease, border-color 0.15s ease, transform 0.15s ease;
  }

  .connector-card:hover {
    background: var(--surface-hover);
    border-color: var(--border-strong);
    transform: translateY(-1px);
  }

  .connector-card.featured {
    border-color: var(--accent-border);
    background: linear-gradient(135deg, var(--surface-2), var(--accent-soft));
  }

  .connector-card svg {
    width: 22px;
    height: 22px;
    flex-shrink: 0;
  }

  .connector-meta {
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .connector-name {
    font-size: 12.5px;
    font-weight: 500;
    color: var(--text);
  }

  .connector-hint {
    font-size: 11px;
    color: var(--muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Telemetry Strip */
  .telemetry-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
  }

  .metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 15px 18px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    transition: border-color 0.15s ease, background-color 0.15s ease;
  }

  .metric-card.clickable {
    cursor: pointer;
    text-align: left;
    font-family: inherit;
  }

  .metric-card.clickable:hover {
    border-color: var(--accent-border);
    background: var(--surface-2);
  }

  .metric-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 12px;
    color: var(--muted);
    font-weight: 500;
  }

  .metric-val {
    font-size: 25px;
    font-weight: 500;
    letter-spacing: -0.02em;
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }

  .metric-val.err {
    color: var(--err);
  }

  .metric-val.ok {
    color: var(--ok);
  }

  /* Tools Drawer */
  .tools-drawer {
    display: none;
    margin-top: 12px;
    padding: 16px 18px;
    border-radius: 20px;
    background: var(--surface);
    border: 1px solid var(--border);
  }

  .tools-drawer.open {
    display: block;
  }

  .tools-drawer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
  }

  .tools-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .tool-chip {
    padding: 5px 11px;
    border-radius: 9999px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: var(--text-secondary);
  }

  /* Recent Projects List */
  .section-sublabel {
    font-size: 12px;
    font-weight: 500;
    color: var(--muted);
    margin: 14px 0 8px;
  }

  .recent-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .recent-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    width: 100%;
    text-align: left;
    padding: 9px 13px;
    border-radius: 14px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    cursor: pointer;
    transition: background-color 0.15s ease, border-color 0.15s ease, color 0.15s ease;
  }

  .recent-item:hover {
    background: var(--surface-2);
    color: var(--text);
  }

  .recent-item.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--text);
  }

  .recent-path {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .recent-badge {
    flex-shrink: 0;
    font-family: 'Inter', sans-serif;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 9px;
    border-radius: 9999px;
    background: var(--accent-solid);
    color: var(--accent-on-solid);
  }

  .form-msg {
    min-height: 16px;
    margin-top: 6px;
    font-size: 12px;
    color: var(--err);
  }

  /* Security Toggles */
  .toggle-list {
    display: flex;
    flex-direction: column;
  }

  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 13px 0;
    border-bottom: 1px solid var(--border);
  }

  .toggle-row:first-child {
    padding-top: 2px;
  }

  .toggle-row:last-child {
    border-bottom: none;
    padding-bottom: 2px;
  }

  .toggle-title {
    font-size: 13.5px;
    font-weight: 500;
    color: var(--text);
  }

  .toggle-title.danger {
    color: var(--err);
  }

  .toggle-desc {
    font-size: 12px;
    color: var(--muted);
    margin-top: 2px;
  }

  .m3-switch {
    position: relative;
    width: 48px;
    height: 28px;
    flex-shrink: 0;
  }

  .m3-switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .m3-slider {
    position: absolute;
    inset: 0;
    border-radius: 9999px;
    background: var(--switch-track);
    cursor: pointer;
    transition: background-color 0.2s ease;
  }

  .m3-slider::before {
    content: '';
    position: absolute;
    width: 20px;
    height: 20px;
    left: 4px;
    top: 4px;
    border-radius: 50%;
    background: var(--switch-thumb);
    transition: transform 0.2s cubic-bezier(0.2, 0.8, 0.2, 1), background-color 0.2s ease;
  }

  .m3-switch input:checked + .m3-slider {
    background: var(--accent-solid);
  }

  .m3-switch input:checked + .m3-slider::before {
    transform: translateX(20px);
    background: var(--switch-checked-thumb);
  }

  .m3-switch.danger input:checked + .m3-slider {
    background: var(--err-solid);
  }

  .m3-switch.danger input:checked + .m3-slider::before {
    background: #ffffff;
  }

  /* Filter Toolbar for Call History */
  .filter-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
    flex-wrap: wrap;
  }

  /* Clean Table */
  .table-wrap {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }

  th, td {
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }

  th {
    font-size: 11.5px;
    font-weight: 500;
    color: var(--muted);
  }

  tr:last-child td {
    border-bottom: none;
  }

  code.mono {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--text);
    background: var(--input-bg);
    padding: 3px 8px;
    border-radius: 8px;
    border: 1px solid var(--border);
  }

  .state-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 9999px;
    font-size: 11.5px;
    font-weight: 500;
  }

  .state-pill.ok {
    background: var(--ok-soft);
    color: var(--ok);
  }

  .state-pill.err {
    background: var(--err-soft);
    color: var(--err);
  }

  .state-pill.muted {
    background: var(--surface-2);
    color: var(--muted);
  }

  .empty-state {
    padding: 24px 12px;
    text-align: center;
    font-size: 13px;
    color: var(--muted);
  }

  /* Modals */
  .modal-overlay {
    position: fixed;
    inset: 0;
    background: var(--modal-backdrop);
    display: none;
    align-items: center;
    justify-content: center;
    padding: 20px;
    z-index: 100;
    backdrop-filter: blur(4px);
  }

  .modal-overlay.open {
    display: flex;
  }

  .modal-card {
    width: 100%;
    max-width: 440px;
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: 28px;
    padding: 24px;
    box-shadow: var(--shadow);
  }

  .modal-card.wide {
    max-width: 680px;
  }

  .modal-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
  }

  .modal-title {
    font-size: 18px;
    font-weight: 500;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .modal-sub {
    font-size: 12.5px;
    color: var(--muted);
    margin-top: 3px;
  }

  .modal-body {
    font-size: 13.5px;
    color: var(--text-secondary);
    line-height: 1.55;
    margin-bottom: 22px;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
  }

  /* Toast */
  .toast {
    position: fixed;
    left: 50%;
    bottom: 24px;
    transform: translateX(-50%) translateY(16px);
    background: var(--surface-2);
    color: var(--text);
    border: 1px solid var(--border-strong);
    padding: 10px 18px;
    border-radius: 9999px;
    font-size: 13px;
    font-weight: 500;
    box-shadow: var(--shadow);
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s ease, transform 0.2s ease;
    z-index: 120;
  }

  .toast.show {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }

  /* Responsive */
  @media (max-width: 820px) {
    .grid {
      grid-template-columns: 1fr;
    }
    .connectors-grid {
      grid-template-columns: 1fr;
    }
    .telemetry-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  @media (max-width: 520px) {
    .app-shell {
      padding: 14px 14px 48px;
    }
    .card {
      padding: 16px;
      border-radius: 20px;
    }
    .endpoint-bar {
      border-radius: 16px;
      flex-direction: column;
      align-items: stretch;
      padding: 10px;
    }
    .input-row {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
</head>
<body>
<div class="app-shell">

  <!-- Top Bar -->
  <header class="topbar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 64 64" fill="none">
          <path d="M26 17H19C14.58 17 11 20.58 11 25V39C11 43.42 14.58 47 19 47H26" stroke="currentColor" stroke-width="5" stroke-linecap="round"/>
          <path d="M38 17H45C49.42 17 53 20.58 53 25V39C53 43.42 49.42 47 45 47H38" stroke="var(--accent)" stroke-width="5" stroke-linecap="round"/>
          <path d="M23 32H41" stroke="var(--ok)" stroke-width="5" stroke-linecap="round"/>
          <circle cx="23" cy="32" r="3.8" fill="currentColor"/>
          <circle cx="41" cy="32" r="3.8" fill="var(--accent)"/>
        </svg>
      </div>
      <div class="brand-text">
        <h1 class="brand-title">Easy MCP</h1>
        <div class="status-pill" id="statusPill">
          <span class="status-dot" id="statusDot"></span>
          <span id="statusText">Online</span>
        </div>
      </div>
    </div>

    <div class="topbar-actions">
      <button type="button" class="btn btn-primary" id="btnOpenEndpoint">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
        </svg>
        MCP Endpoint
      </button>
      <div class="uptime-pill" id="stUptime">Uptime 0m 0s</div>
      <div class="theme-switch" role="group" aria-label="Theme">
        <button type="button" class="theme-btn active" data-set-theme="dark">Dark</button>
        <button type="button" class="theme-btn" data-set-theme="oled">OLED</button>
        <button type="button" class="theme-btn" data-set-theme="light">Light</button>
      </div>
    </div>
  </header>

  <!-- Active Context / Policy Chips -->
  <div class="policy-strip" id="policyStrip"></div>

  <!-- Jail Disabled Warning -->
  <div class="danger-banner" id="jailWarn" role="alert">
    <div class="danger-banner-body">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      <div>
        <strong>Folder jail is disabled.</strong> Connected AI clients can read, write, and execute commands anywhere on this machine, not just inside the active project folder.
      </div>
    </div>
    <button type="button" class="btn btn-sm btn-danger" id="btnRestoreJail">Re-enable Jail</button>
  </div>

  <!-- Main Grid -->
  <div class="grid">

    <!-- Telemetry Strip -->
    <div class="span-full">
      <div class="telemetry-grid">
        <div class="metric-card">
          <div class="metric-top"><span>Total calls</span></div>
          <div class="metric-val" id="stCalls">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-top"><span>Errors</span></div>
          <div class="metric-val" id="stErrors">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-top"><span>Active sessions</span></div>
          <div class="metric-val ok" id="stSessions">0</div>
        </div>
        <button type="button" class="metric-card clickable" id="btnToggleTools" aria-expanded="false">
          <div class="metric-top">
            <span>Registered tools</span>
            <span id="toolsArrow">Inspect ›</span>
          </div>
          <div class="metric-val" id="stTools">0</div>
        </button>
      </div>

      <div class="tools-drawer" id="toolsDrawer">
        <div class="tools-drawer-head">
          <span class="field-label">Exposed MCP Tools</span>
          <button type="button" class="btn btn-sm btn-ghost" id="btnCloseTools">Close</button>
        </div>
        <div class="tools-chips" id="toolsList"></div>
      </div>
    </div>

    <!-- Active Workspace -->
    <section class="card">
      <div class="card-header">
        <div class="card-title-group">
          <div class="card-icon" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
            </svg>
          </div>
          <div>
            <h2 class="card-title">Active Workspace</h2>
            <p class="card-subtitle">Root folder scoped for MCP operations</p>
          </div>
        </div>
      </div>

      <div class="input-row">
        <input type="text" class="text-input" id="projectPath" placeholder="/home/user/project" aria-label="Project folder path">
        <button type="button" class="btn" id="btnSetProject">Set</button>
        <button type="button" class="btn btn-ghost" id="btnPickFolder">Browse</button>
      </div>

      <div class="section-sublabel">Recent workspaces</div>
      <div class="recent-list" id="recentList"></div>
      <div class="form-msg" id="msg" aria-live="polite"></div>
    </section>

    <!-- Security & Policies -->
    <section class="card">
      <div class="card-header">
        <div class="card-title-group">
          <div class="card-icon" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <div>
            <h2 class="card-title">Security &amp; Policies</h2>
            <p class="card-subtitle">Live guardrails enforced by the server</p>
          </div>
        </div>
      </div>

      <div class="toggle-list">
        <div class="toggle-row">
          <div>
            <div class="toggle-title">Read-only mode</div>
            <div class="toggle-desc">Blocks file writes, edits, and deletions</div>
          </div>
          <label class="m3-switch" aria-label="Read-only mode">
            <input type="checkbox" id="togReadOnly">
            <span class="m3-slider"></span>
          </label>
        </div>

        <div class="toggle-row">
          <div>
            <div class="toggle-title">Disable shell execution</div>
            <div class="toggle-desc">Blocks terminal commands and background jobs</div>
          </div>
          <label class="m3-switch" aria-label="Disable shell execution">
            <input type="checkbox" id="togDisableShell">
            <span class="m3-slider"></span>
          </label>
        </div>

        <div class="toggle-row">
          <div>
            <div class="toggle-title danger">Disable folder jail</div>
            <div class="toggle-desc">Allows access to the entire filesystem outside the workspace</div>
          </div>
          <label class="m3-switch danger" aria-label="Disable folder jail">
            <input type="checkbox" id="togSkipJail">
            <span class="m3-slider"></span>
          </label>
        </div>
      </div>
    </section>

    <!-- Background Jobs (Always visible, separate card) -->
    <section class="card span-full">
      <div class="card-header">
        <div class="card-title-group">
          <div class="card-icon" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="4" width="20" height="16" rx="3"/>
              <path d="M7 15l3-3-3-3"/>
              <line x1="13" y1="15" x2="17" y2="15"/>
            </svg>
          </div>
          <div>
            <h2 class="card-title">
              Background Jobs
              <span class="count-badge ok" id="badgeJobs">0 running</span>
            </h2>
            <p class="card-subtitle">Always-visible processes started via MCP</p>
          </div>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Command</th>
              <th>Status</th>
              <th>Started</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="jobsBody"></tbody>
        </table>
      </div>
    </section>

    <!-- Call History (Separate, collapsible + filterable) -->
    <section class="card span-full">
      <div class="card-header" id="callsHeader">
        <div class="card-title-group">
          <div class="card-icon" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
          </div>
          <div>
            <h2 class="card-title">
              Call History
              <span class="count-badge" id="badgeCalls">0</span>
            </h2>
            <p class="card-subtitle">Recent MCP tool invocations with live filtering</p>
          </div>
        </div>

        <button type="button" class="btn btn-sm btn-ghost" id="btnToggleCalls" aria-expanded="true">
          <span id="toggleCallsLabel">Hide</span>
        </button>
      </div>

      <div id="callsSectionBody">
        <div class="filter-bar">
          <input type="text" class="search-input" id="callsSearch" placeholder="Filter by tool name (e.g. read_file, git)..." aria-label="Filter calls by tool name">
          <div class="segmented" role="group" aria-label="Filter calls by status">
            <button type="button" class="seg-btn active" data-call-status="all">All</button>
            <button type="button" class="seg-btn" data-call-status="ok">OK</button>
            <button type="button" class="seg-btn" data-call-status="error">Errors</button>
          </div>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody id="callsBody"></tbody>
          </table>
        </div>
      </div>
    </section>

  </div>
</div>

<!-- MCP Endpoint Popup Modal -->
<div class="modal-overlay" id="endpointModal" role="dialog" aria-modal="true" aria-labelledby="endpointModalTitle">
  <div class="modal-card wide">
    <div class="modal-head">
      <div>
        <h3 class="modal-title" id="endpointModalTitle">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2">
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
          </svg>
          MCP Endpoint
        </h3>
        <p class="modal-sub">Paste this URL into your AI client to connect this workspace</p>
      </div>
      <button type="button" class="icon-close" id="btnCloseEndpoint" aria-label="Close endpoint popup">&times;</button>
    </div>

    <div class="endpoint-bar">
      <input type="text" class="endpoint-input" id="mcpUrl" readonly aria-label="MCP Endpoint URL">
      <button type="button" class="btn btn-primary" id="btnCopyUrl">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <rect x="9" y="9" width="13" height="13" rx="2"/>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
        <span id="copyBtnLabel">Copy link</span>
      </button>
    </div>

    <div class="tunnel-row">
      <div class="tunnel-left">
        <span class="field-label">Tunnel</span>
        <div class="segmented" role="group" aria-label="Tunnel provider">
          <button type="button" class="seg-btn" id="tunCloudflare" data-tunnel="cloudflare">Cloudflare</button>
          <button type="button" class="seg-btn" id="tunFunnel" data-tunnel="funnel">Tailscale · Persistent</button>
        </div>
        <span class="error-inline" id="tunError"></span>
      </div>
      <span class="field-label" id="localDashUrl">Local: http://127.0.0.1:8787/</span>
    </div>

    <div class="connectors-grid">
      <a class="connector-card featured" href="https://gemini.google.com/customize/connectors" target="_blank" rel="noopener noreferrer">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect width="24" height="24" rx="7" fill="#131314"/>
          <path d="M12 4C12 8.42 8.42 12 4 12C8.42 12 12 15.58 12 20C12 15.58 15.58 12 20 12C15.58 12 12 8.42 12 4Z" fill="url(#geminiIconGrad)"/>
          <defs>
            <linearGradient id="geminiIconGrad" x1="4" y1="4" x2="20" y2="20" gradientUnits="userSpaceOnUse">
              <stop stop-color="#4285F4"/>
              <stop offset="0.5" stop-color="#9B72CB"/>
              <stop offset="1" stop-color="#D96570"/>
            </linearGradient>
          </defs>
        </svg>
        <div class="connector-meta">
          <span class="connector-name">Gemini</span>
          <span class="connector-hint">Add connector</span>
        </div>
      </a>

      <a class="connector-card" href="https://claude.ai/plugins" target="_blank" rel="noopener noreferrer">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect width="24" height="24" rx="7" fill="#D97757"/>
          <path d="M12 5l1.6 4.8h5l-4 3 1.5 4.8-4.1-3-4.1 3 1.5-4.8-4-3h5z" fill="#FFF"/>
        </svg>
        <div class="connector-meta">
          <span class="connector-name">Claude</span>
          <span class="connector-hint">Add custom connector</span>
        </div>
      </a>

      <a class="connector-card" href="https://chatgpt.com/plugins" target="_blank" rel="noopener noreferrer">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect width="24" height="24" rx="7" fill="#10A37F"/>
          <circle cx="12" cy="12" r="5.5" stroke="#FFF" stroke-width="2"/>
          <circle cx="12" cy="12" r="2" fill="#FFF"/>
        </svg>
        <div class="connector-meta">
          <span class="connector-name">ChatGPT</span>
          <span class="connector-hint">Add custom MCP</span>
        </div>
      </a>
    </div>
  </div>
</div>

<!-- Confirmation Modal for Disabling Folder Jail -->
<div class="modal-overlay" id="jailModal" role="dialog" aria-modal="true" aria-labelledby="jailModalTitle">
  <div class="modal-card">
    <div class="modal-head" style="margin-bottom:10px;">
      <h3 class="modal-title" id="jailModalTitle">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--err)" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        Disable folder jail?
      </h3>
    </div>
    <p class="modal-body">
      Connected AI clients will be able to read, modify, and run commands anywhere on your machine — not just inside the active workspace. Only enable this if you explicitly need system-wide access.
    </p>
    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" id="btnCancelJail">Cancel</button>
      <button type="button" class="btn btn-danger" id="btnConfirmJail">Disable jail</button>
    </div>
  </div>
</div>

<!-- Toast Feedback -->
<div class="toast" id="toast" role="status" aria-live="polite"></div>

<script>
(function() {
  const ADMIN = '__EASY_MCP_ADMIN__';
  const ui = {
    connected: true,
    toolsOpen: false,
    callsCollapsed: false,
    callSearch: '',
    callStatusFilter: 'all',
    lastData: null
  };

  let toastTimer = null;

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function fmtUptime(s) {
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    return h + 'h ' + m + 'm';
  }

  function fmtTime(iso) {
    try {
      var d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) {
      return '--:--:--';
    }
  }

  function showToast(message) {
    var el = document.getElementById('toast');
    el.textContent = message;
    el.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function() {
      el.classList.remove('show');
    }, 2200);
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('easy_mcp_theme', theme); } catch (e) {}
    document.querySelectorAll('[data-set-theme]').forEach(function(btn) {
      btn.classList.toggle('active', btn.getAttribute('data-set-theme') === theme);
    });
  }

  function apiPost(url, payload) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Easy-Mcp-Admin': ADMIN },
      body: JSON.stringify(payload || {})
    }).then(function(res) { return res.json(); });
  }

  function render() {
    var d = ui.lastData;
    var statusDot = document.getElementById('statusDot');
    var statusText = document.getElementById('statusText');

    if (!ui.connected) {
      statusDot.classList.add('danger');
      statusText.textContent = 'Disconnected';
      return;
    }
    if (!d) return;

    statusDot.classList.toggle('danger', Boolean(d.skipJail));
    statusText.textContent = d.skipJail ? 'Online · Jail bypassed' : 'Online';

    document.getElementById('stUptime').textContent = 'Uptime ' + fmtUptime(d.uptimeSec || 0);
    document.getElementById('localDashUrl').textContent = 'Local: ' + (d.dashboardUrl || window.location.origin + '/');

    // Policy strip chips
    var chips = [];
    var proj = d.project || '';
    var shortProj = proj.split(/[\\/]/).filter(Boolean).pop() || proj;
    chips.push('<span class="policy-chip accent">Workspace: ' + esc(shortProj) + '</span>');
    chips.push('<span class="policy-chip">Tunnel: ' + (d.tunnelMode === 'funnel' ? 'Tailscale Funnel' : 'Cloudflare') + '</span>');
    if (d.readOnly) chips.push('<span class="policy-chip warn">Read-only</span>');
    if (d.disableShell) chips.push('<span class="policy-chip warn">Shell disabled</span>');
    if (d.skipJail) chips.push('<span class="policy-chip danger">Folder jail off</span>');
    document.getElementById('policyStrip').innerHTML = chips.join('');

    // Danger banner
    document.getElementById('jailWarn').classList.toggle('visible', Boolean(d.skipJail));

    // Endpoint modal fields
    document.getElementById('mcpUrl').value = d.mcpUrl || '(starting tunnel...)';
    document.getElementById('tunCloudflare').classList.toggle('active', d.tunnelMode === 'cloudflare');
    document.getElementById('tunFunnel').classList.toggle('active', d.tunnelMode === 'funnel');
    document.getElementById('tunError').textContent = d.tunnelError || '';

    // Project input
    var pp = document.getElementById('projectPath');
    if (document.activeElement !== pp) {
      pp.value = proj;
    }

    // Recent workspaces
    var recents = Array.isArray(d.recentProjects) ? d.recentProjects : [];
    document.getElementById('recentList').innerHTML = recents.slice(0, 5).map(function(p) {
      var active = p === proj;
      return '<button type="button" class="recent-item' + (active ? ' active' : '') + '" data-project="' + esc(p) + '">' +
        '<span class="recent-path">' + esc(p) + '</span>' +
        (active ? '<span class="recent-badge">Active</span>' : '') +
        '</button>';
    }).join('');

    // Security switches
    document.getElementById('togReadOnly').checked = Boolean(d.readOnly);
    document.getElementById('togDisableShell').checked = Boolean(d.disableShell);
    document.getElementById('togSkipJail').checked = Boolean(d.skipJail);

    // Telemetry
    var totalCalls = d.totalCalls || 0;
    var totalErrors = d.totalErrors || 0;
    var toolNames = Array.isArray(d.toolNames) ? d.toolNames : [];
    document.getElementById('stCalls').textContent = totalCalls;
    var errEl = document.getElementById('stErrors');
    errEl.textContent = totalErrors;
    errEl.classList.toggle('err', totalErrors > 0);
    document.getElementById('stSessions').textContent = d.sseSessions || 0;
    document.getElementById('stTools').textContent = typeof d.toolsCount === 'number' ? d.toolsCount : toolNames.length;

    // Tools drawer
    var drawer = document.getElementById('toolsDrawer');
    drawer.classList.toggle('open', ui.toolsOpen);
    document.getElementById('btnToggleTools').setAttribute('aria-expanded', ui.toolsOpen ? 'true' : 'false');
    document.getElementById('toolsArrow').textContent = ui.toolsOpen ? 'Hide' : 'Inspect ›';
    document.getElementById('toolsList').innerHTML = toolNames.map(function(name) {
      return '<span class="tool-chip">' + esc(name) + '</span>';
    }).join('');

    // Background Jobs (always visible)
    var jobs = Array.isArray(d.jobs) ? d.jobs : [];
    var runningJobsCount = jobs.filter(function(j) { return j.status === 'running'; }).length;
    document.getElementById('badgeJobs').textContent = runningJobsCount + ' running';
    var jobsBody = document.getElementById('jobsBody');
    if (!jobs.length) {
      jobsBody.innerHTML = '<tr><td colspan="5" class="empty-state">No background jobs active.</td></tr>';
    } else {
      jobsBody.innerHTML = jobs.map(function(j) {
        var isRunning = j.status === 'running';
        return '<tr>' +
          '<td><code class="mono">' + esc(j.id) + '</code></td>' +
          '<td><code class="mono">' + esc(j.command) + '</code></td>' +
          '<td><span class="state-pill ' + (isRunning ? 'ok' : 'muted') + '">' + esc(j.status) + '</span></td>' +
          '<td style="color:var(--muted);">' + esc(fmtTime(j.startedAt)) + '</td>' +
          '<td>' + (isRunning ? '<button type="button" class="btn btn-sm btn-ghost" data-stop-job="' + esc(j.id) + '">Stop</button>' : '<span style="color:var(--muted);">—</span>') + '</td>' +
          '</tr>';
      }).join('');
    }

    // Call History (collapsible + filterable)
    var calls = Array.isArray(d.recentCalls) ? d.recentCalls : [];
    var callsBodyWrap = document.getElementById('callsSectionBody');
    var callsHeader = document.getElementById('callsHeader');
    callsBodyWrap.style.display = ui.callsCollapsed ? 'none' : 'block';
    callsHeader.classList.toggle('compact-collapsed', ui.callsCollapsed);
    document.getElementById('btnToggleCalls').setAttribute('aria-expanded', ui.callsCollapsed ? 'false' : 'true');
    document.getElementById('toggleCallsLabel').textContent = ui.callsCollapsed ? 'Show' : 'Hide';

    document.querySelectorAll('[data-call-status]').forEach(function(btn) {
      btn.classList.toggle('active', btn.getAttribute('data-call-status') === ui.callStatusFilter);
    });

    var query = ui.callSearch.trim().toLowerCase();
    var filteredCalls = calls.filter(function(c) {
      if (ui.callStatusFilter === 'ok' && !c.ok) return false;
      if (ui.callStatusFilter === 'error' && c.ok) return false;
      if (query && String(c.tool || '').toLowerCase().indexOf(query) === -1) return false;
      return true;
    });

    var hasActiveFilter = Boolean(query) || ui.callStatusFilter !== 'all';
    document.getElementById('badgeCalls').textContent = hasActiveFilter
      ? filteredCalls.length + ' / ' + calls.length
      : String(calls.length);

    var callsBody = document.getElementById('callsBody');
    if (!filteredCalls.length) {
      callsBody.innerHTML = '<tr><td colspan="4" class="empty-state">' +
        (hasActiveFilter ? 'No calls match the current filter.' : 'No tool calls recorded yet.') +
        '</td></tr>';
    } else {
      callsBody.innerHTML = filteredCalls.slice(0, 30).map(function(c) {
        return '<tr>' +
          '<td><code class="mono">' + esc(c.tool) + '</code></td>' +
          '<td><span class="state-pill ' + (c.ok ? 'ok' : 'err') + '">' + (c.ok ? 'OK' : 'Error') + '</span></td>' +
          '<td>' + esc(c.ms) + ' ms</td>' +
          '<td style="color:var(--muted);">' + esc(fmtTime(c.ts)) + '</td>' +
          '</tr>';
      }).join('');
    }
  }

  async function tick() {
    try {
      var res = await fetch('/api/dashboard', { headers: { 'X-Easy-Mcp-Admin': ADMIN } });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      ui.lastData = await res.json();
      ui.connected = true;
      render();
    } catch (e) {
      ui.connected = false;
      render();
    }
  }

  async function setProject(pathOverride) {
    var p = String(pathOverride !== undefined ? pathOverride : document.getElementById('projectPath').value).trim();
    var msgEl = document.getElementById('msg');
    if (!p) {
      msgEl.textContent = 'Please enter a valid folder path.';
      return;
    }
    try {
      var d = await apiPost('/api/set-project', { path: p });
      msgEl.textContent = d.success ? '' : (d.error || 'Failed to update folder');
      if (d.success) {
        showToast('Workspace updated');
      }
      tick();
    } catch (e) {
      msgEl.textContent = 'Failed to update folder';
    }
  }

  async function saveSetting(key, value, label) {
    try {
      var body = {};
      body[key] = value;
      await apiPost('/api/settings', body);
      if (label) showToast(label);
      tick();
    } catch (e) {
      showToast('Failed to update setting');
      tick();
    }
  }

  // Endpoint Modal Controls
  var endpointModal = document.getElementById('endpointModal');
  document.getElementById('btnOpenEndpoint').addEventListener('click', function() {
    endpointModal.classList.add('open');
  });
  document.getElementById('btnCloseEndpoint').addEventListener('click', function() {
    endpointModal.classList.remove('open');
  });
  endpointModal.addEventListener('click', function(e) {
    if (e.target === endpointModal) endpointModal.classList.remove('open');
  });

  // Theme Controls
  document.querySelectorAll('[data-set-theme]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      setTheme(btn.getAttribute('data-set-theme'));
    });
  });

  // Copy MCP URL
  document.getElementById('btnCopyUrl').addEventListener('click', function() {
    var input = document.getElementById('mcpUrl');
    var label = document.getElementById('copyBtnLabel');
    var val = input.value;
    var done = function() {
      label.textContent = 'Copied';
      showToast('MCP endpoint copied to clipboard');
      setTimeout(function() { label.textContent = 'Copy link'; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(val).then(done).catch(function() {
        input.select();
        document.execCommand('copy');
        done();
      });
    } else {
      input.select();
      document.execCommand('copy');
      done();
    }
  });

  // Tunnel Mode Switch
  document.querySelectorAll('[data-tunnel]').forEach(function(btn) {
    btn.addEventListener('click', async function() {
      var mode = btn.getAttribute('data-tunnel');
      document.getElementById('mcpUrl').value = '(switching tunnel...)';
      try {
        await apiPost('/api/set-tunnel', { mode: mode });
        showToast(mode === 'funnel' ? 'Switched to Tailscale Funnel' : 'Switched to Cloudflare Tunnel');
      } catch (e) {
        showToast('Failed to switch tunnel');
      }
      tick();
    });
  });

  // Workspace Controls
  document.getElementById('btnSetProject').addEventListener('click', function() {
    setProject();
  });

  document.getElementById('projectPath').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') setProject();
  });

  document.getElementById('btnPickFolder').addEventListener('click', async function() {
    var btn = this;
    var orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Browsing...';
    document.getElementById('msg').textContent = '';
    try {
      var d = await apiPost('/api/pick-folder', {});
      if (d.success) {
        showToast('Workspace updated');
      } else if (d.error && d.error !== 'No folder selected') {
        document.getElementById('msg').textContent = d.error;
      }
    } catch (e) {
      document.getElementById('msg').textContent = 'Folder picker failed';
    }
    btn.disabled = false;
    btn.textContent = orig;
    tick();
  });

  document.getElementById('recentList').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-project]');
    if (btn) setProject(btn.getAttribute('data-project'));
  });

  // Security Controls
  document.getElementById('togReadOnly').addEventListener('change', function(e) {
    saveSetting('readOnly', e.target.checked, e.target.checked ? 'Read-only mode enabled' : 'Read-only mode disabled');
  });

  document.getElementById('togDisableShell').addEventListener('change', function(e) {
    saveSetting('disableShell', e.target.checked, e.target.checked ? 'Shell execution disabled' : 'Shell execution enabled');
  });

  var jailModal = document.getElementById('jailModal');
  document.getElementById('togSkipJail').addEventListener('change', function(e) {
    if (e.target.checked) {
      e.target.checked = false;
      jailModal.classList.add('open');
    } else {
      saveSetting('skipJail', false, 'Folder jail re-enabled');
    }
  });

  document.getElementById('btnCancelJail').addEventListener('click', function() {
    jailModal.classList.remove('open');
  });

  document.getElementById('btnConfirmJail').addEventListener('click', function() {
    jailModal.classList.remove('open');
    saveSetting('skipJail', true, 'Folder jail disabled');
  });

  jailModal.addEventListener('click', function(e) {
    if (e.target === jailModal) jailModal.classList.remove('open');
  });

  document.getElementById('btnRestoreJail').addEventListener('click', function() {
    saveSetting('skipJail', false, 'Folder jail re-enabled');
  });

  // Tools Drawer
  document.getElementById('btnToggleTools').addEventListener('click', function() {
    ui.toolsOpen = !ui.toolsOpen;
    render();
  });

  document.getElementById('btnCloseTools').addEventListener('click', function() {
    ui.toolsOpen = false;
    render();
  });

  // Background Jobs Stop
  document.getElementById('jobsBody').addEventListener('click', async function(e) {
    var btn = e.target.closest('[data-stop-job]');
    if (!btn) return;
    var id = btn.getAttribute('data-stop-job');
    try {
      await apiPost('/api/stop-job', { id: id });
      showToast('Stopped background job ' + id);
    } catch (e) {
      showToast('Failed to stop job');
    }
    tick();
  });

  // Call History Collapse & Filtering
  document.getElementById('btnToggleCalls').addEventListener('click', function() {
    ui.callsCollapsed = !ui.callsCollapsed;
    try { localStorage.setItem('easy_mcp_calls_collapsed', ui.callsCollapsed ? '1' : '0'); } catch (e) {}
    render();
  });

  document.getElementById('callsSearch').addEventListener('input', function(e) {
    ui.callSearch = e.target.value;
    render();
  });

  document.querySelectorAll('[data-call-status]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      ui.callStatusFilter = btn.getAttribute('data-call-status');
      render();
    });
  });

  // Close modals on Escape
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      endpointModal.classList.remove('open');
      jailModal.classList.remove('open');
    }
  });

  // Restore saved preferences
  try {
    var savedTheme = localStorage.getItem('easy_mcp_theme');
    if (savedTheme === 'dark' || savedTheme === 'oled' || savedTheme === 'light') {
      setTheme(savedTheme);
    }
    if (localStorage.getItem('easy_mcp_calls_collapsed') === '1') {
      ui.callsCollapsed = true;
    }
  } catch (e) {}

  tick();
  setInterval(tick, 2000);
})();
</script>
</body>
</html>`;

// OAuth client/token stores (persisted with hashed secrets — the master
// TOKEN is never handed out by /oauth/register or /oauth/token anymore).
const oauthClientsFile = path.join(easyMcpHome, 'oauth-clients.json');
const oauthTokensFile = path.join(easyMcpHome, 'oauth-tokens.json');
function loadOAuthStore(file) { try { return new Map(Object.entries(JSON.parse(fs.readFileSync(file, 'utf8')))); } catch { return new Map(); } }
const oauthClients = loadOAuthStore(oauthClientsFile); // client_id -> { secretHash, redirect_uris, authMethod, createdAt }
const oauthTokens = loadOAuthStore(oauthTokensFile);   // sha256(token) -> { type, clientId, exp, createdAt }
function saveOAuth() {
  try {
    fs.mkdirSync(easyMcpHome, { recursive: true, mode: 0o700 });
    for (const [file, map] of [[oauthClientsFile, oauthClients], [oauthTokensFile, oauthTokens]]) {
      const tmp = file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(map)), { mode: 0o600 });
      fs.renameSync(tmp, file);
    }
  } catch {}
}
function pruneOAuthClients() {
  if (oauthClients.size <= 100) return;
  const sorted = [...oauthClients.entries()].sort((a, b) => (a[1].createdAt || 0) - (b[1].createdAt || 0));
  for (const [id] of sorted.slice(0, oauthClients.size - 100)) oauthClients.delete(id);
}
const registerHits = [];
function registerRateOk() {
  const now = Date.now();
  while (registerHits.length && registerHits[0] < now - 60000) registerHits.shift();
  if (registerHits.length >= 20) return false;
  registerHits.push(now);
  return true;
}
function validRedirectUri(u) {
  try {
    const x = new URL(String(u));
    if (x.protocol === 'https:') return true;
    return x.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(x.hostname);
  } catch { return false; }
}
const oauthCodes = new Map(); // code -> { exp, challenge, method, clientId, redirectUri }
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  // Token-in-path form: /mcp/<token> (one-paste link, no '?' for strict URL fields)
  const pathTokenMatch = url.pathname.match(/^\/mcp\/([^/]+)$/);
  if (pathTokenMatch) {
    req._pathToken = decodeURIComponent(pathTokenMatch[1]);
    url.pathname = '/mcp';
  }

  // Browser-to-localhost hardening: block Private Network Access preflights,
  // DNS-rebinding Host headers, and cross-site form/fetch posts to loopback.
  if (req.headers['access-control-request-private-network'] === 'true') { res.writeHead(403); return res.end(); }
  if (!hostAllowed(req)) { res.writeHead(403); return res.end(); }
  if (isLoopbackHost(req.headers.host) && req.method !== 'GET' && req.method !== 'HEAD' && req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end(); }

  // CORS only where web MCP clients need it — never on /oauth/* or /api/*,
  // and never a reflected origin (that let any website read responses).
  const corsPath = url.pathname === '/mcp' || url.pathname === '/sse' || url.pathname === '/messages' || url.pathname.startsWith('/.well-known/');
  if (corsPath) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id, x-easy-mcp-token, mcp-protocol-version, mcp-method, mcp-name, *');
    res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id, *');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  try {
    const isAdminRoute = url.pathname === '/' || url.pathname === '/dashboard' || url.pathname.startsWith('/api/');
    if (isAdminRoute) {
      // Dashboard control plane: local browser only — never through the
      // tunnel, never with an MCP/OAuth token.
      if (!isLocalAdminRequest(req)) return sendJson(res, 404, { error: 'Not found' });
      if (url.pathname.startsWith('/api/') && !safeEqual(req.headers['x-easy-mcp-admin'] || '', ADMIN_SECRET)) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }
    } else if (!isPublicPath(url.pathname) && !authorized(req, url)) {
      if (url.pathname === '/mcp') {
        const base = publicUrl || `http://${req.headers.host || '127.0.0.1:' + PORT}`;
        res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`);
      }
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    if (url.pathname === '/.well-known/oauth-authorization-server' || url.pathname === '/.well-known/openid-configuration') {
      const base = publicUrl || `http://${req.headers.host || '127.0.0.1:' + PORT}`;
      return sendJson(res, 200, {
        issuer: base,
        authorization_endpoint: `${base}/oauth/authorize`,
        token_endpoint: `${base}/oauth/token`,
        registration_endpoint: `${base}/oauth/register`,
        scopes_supported: ['mcp', 'mcp:read', 'mcp:write'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256', 'plain'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none']
      });
    }

    if (url.pathname === '/.well-known/oauth-protected-resource') {
      const base = publicUrl || `http://${req.headers.host || '127.0.0.1:' + PORT}`;
      return sendJson(res, 200, {
        resource: `${base}/mcp`,
        authorization_servers: [base],
        bearer_methods_supported: ['header']
      });
    }

    if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
      const base = publicUrl || `http://${req.headers.host || '127.0.0.1:' + PORT}`;
      const suffix = url.pathname.slice('/.well-known/oauth-protected-resource'.length) || '/mcp';
      return sendJson(res, 200, {
        resource: `${base}${suffix}`,
        authorization_servers: [base],
        bearer_methods_supported: ['header'],
        scopes_supported: ['mcp']
      });
    }

    if (url.pathname === '/oauth/register' && req.method === 'POST') {
      if (!registerRateOk()) return sendJson(res, 429, { error: 'rate_limited', error_description: 'Too many registrations, try again in a minute' });
      let meta = {};
      try { meta = JSON.parse(await readBody(req, 65536) || '{}'); } catch {}
      const rawUris = Array.isArray(meta.redirect_uris) ? meta.redirect_uris : [];
      const redirectUris = rawUris.filter(u => validRedirectUri(u));
      if (rawUris.length && !redirectUris.length) {
        return sendJson(res, 400, { error: 'invalid_redirect_uri', error_description: 'redirect_uris must be https (or http loopback)' });
      }
      const authMethod = ['none', 'client_secret_post', 'client_secret_basic'].includes(meta.token_endpoint_auth_method) ? meta.token_endpoint_auth_method : 'client_secret_post';
      const clientId = 'mcp_' + crypto.randomBytes(16).toString('hex');
      const clientSecret = authMethod === 'none' ? '' : crypto.randomBytes(32).toString('hex');
      oauthClients.set(clientId, { secretHash: clientSecret ? sha256hex(clientSecret) : '', redirect_uris: redirectUris, authMethod, createdAt: Date.now() });
      pruneOAuthClients();
      saveOAuth();
      const out = {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0,
        redirect_uris: redirectUris,
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: authMethod,
        scope: 'mcp'
      };
      if (clientSecret) out.client_secret = clientSecret;
      return sendJson(res, 201, out);
    }

    if (url.pathname === '/oauth/authorize') {
      const redirectUri = url.searchParams.get('redirect_uri');
      const state = url.searchParams.get('state') || '';
      const clientId = url.searchParams.get('client_id') || '';
      const client = oauthClients.get(clientId);
      if (redirectUri) {
        if (!client) return sendJson(res, 400, { error: 'invalid_client', error_description: 'Unknown client_id — register first' });
        if (url.searchParams.get('response_type') !== 'code') return sendJson(res, 400, { error: 'unsupported_response_type' });
        const challenge = url.searchParams.get('code_challenge') || '';
        if (!challenge && client.authMethod === 'none') return sendJson(res, 400, { error: 'invalid_request', error_description: 'code_challenge (PKCE) is required for public clients' });
        const uriOk = client.redirect_uris.length ? client.redirect_uris.includes(redirectUri) : validRedirectUri(redirectUri);
        if (!uriOk) return sendJson(res, 400, { error: 'invalid_redirect_uri' });
        const code = crypto.randomBytes(32).toString('hex');
        oauthCodes.set(code, {
          exp: Date.now() + 600000,
          challenge,
          method: url.searchParams.get('code_challenge_method') || 'S256',
          clientId,
          redirectUri
        });
        if (oauthCodes.size > 100) { for (const [k, v] of oauthCodes) { if (v.exp < Date.now()) oauthCodes.delete(k); } }
        const target = new URL(redirectUri);
        target.searchParams.set('code', code);
        if (state) target.searchParams.set('state', state);
        const issBase = publicUrl || `http://${req.headers.host || '127.0.0.1:' + PORT}`;
        target.searchParams.set('iss', issBase);
        res.writeHead(302, { Location: target.toString() });
        return res.end();
      }
      return sendJson(res, 200, { status: 'authorized' });
    }

    if (url.pathname === '/oauth/token' && req.method === 'POST') {
      const raw = await readBody(req, 65536);
      const form = new URLSearchParams(raw);
      let secret = form.get('client_secret') || '';
      let clientId = form.get('client_id') || '';
      const basic = req.headers.authorization || '';
      if (basic.startsWith('Basic ')) {
        try {
          const [id, ...rest] = Buffer.from(basic.slice(6), 'base64').toString().split(':');
          if (!clientId) clientId = id;
          if (!secret) secret = rest.join(':');
        } catch {}
      }
      const grantType = form.get('grant_type') || 'authorization_code';
      const mintTokens = (cid, keepRefresh) => {
        const access = 'emcp_at_' + crypto.randomBytes(32).toString('hex');
        oauthTokens.set(sha256hex(access), { type: 'access', clientId: cid, exp: Date.now() + 86400000, createdAt: Date.now() });
        let refresh = keepRefresh;
        if (!refresh) {
          refresh = 'emcp_rt_' + crypto.randomBytes(32).toString('hex');
          oauthTokens.set(sha256hex(refresh), { type: 'refresh', clientId: cid, exp: 0, createdAt: Date.now() });
        }
        saveOAuth();
        return { access_token: access, token_type: 'Bearer', expires_in: 86400, refresh_token: refresh, scope: 'mcp' };
      };
      if (grantType === 'refresh_token') {
        const rt = form.get('refresh_token') || '';
        // Legacy: connections made before this patch hold the master token as
        // their refresh token. Accept it (it already grants /mcp access) and
        // hand back an opaque access token, keeping the same refresh token.
        if (rt && safeEqual(rt, TOKEN)) return sendJson(res, 200, mintTokens(clientId || 'legacy', TOKEN));
        const rec = oauthTokens.get(sha256hex(rt));
        if (!rec || rec.type !== 'refresh') {
          return sendJson(res, 401, { error: 'invalid_grant', error_description: 'Unknown refresh token' });
        }
        const client = oauthClients.get(rec.clientId);
        if (client && client.authMethod !== 'none' && !safeEqual(sha256hex(secret), client.secretHash)) {
          return sendJson(res, 401, { error: 'invalid_client', error_description: 'Client secret mismatch' });
        }
        return sendJson(res, 200, mintTokens(rec.clientId, rt)); // non-rotating refresh token
      }
      const code = form.get('code') || '';
      const rec = oauthCodes.get(code);
      if (code) oauthCodes.delete(code); // single-use
      if (!rec || rec.exp < Date.now()) {
        return sendJson(res, 401, { error: 'invalid_grant', error_description: 'Unknown or expired code' });
      }
      if (clientId && rec.clientId !== clientId) {
        return sendJson(res, 401, { error: 'invalid_grant', error_description: 'Code was issued to another client' });
      }
      const redirectUri = form.get('redirect_uri') || '';
      if (redirectUri && rec.redirectUri && redirectUri !== rec.redirectUri) {
        return sendJson(res, 401, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      }
      let pkceOk = !rec.challenge;
      if (rec.challenge) {
        const verifier = form.get('code_verifier') || '';
        pkceOk = !!verifier && safeEqual(rec.method === 'plain' ? verifier : crypto.createHash('sha256').update(verifier).digest('base64url'), rec.challenge);
      }
      const client = oauthClients.get(rec.clientId);
      let secretOk = !client || client.authMethod === 'none';
      if (client && client.authMethod !== 'none') secretOk = safeEqual(sha256hex(secret), client.secretHash);
      if (!pkceOk || !secretOk) {
        return sendJson(res, 401, { error: 'invalid_client', error_description: 'PKCE verifier or client secret mismatch' });
      }
      return sendJson(res, 200, mintTokens(rec.clientId, ''));
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/dashboard')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(DASHBOARD_HTML.replace('__EASY_MCP_ADMIN__', ADMIN_SECRET));
    }
    if (req.method === 'GET' && url.pathname === '/api/dashboard') {
      return sendJson(res, 200, dashboardData());
    }
    if (req.method === 'GET' && url.pathname === '/api/status') {
      const d = dashboardData();
      return sendJson(res, 200, { status: d.status, project: d.project, toolsCount: d.toolsCount, sseSessions: d.sseSessions, uptimeSec: d.uptimeSec });
    }
    if (req.method === 'POST' && url.pathname === '/api/set-project') {
      const { path: p } = JSON.parse(await readBody(req) || '{}');
      try { setProject(p); return sendJson(res, 200, { success: true, project: projectRoot }); }
      catch (err) { return sendJson(res, 400, { success: false, error: err.message }); }
    }
    if (req.method === 'POST' && url.pathname === '/api/pick-folder') {
      const picked = await pickFolderNative();
      if (!picked) return sendJson(res, 200, { success: false, error: 'No folder selected' });
      try { setProject(picked); return sendJson(res, 200, { success: true, project: projectRoot }); }
      catch (err) { return sendJson(res, 400, { success: false, error: err.message }); }
    }
    if (req.method === 'POST' && url.pathname === '/api/set-tunnel') {
      const { mode } = JSON.parse(await readBody(req) || '{}');
      try {
        await setTunnel(mode);
        return sendJson(res, 200, { success: !tunnelError, tunnelMode, publicUrl: publicUrl || null, error: tunnelError || null });
      } catch (err) {
        return sendJson(res, 200, { success: false, tunnelMode, error: err.message });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/set-public-url') {
      const { url: u } = JSON.parse(await readBody(req) || '{}');
      const clean = String(u || '').trim().replace(/\/+$/, '');
      if (!/^https:\/\//.test(clean)) return sendJson(res, 400, { success: false, error: 'url must be https://...' });
      publicUrl = clean;
      return sendJson(res, 200, { success: true, publicUrl });
    }
    if (req.method === 'GET' && url.pathname === '/api/settings') {
      return sendJson(res, 200, { readOnly: READ_ONLY, disableShell: DISABLE_SHELL, skipJail: SKIP_JAIL });
    }
    if (req.method === 'POST' && url.pathname === '/api/settings') {
      const body = JSON.parse(await readBody(req) || '{}');
      if (typeof body.readOnly === 'boolean') READ_ONLY = body.readOnly;
      if (typeof body.disableShell === 'boolean') DISABLE_SHELL = body.disableShell;
      if (typeof body.skipJail === 'boolean') SKIP_JAIL = body.skipJail;
      return sendJson(res, 200, { success: true, readOnly: READ_ONLY, disableShell: DISABLE_SHELL, skipJail: SKIP_JAIL });
    }
    if (req.method === 'POST' && url.pathname === '/api/stop-job') {
      const { id } = JSON.parse(await readBody(req) || '{}');
      const job = jobs.get(id);
      if (!job) return sendJson(res, 404, { success: false, error: 'Unknown job' });
      try { process.kill(job.pid); } catch {}
      job.status = 'stopped';
      return sendJson(res, 200, { success: true });
    }
    if (req.method === 'POST' && url.pathname === '/call') {
      const { name, arguments: toolArgs } = JSON.parse(await readBody(req) || '{}');
      try { return sendJson(res, 200, { success: true, result: await callTool(name, toolArgs) }); }
      catch (err) { return sendJson(res, 200, { success: false, error: err.message }); }
    }
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const raw = await readBody(req);
      let parsed;
      try { parsed = JSON.parse(raw || '{}'); } catch { return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
      const messages = Array.isArray(parsed) ? parsed : [parsed];
      const isInit = messages.some(m => m && m.method === 'initialize');
      let sessionId = req.headers['mcp-session-id'];
      if (isInit) {
        sessionId = crypto.randomBytes(16).toString('hex');
        mcpSessions.set(sessionId, { createdAt: Date.now() });
      }
      const outs = [];
      for (const m of messages) {
        const out = await handleRpc(m);
        if (out) outs.push(out);
      }
      if (!outs.length) { res.writeHead(202); return res.end(); }
      const payload = Array.isArray(parsed) ? outs : outs[0];
      const sseId = url.searchParams.get('sessionId') || sessionId;
      const sseRes = sseId && sseSessions.get(sseId);
      if (sseRes) { try { sseRes.write(`event: message\ndata: ${JSON.stringify(payload)}\n\n`); } catch {} }
      const body = JSON.stringify(payload);
      const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
      if (sessionId) headers['Mcp-Session-Id'] = sessionId;
      res.writeHead(200, headers);
      return res.end(body);
    }
    if (url.pathname === '/mcp' && req.method === 'GET') {
      const accept = req.headers.accept || '';
      if (!accept.includes('text/event-stream')) {
        // Plain GET (e.g. URL validators): answer with a JSON status so connectors can probe the endpoint.
        return sendJson(res, 200, {
          status: 'online',
          service: 'Easy MCP',
          protocolVersion: '2025-03-26',
          toolsCount: TOOLS.length,
          tools: TOOLS.map(t => t.name)
        });
      }
      // Legacy SSE transport: pad to flush proxy buffers, then send the endpoint event.
      if (req.socket) { req.socket.setKeepAlive(true, 10000); req.socket.setNoDelay(true); }
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      const proto = req.headers['x-forwarded-proto'] || 'https';
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      const sseId = crypto.randomBytes(16).toString('hex');
      const sseToken = crypto.randomBytes(16).toString('hex');
      sseSessionTokens.set(sseId, sseToken);
      const endpointUri = `${proto}://${host}/mcp?sessionId=${sseId}&token=${sseToken}`;
      res.write(`: ${' '.repeat(4096)}\n\n`);
      res.write(`event: endpoint\ndata: ${endpointUri}\n\n`);
      sseSessions.set(sseId, res);
      const ping = setInterval(() => { try { res.write(': ping\n\n'); res.write('event: ping\ndata: {}\n\n'); } catch {} }, 20000);
      const cleanup = () => { clearInterval(ping); sseSessions.delete(sseId); sseSessionTokens.delete(sseId); };
      req.on('close', cleanup);
      res.on('close', cleanup);
      return;
    }
    if (url.pathname === '/mcp' && req.method === 'DELETE') {
      const sessionId = req.headers['mcp-session-id'];
      if (sessionId) mcpSessions.delete(sessionId);
      res.writeHead(200);
      return res.end();
    }
    if (req.method === 'GET' && url.pathname === '/sse') {
      const sessionId = crypto.randomBytes(8).toString('hex');
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      sseSessions.set(sessionId, res);
      const sseToken = crypto.randomBytes(16).toString('hex');
      sseSessionTokens.set(sessionId, sseToken);
      const q = TOKEN ? `?token=${sseToken}&sessionId=${sessionId}` : `?sessionId=${sessionId}`;
      res.write(`event: endpoint\ndata: /messages${q}\n\n`);
      const ping = setInterval(() => res.write(': ping\n\n'), 25000);
      req.on('close', () => { clearInterval(ping); sseSessions.delete(sessionId); sseSessionTokens.delete(sessionId); });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/messages') {
      const sessionId = url.searchParams.get('sessionId');
      const sse = sseSessions.get(sessionId);
      const msg = JSON.parse(await readBody(req) || '{}');
      const out = await handleRpc(msg);
      if (out && sse) sse.write(`event: message\ndata: ${JSON.stringify(out)}\n\n`);
      res.writeHead(202);
      return res.end();
    }
    return sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    return sendJson(res, 500, { error: err.message });
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use — Easy MCP may already be running. Stop the old instance or use --port <n>.`);
    process.exit(1);
  }
  throw err;
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Easy MCP server on http://127.0.0.1:${PORT} — project: ${projectRoot}`);
  startTunnel(tunnelMode).catch(err => { tunnelError = err.message; });
  if (SKIP_JAIL) console.log('WARNING: --dangerously-skip-jail is ON. The AI can access the whole machine.');
});
