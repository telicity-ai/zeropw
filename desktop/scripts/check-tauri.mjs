#!/usr/bin/env node
// Static checks for the Tauri shell (docs/desktop-app.md §8.2–§8.4, §9). No dependencies.
//
// - tauri.conf.json: the exact CSP of §8.3 (also verbatim in the doc), withGlobalTauri false,
//   no CSP or IPC loosening, the main window as specified, deep links for `zeropw` only, no
//   sidecars in the base config (they live in tauri.bundle.conf.json).
// - Object.prototype is frozen before any page script: by the shell's freeze_prototype.js,
//   since Tauri's bare freezePrototype breaks @xterm/xterm (see checkFreezePrototype).
// - The IPC surface is exactly desktop/src/ipc/contract.ts: the app manifest list in
//   build.rs, the invoke handler and one snake_case command per entry in src-tauri/src, and
//   a single capability for the main window holding core:default plus exactly the
//   allow-<command> permissions.
// - No shell, fs, http or opener plugin is a direct dependency; no plugin is used from JS.
// - No file under desktop/ (build outputs aside) contains a NUL byte or exceeds the review
//   harness's 300,000-byte limit.

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tauriDir = join(root, 'src-tauri');
const problems = [];
const fail = (msg) => problems.push(msg);
const read = (p) => readFileSync(p, 'utf8');
const json = (p) => JSON.parse(read(p));
const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const sorted = (xs) => [...xs].sort();

export const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
  "font-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; " +
  "form-action 'none'; frame-ancestors 'none'";
const FORBIDDEN_PLUGINS = ['shell', 'fs', 'http', 'opener'];
const ALLOWED_RUST_PLUGINS = [
  'tauri-plugin-clipboard-manager',
  'tauri-plugin-deep-link',
  'tauri-plugin-dialog',
  'tauri-plugin-single-instance',
];
const SIDECARS = ['binaries/zeropw-admin', 'binaries/zeropw_session', 'binaries/zeropw-agent'];
const MAX_FILE_BYTES = 300_000;

// ---- the contract -------------------------------------------------------------------------
const contract = read(join(root, 'src/ipc/contract.ts'));
const start = contract.indexOf('export interface Commands {');
const block = start >= 0 ? contract.slice(start, contract.indexOf('\n}\n', start)) : '';
const commands = [...block.matchAll(/^\s+([a-z][a-z0-9_]*): \[/gm)].map((m) => m[1]);
if (commands.length < 10) fail(`contract.ts: could not read the Commands interface (${commands.length} entries)`);
if (new Set(commands).size !== commands.length) fail('contract.ts: duplicate command names');
const permission = (name) => `allow-${name.replaceAll('_', '-')}`;

// ---- tauri.conf.json ----------------------------------------------------------------------
const conf = json(join(tauriDir, 'tauri.conf.json'));
const security = conf.app?.security ?? {};
if (security.csp !== CSP) fail('tauri.conf.json: app.security.csp is not exactly the CSP of docs/desktop-app.md §8.3');
const doc = join(root, '..', 'docs', 'desktop-app.md');
if (!existsSync(doc) || !read(doc).includes('`' + CSP + '`')) fail('docs/desktop-app.md §8.3 no longer states the CSP this check enforces');
if (conf.app?.withGlobalTauri !== false) fail('tauri.conf.json: app.withGlobalTauri must be false');
checkFreezePrototype();
for (const key of Object.keys(security)) {
  if (!['csp', 'freezePrototype', 'capabilities'].includes(key)) {
    fail(`tauri.conf.json: app.security.${key} is not allowed (CSP/IPC loosening, asset protocol, devCsp…)`);
  }
}
if (conf.productName !== 'ZeroPW') fail('tauri.conf.json: productName must be ZeroPW');
if (conf.identifier !== 'ai.telicity.zeropw') fail('tauri.conf.json: identifier must be ai.telicity.zeropw');
if (conf.build?.frontendDist !== '../dist') fail('tauri.conf.json: build.frontendDist must be ../dist');
if (conf.build?.devUrl !== 'http://localhost:5173') fail('tauri.conf.json: build.devUrl must be http://localhost:5173');
if (conf.bundle?.externalBin !== undefined) fail('tauri.conf.json: externalBin belongs in tauri.bundle.conf.json only');
const bundleConf = json(join(tauriDir, 'tauri.bundle.conf.json'));
if (!sameList(bundleConf.bundle?.externalBin ?? [], SIDECARS) || Object.keys(bundleConf).join() !== 'bundle' || Object.keys(bundleConf.bundle).join() !== 'externalBin') {
  fail(`tauri.bundle.conf.json: must hold only bundle.externalBin = ${SIDECARS.join(', ')}`);
}

const windows = conf.app?.windows ?? [];
const main = windows[0] ?? {};
const want = { label: 'main', width: 1180, height: 780, minWidth: 1100, minHeight: 740, titleBarStyle: 'Overlay', hiddenTitle: true };
if (windows.length !== 1) fail('tauri.conf.json: exactly one window (main)');
for (const [k, v] of Object.entries(want)) if (main[k] !== v) fail(`tauri.conf.json: window ${k} must be ${JSON.stringify(v)}`);
if (main.dragDropEnabled !== false) fail('tauri.conf.json: dragDropEnabled must be false (drop events would hand file paths to the webview)');

const plugins = conf.plugins ?? {};
if (Object.keys(plugins).join() !== 'deep-link') fail('tauri.conf.json: only the deep-link plugin is configured');
if (!sameList(plugins['deep-link']?.desktop?.schemes ?? [], ['zeropw'])) fail('tauri.conf.json: deep links for the zeropw scheme only');

// ---- capabilities -------------------------------------------------------------------------
const capDir = join(tauriDir, 'capabilities');
const capFiles = readdirSync(capDir).filter((f) => !f.startsWith('.'));
if (capFiles.join() !== 'default.json') fail(`capabilities/: only default.json is allowed (found ${capFiles.join(', ')})`);
const cap = json(join(capDir, 'default.json'));
if (!sameList(security.capabilities ?? [], [cap.identifier])) fail('tauri.conf.json: app.security.capabilities must list exactly the default capability');
if (!sameList(cap.windows ?? [], ['main'])) fail('capabilities/default.json: windows must be ["main"]');
for (const key of Object.keys(cap)) {
  if (!['$schema', 'identifier', 'description', 'windows', 'permissions'].includes(key)) fail(`capabilities/default.json: "${key}" is not allowed (remote, webviews, platforms…)`);
}
const perms = cap.permissions ?? [];
if (!perms.every((p) => typeof p === 'string')) fail('capabilities/default.json: permissions must be plain identifiers (no scoped entries)');
const wantPerms = ['core:default', ...commands.map(permission)];
if (new Set(perms).size !== perms.length) fail('capabilities/default.json: duplicate permissions');
const extra = perms.filter((p) => !wantPerms.includes(p));
const missing = wantPerms.filter((p) => !perms.includes(p));
if (extra.length) fail(`capabilities/default.json: permissions outside core:default and the contract: ${extra.join(', ')}`);
if (missing.length) fail(`capabilities/default.json: missing contract permissions: ${missing.join(', ')}`);

// ---- build.rs manifest, handler and commands ----------------------------------------------
const buildRs = read(join(tauriDir, 'build.rs'));
const list = buildRs.match(/const COMMANDS: &\[&str\] = &\[([\s\S]*?)\];/);
const manifest = list ? [...list[1].matchAll(/"([a-z0-9_]+)"/g)].map((m) => m[1]) : [];
if (!sameList(manifest, commands)) fail('build.rs: COMMANDS must list exactly the contract commands, in contract order');

const rustSources = readdirSync(join(tauriDir, 'src')).filter((f) => f.endsWith('.rs')).map((f) => read(join(tauriDir, 'src', f))).join('\n');
const handler = rustSources.match(/generate_handler!\[([\s\S]*?)\]/);
const handled = handler ? handler[1].split(',').map((s) => s.trim().split('::').pop()).filter(Boolean) : [];
if (!sameList(sorted(handled), sorted(commands))) fail('src-tauri: generate_handler! must register exactly the contract commands');
for (const name of commands) {
  const re = new RegExp(`#\\[tauri::command\\(rename_all = "snake_case"\\)\\]\\s*pub (async )?fn ${name}\\b`);
  if (!re.test(rustSources)) fail(`src-tauri: no #[tauri::command(rename_all = "snake_case")] fn ${name}`);
}
const commandAttrs = (rustSources.match(/#\[tauri::command/g) ?? []).length;
if (commandAttrs !== commands.length) fail(`src-tauri: ${commandAttrs} commands defined, the contract has ${commands.length}`);

// ---- plugins ------------------------------------------------------------------------------
for (const file of ['Cargo.toml', 'core/Cargo.toml', 'src-tauri/Cargo.toml']) {
  const text = read(join(root, file));
  for (const p of FORBIDDEN_PLUGINS) if (new RegExp(`tauri-plugin-${p}\\b`).test(text)) fail(`${file}: forbidden plugin tauri-plugin-${p}`);
}
const shellToml = read(join(tauriDir, 'Cargo.toml'));
const rustPlugins = [...shellToml.matchAll(/^(tauri-plugin-[a-z0-9-]+)\s*=/gm)].map((m) => m[1]);
for (const p of rustPlugins) if (!ALLOWED_RUST_PLUGINS.includes(p)) fail(`src-tauri/Cargo.toml: plugin ${p} is not on the allowlist`);
const pkg = json(join(root, 'package.json'));
for (const dep of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
  if (dep.startsWith('@tauri-apps/plugin-')) fail(`package.json: ${dep}: plugins are used from Rust only`);
}

// ---- webview sources ----------------------------------------------------------------------
function walk(dir, skip, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const rel = relative(root, p);
    if (skip(rel, name)) continue;
    if (statSync(p).isDirectory()) walk(p, skip, out);
    else out.push(p);
  }
  return out;
}
for (const file of walk(join(root, 'src'), () => false)) {
  const text = read(file);
  if (/deep-link:\/\/|plugin:deep-link|plugin:(dialog|clipboard-manager|single-instance)\|/.test(text)) {
    fail(`${relative(root, file)}: the webview must not use plugin commands or the raw deep-link event`);
  }
}
if (/<style[\s>]/i.test(read(join(root, 'index.html')))) {
  fail("index.html: inline <style> makes Tauri add a style nonce, which disables 'unsafe-inline' for the app's runtime styles");
}

// ---- files the review harness would reject ------------------------------------------------
const GENERATED = new Set(['node_modules', 'dist', 'target', 'src-tauri/gen', 'src-tauri/icons', 'src-tauri/binaries']);
const files = walk(root, (rel, name) => GENERATED.has(rel) || name === '.DS_Store');
for (const file of files) {
  const bytes = readFileSync(file);
  if (bytes.length > MAX_FILE_BYTES) fail(`${relative(root, file)}: ${bytes.length} bytes (limit ${MAX_FILE_BYTES})`);
  if (bytes.includes(0)) fail(`${relative(root, file)}: contains a NUL byte (binary files are not committed)`);
}

// ---- Object.prototype is frozen before any page script --------------------------------------
// Tauri's `freezePrototype` is a bare Object.freeze(Object.prototype); with it, @xterm/xterm
// throws while the bundle loads (it assigns `toString` on a plain object: the "override
// mistake") and the window stays blank. The shell freezes the prototype itself, with override
// taming, from src-tauri/src/freeze_prototype.js. Checked here: it is wired into the main
// window, and in a fresh realm it freezes Object.prototype, refuses changes to it, and still
// lets ordinary objects take own properties with inherited names.
function checkFreezePrototype() {
  if (security.freezePrototype !== false) {
    fail('tauri.conf.json: app.security.freezePrototype must be false; the shell freezes Object.prototype itself (src-tauri/src/freeze_prototype.js)');
  }
  const shellRs = read(join(tauriDir, 'src', 'shell.rs'));
  if (!shellRs.includes('include_str!("freeze_prototype.js")') || !shellRs.includes('.initialization_script(FREEZE_PROTOTYPE)')) {
    fail('src-tauri/src/shell.rs: the main window must run freeze_prototype.js as an initialization script');
  }
  const ctx = vm.createContext({});
  try {
    vm.runInContext(read(join(tauriDir, 'src', 'freeze_prototype.js')), ctx);
  } catch {
    fail('freeze_prototype.js: throws when run');
    return;
  }
  const probe = (code) => {
    try {
      return vm.runInContext(`(function () { 'use strict'; ${code} })()`, ctx);
    } catch (e) {
      return `threw ${e && e.name}`;
    }
  };
  const expect = (code, want, what) => {
    const got = probe(code);
    if (got !== want) fail(`freeze_prototype.js: ${what} (got ${String(got)})`);
  };
  expect('return Object.isFrozen(Object.prototype);', true, 'Object.prototype is not frozen');
  expect("Object.prototype.toString = function () {}; return 'set';", 'threw TypeError', 'Object.prototype.toString can be replaced');
  expect("Object.prototype.polluted = 1; return 'set';", 'threw TypeError', 'Object.prototype can be extended');
  expect("Object.defineProperty(Object.prototype, 'valueOf', { value: 1 }); return 'set';", 'threw TypeError', 'Object.prototype can be redefined');
  expect("var ns = {}; ns.toString = function () { return 'own'; }; return ns.toString() + Object.prototype.hasOwnProperty.call(ns, 'toString');", 'owntrue', 'an object cannot take an own toString');
  expect("var o = {}; o.constructor = 1; o.hasOwnProperty = 2; return o.constructor + o.hasOwnProperty + ({}).constructor.name;", '3Object', 'own constructor/hasOwnProperty broke the prototype');
  expect('return Object.prototype.toString.call([]);', '[object Array]', 'Object.prototype.toString no longer works');
  expect("var m = JSON.parse('{\"__proto__\": {\"polluted\": 1}}'); var t = {}; for (var k in m) t[k] = m[k]; return ({}).polluted === undefined;", true, 'a __proto__ merge pollutes Object.prototype');
}

if (problems.length) {
  console.error(`check-tauri: ${problems.length} problem(s)`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`check-tauri: ok (${commands.length} commands, ${files.length} files scanned)`);
