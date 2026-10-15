#!/usr/bin/env node
// Static checks for the Tauri shell (docs/desktop-app.md §8.2–§8.4, §9). No dependencies.
//
// - tauri.conf.json: the exact CSP of §8.3 (also verbatim in the doc), withGlobalTauri false,
//   no CSP or IPC loosening, the main window as specified, deep links for `zeropw` only, and a
//   minimal bundle section: sidecars, resources and macOS settings are release-only.
// - tauri.bundle.conf.json (the release config, §9): exactly the three sidecars, LICENSE and
//   THIRD_PARTY_LICENSES.md as resources, and bundle.macOS with minimum macOS 11.0, the
//   Info.release.plist that holds only the Local Network usage description, and an ad-hoc
//   signing identity ("-") or none. No credential, certificate, notarization, entitlement,
//   updater or signing-command setting in either config: Developer ID signing and
//   notarization happen outside the build (docs/releasing.md).
// - No other file Tauri merges on its own: src-tauri/ holds no platform config
//   (tauri.<platform>.conf.json[5], Tauri.<platform>.toml), no tauri.conf.json5 or Tauri.toml,
//   no Info.plist and no other .plist or .entitlements file; these two configs and
//   Info.release.plist are the whole build configuration. The deep-link plugin config is
//   exactly {"desktop": {"schemes": ["zeropw"]}}: universal-link domains would make the Tauri
//   CLI sign the app with the com.apple.developer.associated-domains entitlement. The Tauri
//   CLI (2.12.1) derives macOS entitlements only from bundle.macOS.entitlements, refused above,
//   and those deep-link domains. desktop/scripts/package-macos.py also checks that the shipped
//   executables and the bundle carry no entitlements.
// - Object.prototype is frozen before any page script: by the shell's freeze_prototype.js,
//   since Tauri's bare freezePrototype breaks @xterm/xterm (see checkFreezePrototype).
// - The IPC surface is exactly desktop/src/ipc/contract.ts: the app manifest list in
//   build.rs, the invoke handler and one snake_case command per entry in src-tauri/src, and
//   a single capability for the main window holding core:default, window dragging for the
//   overlay title bar, plus exactly the allow-<command> permissions.
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
  'tauri-plugin-deep-link',
  'tauri-plugin-dialog',
  'tauri-plugin-single-instance',
];
const SIDECARS = ['binaries/zeropw-admin', 'binaries/zeropw_session', 'binaries/zeropw-agent'];
const BASE_KEYS = ['$schema', 'productName', 'version', 'identifier', 'build', 'app', 'bundle', 'plugins'];
const BASE_BUNDLE_KEYS = ['active', 'targets', 'category', 'shortDescription', 'icon'];
const RELEASE_RESOURCES = { '../../LICENSE': 'LICENSE', 'notices/THIRD_PARTY_LICENSES.md': 'THIRD_PARTY_LICENSES.md' };
const RELEASE_MACOS = { minimumSystemVersion: '11.0', infoPlist: 'Info.release.plist' };
const RELEASE_PLIST_KEYS = ['NSLocalNetworkUsageDescription'];
const DEEP_LINK = { desktop: { schemes: ['zeropw'] } };
// The only files in src-tauri/ that Tauri reads as build configuration.
const REVIEWED_CONFIG = ['tauri.conf.json', 'tauri.bundle.conf.json', 'Info.release.plist'];
// Setting names that would carry or select signing material, notarization accounts or updater keys.
const CREDENTIAL_KEY =
  /certificate|password|secret|private.?key|pubkey|keychain|notar|apple.?id|team.?id|provider.?short.?name|api.?(key|issuer)|entitlement|sign.?command|signing.?identity|updater/i;
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
if (conf.build?.devUrl !== 'http://localhost:1420') fail('tauri.conf.json: build.devUrl must be http://localhost:1420 (vite.config.ts server.port)');
checkReleaseConfig();

const windows = conf.app?.windows ?? [];
const main = windows[0] ?? {};
const want = { label: 'main', width: 1180, height: 780, minWidth: 1100, minHeight: 740, titleBarStyle: 'Overlay', hiddenTitle: true };
if (windows.length !== 1) fail('tauri.conf.json: exactly one window (main)');
for (const [k, v] of Object.entries(want)) if (main[k] !== v) fail(`tauri.conf.json: window ${k} must be ${JSON.stringify(v)}`);
if (main.dragDropEnabled !== false) fail('tauri.conf.json: dragDropEnabled must be false (drop events would hand file paths to the webview)');

const plugins = conf.plugins ?? {};
if (Object.keys(plugins).join() !== 'deep-link') fail('tauri.conf.json: only the deep-link plugin is configured');
if (!sameList(plugins['deep-link']?.desktop?.schemes ?? [], ['zeropw'])) fail('tauri.conf.json: deep links for the zeropw scheme only');
if (JSON.stringify(plugins['deep-link']) !== JSON.stringify(DEEP_LINK)) {
  fail(`tauri.conf.json: plugins.deep-link must be exactly ${JSON.stringify(DEEP_LINK)} (domains would add the associated-domains entitlement)`);
}

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
const wantPerms = ['core:default', 'core:window:allow-start-dragging', ...commands.map(permission)];
if (new Set(perms).size !== perms.length) fail('capabilities/default.json: duplicate permissions');
const extra = perms.filter((p) => !wantPerms.includes(p));
const missing = wantPerms.filter((p) => !perms.includes(p));
if (extra.length) fail(`capabilities/default.json: permissions outside core:default, window dragging and the contract: ${extra.join(', ')}`);
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
const GENERATED = new Set(['node_modules', 'dist', 'target', 'src-tauri/gen', 'src-tauri/icons', 'src-tauri/binaries', 'src-tauri/notices']);
const files = walk(root, (rel, name) => GENERATED.has(rel) || name === '.DS_Store' || name === '__pycache__');
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

// ---- the release config ---------------------------------------------------------------------
// tauri.conf.json stays minimal (it is also what `tauri dev`, Clippy and the tests build with);
// what only the distributed app needs lives in tauri.bundle.conf.json, merged by `tauri build
// --config` in npm run bundle and desktop/scripts/package-macos.py.
function checkReleaseConfig() {
  const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
  const extraTop = Object.keys(conf).filter((k) => !BASE_KEYS.includes(k));
  if (extraTop.length) fail(`tauri.conf.json: top-level ${extraTop.join(', ')} not allowed`);
  const extraBundle = Object.keys(conf.bundle ?? {}).filter((k) => !BASE_BUNDLE_KEYS.includes(k));
  if (extraBundle.length) {
    fail(`tauri.conf.json: bundle.${extraBundle.join(', bundle.')} not allowed; the base bundle holds only ${BASE_BUNDLE_KEYS.join(', ')} (sidecars, resources and macOS settings are release-only)`);
  }
  const release = json(join(tauriDir, 'tauri.bundle.conf.json'));
  const bundle = isObject(release.bundle) ? release.bundle : {};
  if (Object.keys(release).join() !== 'bundle') fail('tauri.bundle.conf.json: only a bundle section is allowed');
  if (!sameList(sorted(Object.keys(bundle)), ['externalBin', 'macOS', 'resources'])) {
    fail('tauri.bundle.conf.json: bundle must hold exactly externalBin, resources and macOS');
  }
  if (!sameList(bundle.externalBin ?? [], SIDECARS)) fail(`tauri.bundle.conf.json: bundle.externalBin must be ${SIDECARS.join(', ')}`);
  const resources = isObject(bundle.resources) ? bundle.resources : {};
  const wantResources = Object.entries(RELEASE_RESOURCES);
  if (Object.keys(resources).length !== wantResources.length || wantResources.some(([from, to]) => resources[from] !== to)) {
    fail(`tauri.bundle.conf.json: bundle.resources must map exactly ${wantResources.map(([from, to]) => `${from} -> ${to}`).join(', ')}`);
  }
  const macos = isObject(bundle.macOS) ? bundle.macOS : {};
  for (const key of Object.keys(macos)) {
    if (!(key in RELEASE_MACOS) && key !== 'signingIdentity') fail(`tauri.bundle.conf.json: bundle.macOS.${key} is not allowed`);
  }
  for (const [key, value] of Object.entries(RELEASE_MACOS)) {
    if (macos[key] !== value) fail(`tauri.bundle.conf.json: bundle.macOS.${key} must be ${JSON.stringify(value)}`);
  }
  if ('signingIdentity' in macos && macos.signingIdentity !== '-') {
    fail('tauri.bundle.conf.json: bundle.macOS.signingIdentity must be "-" (ad hoc) or absent; Developer ID signing happens outside the build (docs/releasing.md)');
  }
  const keyPaths = (value, path = []) =>
    isObject(value) || Array.isArray(value)
      ? Object.entries(value).flatMap(([k, v]) => [[...path, k], ...keyPaths(v, [...path, k])])
      : [];
  for (const [file, value] of [['tauri.conf.json', conf], ['tauri.bundle.conf.json', release]]) {
    for (const path of keyPaths(value)) {
      const dotted = path.join('.');
      if (file === 'tauri.bundle.conf.json' && dotted === 'bundle.macOS.signingIdentity') continue;
      if (CREDENTIAL_KEY.test(String(path.at(-1)))) fail(`${file}: ${dotted} is not allowed (no signing, credential or updater settings in the build config)`);
    }
  }
  // Tauri merges tauri.<platform>.conf.json[5] / Tauri.<platform>.toml into tauri.conf.json
  // and src-tauri/Info.plist into the bundle's Info.plist on its own; refuse every such file
  // (any case: macOS file systems usually ignore it) besides the reviewed ones.
  for (const name of readdirSync(tauriDir)) {
    const lower = name.toLowerCase();
    if (lower === 'info.plist') {
      fail('src-tauri/Info.plist would be merged into every build; release keys go in Info.release.plist');
    } else if (/^tauri(\..+)?\.(json5?|toml)$/.test(lower) && !REVIEWED_CONFIG.includes(name)) {
      fail(`src-tauri/${name}: Tauri would merge it into the build configuration; only ${REVIEWED_CONFIG.slice(0, 2).join(' and ')} are allowed`);
    } else if (/\.(plist|entitlements)$/.test(lower) && !REVIEWED_CONFIG.includes(name)) {
      fail(`src-tauri/${name}: no property list or entitlements file besides Info.release.plist`);
    }
  }
  const plist = read(join(tauriDir, 'Info.release.plist'));
  const plistKeys = [...plist.matchAll(/<key>([^<]*)<\/key>/g)].map((m) => m[1]);
  if (!sameList(plistKeys, RELEASE_PLIST_KEYS)) fail(`Info.release.plist: must hold only ${RELEASE_PLIST_KEYS.join(', ')}`);
  const description = plist.match(/<key>NSLocalNetworkUsageDescription<\/key>\s*<string>([^<]*)<\/string>/);
  if (!description || !description[1].trim()) fail('Info.release.plist: NSLocalNetworkUsageDescription needs a description');
}

if (problems.length) {
  console.error(`check-tauri: ${problems.length} problem(s)`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`check-tauri: ok (${commands.length} commands, ${files.length} files scanned)`);
