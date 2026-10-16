#!/usr/bin/env node
// Static checks for the webview sources (docs/desktop-app.md §8.5, §8.3). No dependencies.
// Fails when src/ uses HTML string injection, browser storage or dynamic code, or when
// index.html loads anything remote. Untrusted text must be rendered as text only.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(root, 'src');
const EXT = /\.(ts|tsx|js|jsx|mjs|css|html)$/;

const RULES = [
  { re: /\binnerHTML\b|\bouterHTML\b/, why: 'HTML string injection (innerHTML/outerHTML)' },
  { re: /dangerouslySetInnerHTML/, why: 'HTML string injection (dangerouslySetInnerHTML)' },
  { re: /\binsertAdjacentHTML\b/, why: 'HTML string injection (insertAdjacentHTML)' },
  { re: /\bdocument\s*\.\s*write(ln)?\b/, why: 'document.write' },
  { re: /\blocalStorage\b/, why: 'browser storage (localStorage)' },
  { re: /\bsessionStorage\b/, why: 'browser storage (sessionStorage)' },
  { re: /\bindexedDB\b/, why: 'browser storage (indexedDB)' },
  { re: /(^|[^.\w$])eval\s*\(/, why: 'dynamic code (eval)' },
  { re: /\bnew\s+Function\s*\(/, why: 'dynamic code (new Function)' },
  { re: /\bcreateContextualFragment\b/, why: 'HTML string injection (createContextualFragment)' },
  { re: /\bsrcdoc\b/, why: 'HTML string injection (srcdoc)' },
];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (EXT.test(name)) out.push(p);
  }
  return out;
}

const problems = [];
for (const file of walk(SRC)) {
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    for (const r of RULES) if (r.re.test(line)) problems.push(`${relative(root, file)}:${i + 1}: ${r.why}`);
  });
}

// index.html: no remote scripts, styles or fonts
const html = readFileSync(join(root, 'index.html'), 'utf8');
const remote = /<(script|link|img|iframe)\b[^>]*\b(src|href)\s*=\s*["']?\s*(https?:)?\/\//gi;
for (const m of html.matchAll(remote)) problems.push(`index.html: remote resource: ${m[0].slice(0, 80)}`);
if (/<script\b(?![^>]*\bsrc=)[^>]*>\s*\S/i.test(html)) problems.push('index.html: inline script');

// CSS: no remote @import or url()
for (const file of walk(SRC).filter((f) => f.endsWith('.css'))) {
  const css = readFileSync(file, 'utf8');
  if (/@import\s+(url\()?\s*["']?(https?:)?\/\//i.test(css) || /url\(\s*["']?(https?:)?\/\//i.test(css)) {
    problems.push(`${relative(root, file)}: remote CSS resource`);
  }
}

if (problems.length) {
  console.error(`check-static: ${problems.length} problem(s)`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`check-static: ok (${walk(SRC).length} files)`);
