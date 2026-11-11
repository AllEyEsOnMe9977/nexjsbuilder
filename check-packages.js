#!/usr/bin/env node
// =============================================================================
// check-packages.js - shared guard used by import-template.sh and 04a-app-init.sh
// Usage: node check-packages.js <blocked-file> <json-file> [--reserved] [--require-next]
//   <json-file>      package.json (dependencies as object) or manifest.json (as arrays)
//   --reserved       also refuse packages the builder base owns (next, react, typescript...)
//   --require-next   refuse projects that do not depend on "next"
// Exit code 0 = OK, 1 = problems (printed to stderr), 2 = unreadable input.
// =============================================================================
const fs = require('fs');

const [, , blockedFile, jsonFile, ...flags] = process.argv;
if (!blockedFile || !jsonFile) {
  console.error('[ERROR] Usage: check-packages.js <blocked-file> <json-file> [--reserved] [--require-next]');
  process.exit(2);
}

// Packages owned by the builder base: a template must never pin or override them
const RESERVED = [
  'next', 'react', 'react-dom', 'typescript', 'tailwindcss', 'postcss',
  'prisma', '@prisma/client', 'eslint', 'eslint-config-next',
];

// "lucide-react@^1.0" -> "lucide-react", "@scope/pkg@1" -> "@scope/pkg"
const pkgName = (spec) => String(spec).replace(/(?!^)@.*$/, '');
// Accepts both ["a@1","b"] (manifest) and {"a":"1"} (package.json)
const namesOf = (v) => (Array.isArray(v) ? v.map(pkgName) : Object.keys(v || {}));

let blocked, data;
try {
  blocked = fs.readFileSync(blockedFile, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  data = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
} catch (err) {
  console.error('[ERROR] Cannot read/parse input: ' + err.message);
  process.exit(2);
}

const isBlocked = (name) => blocked.some((b) => (b.endsWith('*') ? name.startsWith(b.slice(0, -1)) : name === b));

const deps = namesOf(data.dependencies);
const all = [...deps, ...namesOf(data.devDependencies)];
const problems = [];

all.filter(isBlocked).forEach((n) =>
  problems.push(`"${n}" belongs to a non-Next.js stack (Vite/Express/etc.) and cannot be used in a builder template.`));

if (flags.includes('--reserved')) {
  all.filter((n) => RESERVED.includes(n)).forEach((n) =>
    problems.push(`"${n}" is provided by the builder base; a template must not list or pin it.`));
}

if (flags.includes('--require-next') && !deps.includes('next')) {
  problems.push('No "next" dependency: this is not a Next.js project. Rebuild it with the Next.js App Router.');
}

if (problems.length) {
  problems.forEach((p) => console.error('[ERROR] ' + p));
  process.exit(1);
}
console.log('[OK] package check passed (' + all.length + ' packages)');