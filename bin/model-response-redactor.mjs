#!/usr/bin/env node
import { realpathSync, statSync, existsSync, writeFileSync } from 'node:fs';
import { sep } from 'node:path';
import { redactTrace, TOOL_ID } from '../src/index.mjs';
import { readJson } from '../src/json.mjs';
import { assertWritableDestination } from '../src/write-guard.mjs';

const options = Object.create(null);
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 2) {
  const key = args[i];
  if (!['--trace', '--policy', '--root', '--out', '--max-bytes'].includes(key) || Object.hasOwn(options, key) || !args[i + 1] || args[i + 1].startsWith('--')) {
    process.stderr.write('Invalid configuration. Use --trace FILE --policy FILE [--root DIR --out FILE] [--max-bytes N].\n'); process.exit(2);
  }
  options[key] = args[i + 1];
}
const integer = s => typeof s === 'string' && /^[1-9]\d*$/u.test(s) && Number.isSafeInteger(Number(s)) && Number(s) <= 10485760;
if (!options['--trace'] || !options['--policy'] || (options['--out'] && !options['--root']) || (options['--max-bytes'] && !integer(options['--max-bytes']))) {
  process.stderr.write('Invalid configuration. Use --trace FILE --policy FILE [--root DIR --out FILE] [--max-bytes N].\n'); process.exit(2);
}
const maxBytes = Number(options['--max-bytes'] ?? 2097152);
const configError = () => { process.stderr.write('Invalid local policy or output configuration.\n'); process.exit(2); };
const incomplete = () => ({ tool: TOOL_ID, status: 'incomplete', summary: { messages: 0, stringsScanned: 0, replacements: 0 }, counts: [], findings: [{ rule: 'unreadable-trace', severity: 'unknown' }] });
let root;
let policy;
try {
  if (options['--root']) {
    root = realpathSync(options['--root']);
    if (!statSync(root).isDirectory()) throw new Error('root');
  }
  const contained = path => {
    const actual = realpathSync(path);
    if (root && actual !== root && !actual.startsWith(root + sep)) throw new Error('outside root');
  };
  contained(options['--policy']);
  policy = readJson(options['--policy'], 65536);
  redactTrace({ schemaVersion: 1, messages: [] }, policy);
} catch { configError(); }

let report;
try {
  if (root) {
    const actual = realpathSync(options['--trace']);
    if (actual !== root && !actual.startsWith(root + sep)) throw new Error('outside root');
  }
  report = redactTrace(readJson(options['--trace'], maxBytes), policy);
} catch { report = incomplete(); }

if (options['--out'] && report.status !== 'incomplete') {
  try {
    const target = await assertWritableDestination(options['--out'], { root, inputs: [options['--trace'], options['--policy']] });
    if (existsSync(target)) throw new Error('existing output');
    writeFileSync(target, JSON.stringify(report.redactedTrace) + '\n', { flag: 'wx', mode: 0o600 });
  } catch { configError(); }
}
process.stdout.write(JSON.stringify(report) + '\n');
process.exit(report.status === 'pass' ? 0 : report.status === 'fail' ? 1 : 2);
