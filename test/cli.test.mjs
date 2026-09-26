import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, symlinkSync, linkSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const cli = new URL('../bin/model-response-redactor.mjs', import.meta.url).pathname;
const trace = { schemaVersion: 1, messages: [{ role: 'user', content: 'Hello.' }, { role: 'tool', content: { error: 'SYNTHETIC_SECRET_123' } }] };
const policy = { schemaVersion: 1, rules: [{ id: 'canary', type: 'literal', value: 'SYNTHETIC_SECRET_123' }] };
const withDir = fn => { const dir = mkdtempSync(join(tmpdir(), 'model-response-redactor-')); try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); } };
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000 });
const fixtures = dir => { const input = join(dir, 'trace.json'), config = join(dir, 'policy.json'); writeFileSync(input, JSON.stringify(trace)); writeFileSync(config, JSON.stringify(policy)); return { input, config }; };

test('read-only good trace exits zero and preserves order in JSON report', () => withDir(dir => {
  const { input, config } = fixtures(dir);
  writeFileSync(input, JSON.stringify({ schemaVersion: 1, messages: [{ role: 'user', content: 'Hello.' }] }));
  const result = run('--trace', input, '--policy', config);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout).redactedTrace.messages.map(m => m.role), ['user']);
}));

test('CLI redacts nested errors and writes only new output inside declared root', () => withDir(dir => {
  const { input, config } = fixtures(dir); const out = join(dir, 'safe.json');
  const result = run('--root', dir, '--trace', input, '--policy', config, '--out', out);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(JSON.parse(result.stdout).summary.replacements, 1);
  assert.doesNotMatch(result.stdout, /SYNTHETIC_SECRET_123/);
  assert.equal(JSON.parse(readFileSync(out)).messages[1].content.error, '[REDACTED]');
  assert.match(readFileSync(input, 'utf8'), /SYNTHETIC_SECRET_123/);
}));

test('invalid policy has empty stdout; unreadable trace has incomplete report', () => withDir(dir => {
  const { input, config } = fixtures(dir);
  writeFileSync(config, '{}');
  const bad = run('--trace', input, '--policy', config);
  assert.equal(bad.status, 2); assert.equal(bad.stdout, '');
  writeFileSync(config, JSON.stringify(policy));
  const missing = run('--trace', join(dir, 'missing.json'), '--policy', config);
  assert.equal(missing.status, 2); assert.equal(JSON.parse(missing.stdout).status, 'incomplete');
}));

test('unsupported local policy option exits two with empty stdout, never a clean unredacted trace', () => withDir(dir => {
  const { input, config } = fixtures(dir);
  writeFileSync(input, JSON.stringify({ schemaVersion: 1, messages: [{ role: 'user', content: 'synthetic_secret_123' }] }));
  writeFileSync(config, JSON.stringify({ schemaVersion: 1, rules: [{ id: 'canary', type: 'literal', value: 'SYNTHETIC_SECRET_123', caseInsensitive: true }] }));
  const result = run('--trace', input, '--policy', config);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
}));

test('destination symlink, hardlink to either read input, and existing file are refused without rewriting', () => withDir(dir => {
  const { input, config } = fixtures(dir); const out = join(dir, 'out.json');
  for (const target of [input, config]) {
    linkSync(target, out);
    const before = readFileSync(target, 'utf8');
    const result = run('--root', dir, '--trace', input, '--policy', config, '--out', out);
    assert.equal(result.status, 2); assert.equal(result.stdout, '');
    assert.equal(readFileSync(target, 'utf8'), before);
    rmSync(out);
  }
  symlinkSync(input, out);
  assert.equal(run('--root', dir, '--trace', input, '--policy', config, '--out', out).status, 2);
  rmSync(out);
  writeFileSync(out, 'leave me alone');
  assert.equal(run('--root', dir, '--trace', input, '--policy', config, '--out', out).status, 2);
  assert.equal(readFileSync(out, 'utf8'), 'leave me alone');
}));

test('symlinked parent escaping root and input symlink escaping root are refused', () => withDir(dir => {
  const root = join(dir, 'root'), outside = join(dir, 'outside'); mkdirSync(root); mkdirSync(outside);
  const { input, config } = fixtures(root); const link = join(root, 'link'); symlinkSync(outside, link);
  const out = join(link, 'escape.json');
  const result = run('--root', root, '--trace', input, '--policy', config, '--out', out);
  assert.equal(result.status, 2); assert.equal(result.stdout, ''); assert.equal(existsSync(join(outside, 'escape.json')), false);
  const outsideInput = join(outside, 'trace.json'); writeFileSync(outsideInput, JSON.stringify(trace));
  const disguised = join(root, 'trace-link.json'); symlinkSync(outsideInput, disguised);
  const read = run('--root', root, '--trace', disguised, '--policy', config);
  assert.equal(read.status, 2); assert.equal(JSON.parse(read.stdout).status, 'incomplete');
}));

test('exact input byte bound passes, N+1 is incomplete and does not write', () => withDir(dir => {
  const { input, config } = fixtures(dir); const n = Buffer.byteLength(JSON.stringify(trace));
  assert.equal(run('--trace', input, '--policy', config, '--max-bytes', String(n)).status, 1);
  const out = join(dir, 'out.json');
  const result = run('--root', dir, '--trace', input, '--policy', config, '--out', out, '--max-bytes', String(n - 1));
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).status, 'incomplete'); assert.equal(existsSync(out), false);
}));

test('duplicate JSON keys in trace are incomplete, not overwritten', () => withDir(dir => {
  const { input, config } = fixtures(dir);
  writeFileSync(input, '{"schemaVersion":1,"messages":[{"role":"tool","content":"SYNTHETIC_SECRET_123","content":"safe"}]}');
  const result = run('--trace', input, '--policy', config);
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).status, 'incomplete');
}));

test('policy bytes accept exactly 65536 and reject 65537 as configuration error', () => withDir(dir => {
  const { input, config } = fixtures(dir);
  const data = JSON.stringify(policy);
  writeFileSync(config, data + ' '.repeat(65536 - Buffer.byteLength(data)));
  assert.equal(run('--trace', input, '--policy', config).status, 1);
  writeFileSync(config, data + ' '.repeat(65537 - Buffer.byteLength(data)));
  const result = run('--trace', input, '--policy', config);
  assert.equal(result.status, 2); assert.equal(result.stdout, '');
}));
