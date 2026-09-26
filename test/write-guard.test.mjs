import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, symlinkSync, linkSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertWritableDestination, DestinationError } from '../src/write-guard.mjs';

const withDir = async fn => { const dir = mkdtempSync(join(tmpdir(), 'redactor-guard-')); try { await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); } };

test('new destination under root is allowed', () => withDir(async dir => {
  const out = join(dir, 'new.json');
  assert.equal(await assertWritableDestination(out, { root: dir }), out);
}));

test('symlink at destination is independently refused', () => withDir(async dir => {
  const input = join(dir, 'input.json'), out = join(dir, 'out.json'); writeFileSync(input, '{}'); symlinkSync(input, out);
  await assert.rejects(assertWritableDestination(out, { root: dir, inputs: [] }), DestinationError);
}));

test('symlinked parent outside root is independently refused', () => withDir(async dir => {
  const root = join(dir, 'root'), outside = join(dir, 'outside'); mkdirSync(root); mkdirSync(outside);
  const link = join(root, 'link'); symlinkSync(outside, link);
  await assert.rejects(assertWritableDestination(join(link, 'new.json'), { root, inputs: [] }), DestinationError);
}));

test('hard link to policy file is refused even when the trace file differs', () => withDir(async dir => {
  const trace = join(dir, 'trace.json'), policy = join(dir, 'policy.json'), out = join(dir, 'out.json');
  writeFileSync(trace, '{}'); writeFileSync(policy, '{}'); linkSync(policy, out);
  await assert.rejects(assertWritableDestination(out, { root: dir, inputs: [trace, policy] }), DestinationError);
}));
