import test from 'node:test';
import assert from 'node:assert/strict';
import { redactTrace, TOOL_ID } from '../src/index.mjs';

const policy = () => ({ schemaVersion: 1, rules: [{ id: 'canary', type: 'literal', value: 'SYNTHETIC_SECRET_123' }, { id: 'email', type: 'email' }] });
const clean = () => ({ schemaVersion: 1, messages: [{ role: 'system', content: 'Only synthetic examples.' }, { role: 'user', content: 'Hello.' }, { role: 'assistant', content: 'Hello back.' }] });

test('clean trace passes and role/order/message structure survives unchanged', () => {
  const trace = clean();
  const result = redactTrace(trace, policy());
  assert.equal(TOOL_ID, 'model-response-redactor');
  assert.equal(result.status, 'pass');
  assert.deepEqual(result.redactedTrace, trace);
  assert.equal(result.summary.messages, 3);
  assert.equal(result.summary.replacements, 0);
});

test('configured literal and email disappear from nested tool messages and error objects', () => {
  const trace = clean();
  trace.messages.push({ role: 'tool', content: { output: ['SYNTHETIC_SECRET_123', { error: 'contact canary@example.invalid; SYNTHETIC_SECRET_123' }] } });
  const result = redactTrace(trace, policy());
  assert.equal(result.status, 'fail');
  assert.deepEqual(result.redactedTrace.messages.map(m => m.role), ['system', 'user', 'assistant', 'tool']);
  assert.equal(result.redactedTrace.messages[3].content.output[0], '[REDACTED]');
  assert.equal(result.redactedTrace.messages[3].content.output[1].error, 'contact [REDACTED]; [REDACTED]');
  assert.equal(result.summary.replacements, 3);
  assert.equal(result.summary.messages, 4);
  assert.deepEqual(result.counts, [{ rule: 'canary', count: 2 }, { rule: 'email', count: 1 }]);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_SECRET_123|canary@example.invalid/);
  assert.equal(trace.messages[3].content.output[0], 'SYNTHETIC_SECRET_123');
});

test('overlapping literal rules do not invent counts or reveal a shorter span', () => {
  const trace = { schemaVersion: 1, messages: [{ role: 'user', content: 'SYNTHETIC_SECRET_123' }] };
  const rules = { schemaVersion: 1, rules: [{ id: 'short', type: 'literal', value: 'SYNTHETIC' }, { id: 'long', type: 'literal', value: 'SYNTHETIC_SECRET_123' }] };
  const result = redactTrace(trace, rules);
  assert.equal(result.redactedTrace.messages[0].content, '[REDACTED]');
  assert.deepEqual(result.counts, [{ rule: 'long', count: 1 }]);
});

test('malformed or missing roles, or sensitive object keys, yield incomplete and no redacted trace', () => {
  for (const trace of [
    { schemaVersion: 1, messages: [{ content: 'hello' }] },
    { schemaVersion: 1, messages: [{ role: 'other', content: 'hello' }] },
    { schemaVersion: 1, messages: [{ role: 'user', content: { SYNTHETIC_SECRET_123: 'hello' } }] },
    { schemaVersion: 1, messages: [{ role: 'user', content: 42 }] }
  ]) {
    const result = redactTrace(trace, policy());
    assert.equal(result.status, 'incomplete');
    assert.equal(result.redactedTrace, undefined);
  }
});

test('message count bound admits exactly N but refuses N+1', () => {
  assert.equal(redactTrace(clean(), policy(), { maxMessages: 3 }).status, 'pass');
  assert.equal(redactTrace(clean(), policy(), { maxMessages: 2 }).status, 'incomplete');
});

test('policy must be explicit, safe and bounded', () => {
  for (const bad of [null, {}, { schemaVersion: 1, rules: [] }, { schemaVersion: 1, rules: [{ id: 'x', type: 'regex', value: '.*' }] }, { schemaVersion: 1, rules: [{ id: 'x', type: 'literal', value: '' }] }, { schemaVersion: 1, rules: [{ id: 'x', type: 'literal', value: 'assistant' }] }]) {
    assert.throws(() => redactTrace(clean(), bad), /policy/i);
  }
});

test('unsupported policy keys are rejected instead of silently weakening redaction', () => {
  const lower = { schemaVersion: 1, messages: [{ role: 'user', content: 'synthetic_secret_123' }] };
  const base = policy();
  assert.throws(() => redactTrace(lower, { ...base, caseInsensitive: true }), /policy/i);
  assert.throws(() => redactTrace(lower, { ...base, rules: [{ ...base.rules[0], caseInsensitive: true }] }), /policy/i);
  assert.throws(() => redactTrace(lower, { schemaVersion: 1, rules: [{ id: 'email', type: 'email', domainOnly: true }] }), /policy/i);
});

test('string bound permits exactly N and refuses N+1 without output', () => {
  const trace = { schemaVersion: 1, messages: [{ role: 'user', content: 'hello' }] };
  assert.equal(redactTrace(trace, policy(), { maxString: 5 }).status, 'pass');
  trace.messages[0].content = 'helloo';
  const result = redactTrace(trace, policy(), { maxString: 5 });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.redactedTrace, undefined);
});

test('prototype-shaped JSON keys remain ordinary keys in redacted structure', () => {
  const trace = JSON.parse('{"schemaVersion":1,"messages":[{"role":"tool","content":{"__proto__":"SYNTHETIC_SECRET_123"}}]}');
  const result = redactTrace(trace, policy());
  assert.equal(result.status, 'fail');
  assert.equal(Object.getOwnPropertyDescriptor(result.redactedTrace.messages[0].content, '__proto__').value, '[REDACTED]');
});

test('replacement marker cannot itself be a configured secret', () => {
  assert.throws(() => redactTrace(clean(), { schemaVersion: 1, rules: [{ id: 'mask', type: 'literal', value: 'REDACTED' }] }), /policy/i);
});

test('32 policy rules are accepted and 33 are rejected', () => {
  const rules = Array.from({ length: 32 }, (_, i) => ({ id: `rule-${i}`, type: 'literal', value: `synthetic-token-${i}` }));
  assert.equal(redactTrace(clean(), { schemaVersion: 1, rules }).status, 'pass');
  assert.throws(() => redactTrace(clean(), { schemaVersion: 1, rules: [...rules, { id: 'extra', type: 'email' }] }), /policy/i);
});

test('nested traversal admits exact depth and rejects the next level', () => {
  const trace = { schemaVersion: 1, messages: [{ role: 'user', content: { a: { b: 'okay' } } }] };
  assert.equal(redactTrace(trace, policy(), { maxDepth: 4 }).status, 'pass');
  assert.equal(redactTrace(trace, policy(), { maxDepth: 3 }).status, 'incomplete');
});

test('object key of 256 characters is preserved, 257 refuses output', () => {
  const trace = { schemaVersion: 1, messages: [{ role: 'tool', content: { ['k'.repeat(256)]: 'okay' } }] };
  assert.equal(redactTrace(trace, policy()).status, 'pass');
  trace.messages[0].content = { ['k'.repeat(257)]: 'okay' };
  assert.equal(redactTrace(trace, policy()).status, 'incomplete');
});

test('traversal permits 100000 visited values, refuses 100001', () => {
  const trace = { schemaVersion: 1, messages: [{ role: 'tool', content: Array(99998).fill(0) }] };
  assert.equal(redactTrace(trace, policy()).status, 'pass');
  trace.messages[0].content.push(0);
  assert.equal(redactTrace(trace, policy()).status, 'incomplete');
});
