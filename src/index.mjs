export const TOOL_ID = 'model-response-redactor';

const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const keysAre = (value, allowed) => Object.keys(value).every(key => allowed.includes(key));
const order = (a, b) => a === b ? 0 : a < b ? -1 : 1;
const clean = x => typeof x === 'string' && !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(x);
const roles = new Set(['system', 'developer', 'user', 'assistant', 'tool']);
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;

function validatePolicy(policy) {
  if (!object(policy) || !keysAre(policy, ['schemaVersion', 'rules']) || policy.schemaVersion !== 1 || !Array.isArray(policy.rules) || policy.rules.length < 1 || policy.rules.length > 32) throw new TypeError('invalid policy');
  const ids = new Set();
  for (const rule of policy.rules) {
    if (!object(rule) || !keysAre(rule, rule.type === 'literal' ? ['id', 'type', 'value'] : ['id', 'type']) || !/^[a-z][a-z0-9-]{0,31}$/u.test(rule.id ?? '') || ids.has(rule.id) || !['literal', 'email'].includes(rule.type)) throw new TypeError('invalid policy rule');
    if (rule.type === 'literal' && (!clean(rule.value) || rule.value.length < 2 || rule.value.length > 256)) throw new TypeError('invalid policy literal');
    if (rule.type === 'literal' && [...roles].some(role => role.includes(rule.value))) throw new TypeError('policy matches structural role');
    if (rule.type === 'literal' && ('[REDACTED]'.includes(rule.value) || rule.id.includes(rule.value))) throw new TypeError('policy literal appears in report metadata');
    if (rule.type === 'email' && Object.hasOwn(rule, 'value')) throw new TypeError('invalid policy email');
    ids.add(rule.id);
  }
  return policy.rules;
}

function matches(value, rules) {
  const candidates = [];
  for (const rule of rules) {
    if (rule.type === 'literal') {
      let from = 0; let at;
      while ((at = value.indexOf(rule.value, from)) !== -1) {
        candidates.push({ from: at, to: at + rule.value.length, id: rule.id }); from = at + 1;
      }
    } else {
      EMAIL.lastIndex = 0;
      for (const match of value.matchAll(EMAIL)) candidates.push({ from: match.index, to: match.index + match[0].length, id: rule.id });
    }
  }
  candidates.sort((a, b) => a.from - b.from || b.to - a.to || order(a.id, b.id));
  const chosen = []; let end = 0;
  for (const candidate of candidates) if (candidate.from >= end) { chosen.push(candidate); end = candidate.to; }
  return chosen;
}

export function redactTrace(trace, policy, { maxMessages = 1000, maxDepth = 16, maxString = 65536 } = {}) {
  const rules = validatePolicy(policy);
  if (![maxMessages, maxDepth, maxString].every(x => Number.isSafeInteger(x) && x >= 1)) throw new TypeError('invalid limits');
  const messageCount = Array.isArray(trace?.messages) ? trace.messages.length : 0;
  const summary = { messages: messageCount, stringsScanned: 0, replacements: 0 };
  const incomplete = reason => ({ tool: TOOL_ID, status: 'incomplete', summary: { messages: messageCount, stringsScanned: 0, replacements: 0 }, counts: [], findings: [{ rule: reason, severity: 'unknown' }] });
  if (!object(trace) || trace.schemaVersion !== 1 || !Array.isArray(trace.messages) || messageCount > maxMessages) return incomplete('invalid-trace');
  for (const message of trace.messages) if (!object(message) || !roles.has(message.role) || !Object.hasOwn(message, 'content') || !(typeof message.content === 'string' || Array.isArray(message.content) || object(message.content))) return incomplete('invalid-message');
  let invalid = false; let nodes = 0;
  const counts = new Map();
  const walk = (value, depth) => {
    if (++nodes > 100000 || depth > maxDepth) { invalid = true; return undefined; }
    if (typeof value === 'string') {
      if (value.length > maxString) { invalid = true; return undefined; }
      summary.stringsScanned++;
      const spans = matches(value, rules);
      if (spans.length === 0) return value;
      let result = ''; let cursor = 0;
      for (const span of spans) {
        result += value.slice(cursor, span.from) + '[REDACTED]'; cursor = span.to;
        counts.set(span.id, (counts.get(span.id) ?? 0) + 1);
        summary.replacements++;
      }
      return result + value.slice(cursor);
    }
    if (Array.isArray(value)) return value.map(child => walk(child, depth + 1));
    if (object(value)) {
      const result = {};
      for (const [key, child] of Object.entries(value)) {
        if (key.length > 256 || matches(key, rules).length) { invalid = true; continue; }
        Object.defineProperty(result, key, { value: walk(child, depth + 1), enumerable: true, writable: true, configurable: true });
      }
      return result;
    }
    return value;
  };
  // Message roles are validated above and preserved as structural metadata.
  const output = { ...trace, messages: trace.messages.map(message => {
    const copy = {};
    for (const [key, value] of Object.entries(message)) {
      if (key.length > 256 || matches(key, rules).length) { invalid = true; continue; }
      Object.defineProperty(copy, key, { value: key === 'role' ? value : walk(value, 2), enumerable: true, writable: true, configurable: true });
    }
    return copy;
  }) };
  for (const [key, value] of Object.entries(trace)) {
    if (key === 'messages') continue;
    if (key.length > 256 || matches(key, rules).length) { invalid = true; continue; }
    Object.defineProperty(output, key, { value: walk(value, 1), enumerable: true, writable: true, configurable: true });
  }
  if (invalid) return incomplete('unrenderable-trace');
  const items = [...counts].map(([rule, count]) => ({ rule, count })).sort((a, b) => order(a.rule, b.rule));
  return { tool: TOOL_ID, status: summary.replacements ? 'fail' : 'pass', summary, counts: items, findings: summary.replacements ? [{ rule: 'sensitive-span', severity: 'error', count: summary.replacements }] : [], redactedTrace: output };
}
