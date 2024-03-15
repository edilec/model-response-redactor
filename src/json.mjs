import { readFileSync, statSync } from 'node:fs';
import { TextDecoder } from 'node:util';

function duplicateKeys(text) {
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') stack.push({ type: 'object', keys: new Set(), expectingKey: true });
    else if (c === '[') stack.push({ type: 'array' });
    else if (c === '}' || c === ']') stack.pop();
    else if (c === ',' && stack.at(-1)?.type === 'object') stack.at(-1).expectingKey = true;
    else if (c === ':' && stack.at(-1)?.type === 'object') stack.at(-1).expectingKey = false;
    else if (c === '"') {
      const start = i;
      for (i++; i < text.length; i++) {
        if (text[i] === '\\') { i++; continue; }
        if (text[i] === '"') break;
      }
      const frame = stack.at(-1);
      if (frame?.type === 'object' && frame.expectingKey) {
        const key = JSON.parse(text.slice(start, i + 1));
        if (frame.keys.has(key)) return true;
        frame.keys.add(key);
      }
    }
  }
  return false;
}

export function readJson(path, maxBytes) {
  if (statSync(path).size > maxBytes) throw new Error('input limit');
  const bytes = readFileSync(path);
  if (bytes.length > maxBytes) throw new Error('input limit');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = JSON.parse(text);
  if (duplicateKeys(text)) throw new Error('ambiguous JSON');
  return value;
}
