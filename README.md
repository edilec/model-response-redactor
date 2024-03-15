# Model Response Redactor

An offline, dependency-free reporter that applies an explicit local policy to a saved JSON model trace. It produces a structurally preserved, redacted copy and non-sensitive counts. It never sends the trace to a model, service, or database, and never edits the original.

## Quick start

Node 22+; no installation or network required.

```sh
node bin/model-response-redactor.mjs --trace examples/clean-trace.json --policy examples/policy.json
node bin/model-response-redactor.mjs --trace examples/trace.json --policy examples/policy.json
npm run check
```

The first command exits 0; the second exits 1 because it found and replaced a synthetic token and address in nested tool output. Both emit one JSON report with `redactedTrace`, `summary`, `counts`, and `findings`. To save a redacted copy, provide `--root DIR --out NEW_FILE` with both trace and policy inside that root. The output must not exist. The root confines reads and writes after resolving symlinks; a symlink at the output, a parent symlink escaping the root, an existing file and a hard link to either input are refused. No source is overwritten.

Library callers may import `redactTrace` and `TOOL_ID` from `src/index.mjs`.

## Input and policy

Trace: UTF-8 JSON `{ "schemaVersion": 1, "messages": [{ "role": "user", "content": "..." }] }`. Roles are `system`, `developer`, `user`, `assistant` or `tool`; content may be a string, object or array, including nested tool outputs and error objects. Other fields are traversed as well. Message role and order are preserved; all other string values are considered for replacement. If a sensitive match occurs in an object key, the run is incomplete and emits no redacted trace rather than changing the key or leaking it.

Policy: UTF-8 JSON `{ "schemaVersion": 1, "rules": [{ "id": "token", "type": "literal", "value": "SYNTHETIC_SECRET_123" }, { "id": "email", "type": "email" }] }`. `literal` is an exact case-sensitive substring; `email` is a conservative ASCII address pattern. No arbitrary regular expressions or implicit detectors are accepted. The fixed replacement is `[REDACTED]`. When matches overlap, the longest span at the earliest position wins; counts identify only the chosen rules. Caller-supplied IDs must be non-sensitive. This tool only attests that the configured detectors ran; no detector can establish that *all* sensitive data is absent.

## Rules

| Rule | Meaning |
| --- | --- |
| `sensitive-span` | One or more configured spans were replaced; status `fail`. |
| `invalid-trace`, `invalid-message`, `unrenderable-trace`, `unreadable-trace` | Required input cannot safely be processed; status `incomplete`, no redacted trace or output file. |

## Exit codes and limits

| Exit | Meaning |
| --- | --- |
| 0 | Complete scan with no configured matches (`pass`). |
| 1 | Complete scan with replacements (`fail`); output is redacted. |
| 2 | Incomplete trace (JSON report), or invalid policy/options/output destination (empty stdout). |

Default trace limit: 2,097,152 bytes; `--max-bytes` accepts 1–10,485,760. Policy limit: 65,536 bytes. Library limits: 1,000 messages, 16 nesting levels, 65,536 characters per string, 256 characters per object key, 100,000 traversed nodes and 32 policy rules. Exact N is admitted; N+1 is refused. Invalid UTF-8 and duplicate JSON keys are rejected without echoing input. Reports contain counts, rules and the transformed trace, never the configured literal value.

## Non-goals

No live interception, account action, irreversible deletion, broad personal-data discovery, arbitrary regex execution, or certification that undetected secrets are safe. Review the policy and downstream handling of the redacted copy before sharing it.
