#!/usr/bin/env node
// Copies the platform-neutral agent from the repo root into this eval plugin and
// points its tools: line at the eval query service. Run it before every eval run,
// so the suite always tests the agent file as it is in the repo.
//
//   node evals/generic/build.mjs

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const AGENT = 'soc-sustained-campaign-hunter-generic.md';
const TOOLS = 'tools: mcp__plugin_huntgen_sql__run_query, mcp__plugin_huntgen_sql__list_sources, Write';

const src = new URL(`../../${AGENT}`, import.meta.url);
const lines = readFileSync(src, 'utf8').split(/\r?\n/);
if (lines[0] !== '---') throw new Error(`${AGENT}: front matter not found`);
const close = lines.indexOf('---', 1);
if (close < 0) throw new Error(`${AGENT}: front matter is not closed`);

const front = lines.slice(1, close).filter((l) => !l.startsWith('# Replace run_query'));
const toolsAt = front.findIndex((l) => l.startsWith('tools:'));
if (toolsAt < 0) throw new Error(`${AGENT}: no tools: line in the front matter`);
front[toolsAt] = TOOLS;

const out = ['---', ...front, ...lines.slice(close)].join('\n');
mkdirSync(new URL('./agents/', import.meta.url), { recursive: true });
writeFileSync(new URL(`./agents/${AGENT}`, import.meta.url), out);
console.log(`built agents/${AGENT} with ${TOOLS}`);
