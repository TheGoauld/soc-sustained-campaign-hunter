#!/usr/bin/env node
// Starts server.mjs and talks MCP to it over stdio, the way Claude Code does.
//
//   node evals/generic/server/smoke.mjs

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const server = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', fileURLToPath(new URL('./server.mjs', import.meta.url))], { stdio: ['pipe', 'pipe', 'inherit'] });
const pending = new Map();
createInterface({ input: server.stdout }).on('line', (line) => {
  const msg = JSON.parse(line);
  pending.get(msg.id)?.(msg);
});
let nextId = 1;
const call = (method, params) => new Promise((resolve) => {
  const id = nextId++;
  pending.set(id, resolve);
  server.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
});
const tool = async (name, args) => (await call('tools/call', { name, arguments: args })).result;

let failed = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); if (!ok) failed++; };

const init = await call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } });
check('initialize', init.result?.capabilities?.tools !== undefined, init.result?.serverInfo?.name);
server.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);

const list = await call('tools/list', {});
check('tools/list names both tools', list.result.tools.map((t) => t.name).join(',') === 'list_sources,run_query');

const sources = JSON.parse((await tool('list_sources', {})).content[0].text);
check('list_sources returns 8 environments', sources.environments.length === 8, sources.environments.map((e) => e.name).join(', '));
const litware = sources.environments.find((e) => e.name === 'litware');
check('litware has only the sign-in table', litware.tables.length === 1 && litware.tables[0].name === 'idp_signins');

const ok = await tool('run_query', { environment: 'northwind', window: '30d', query: "SELECT count(DISTINCT source_ip) ips FROM idp_signins WHERE user_agent = 'python-requests/2.32.3'" });
const okBody = JSON.parse(ok.content[0].text);
check('run_query returns rows', !ok.isError && okBody.rows[0].ips === 55, ok.content[0].text.slice(0, 160));

const write = await tool('run_query', { environment: 'northwind', query: 'DROP TABLE idp_signins' });
check('run_query refuses a write as a tool error', write.isError === true, write.content[0].text);

const bad = await tool('run_query', { environment: 'nowhere', query: 'SELECT 1' });
check('run_query rejects an unknown environment', bad.isError === true, bad.content[0].text.slice(0, 80));

const sqlErr = await tool('run_query', { environment: 'northwind', query: 'SELECT nope FROM idp_signins' });
check('run_query reports SQL errors as tool errors', sqlErr.isError === true, sqlErr.content[0].text);

const clamp = JSON.parse((await tool('run_query', { environment: 'proseware-fw', window: '60d', query: 'SELECT count(*) n FROM firewall' })).content[0].text);
check('run_query notes a window clamped to the cap', (clamp.notes ?? []).some((n) => n.includes('14-day cap')), JSON.stringify(clamp.notes));

server.stdin.end();
console.log(failed ? `\n${failed} check(s) failed` : '\nAll checks passed');
process.exit(failed ? 1 : 0);
