#!/usr/bin/env node
// Local MCP server (stdio) for the hunter evals: a read-only SQL query service over
// synthetic logs. No network access, no files written, no dependencies beyond Node 22.13+.

import { createInterface } from 'node:readline';
import { openService, listSources, runQuery, UserError, DIALECT } from './engine.mjs';

const service = openService();
const envNames = [...service.envs.keys()];

const TOOLS = [
  {
    name: 'list_sources',
    description: 'List the environments and, for each, its tables with columns, row counts, earliest and latest event time, and lookback cap in days. Pass an environment to describe just that one.',
    inputSchema: { type: 'object', properties: { environment: { type: 'string', enum: envNames } }, additionalProperties: false },
  },
  {
    name: 'run_query',
    description: `Run one read-only query against one environment. ${DIALECT}`,
    inputSchema: {
      type: 'object',
      properties: {
        environment: { type: 'string', enum: envNames },
        query: { type: 'string', description: 'One SQLite SELECT statement.' },
        window: { type: 'string', description: 'Time range back from now, for example "30d", "3d", "1d" or "2h".' },
        start: { type: 'string', description: 'Start of the time range, ISO 8601 UTC. Overrides window.' },
        end: { type: 'string', description: 'End of the time range, ISO 8601 UTC. Defaults to now.' },
      },
      required: ['environment', 'query'],
      additionalProperties: false,
    },
  },
];

const send = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);

function callTool(name, args = {}) {
  try {
    const result = name === 'list_sources' ? listSources(service, args.environment) : name === 'run_query' ? runQuery(service, args) : null;
    if (!result) return { content: [{ type: 'text', text: `Unknown tool "${name}".` }], isError: true };
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  } catch (e) {
    const text = e instanceof UserError ? e.message : `Internal error: ${e.message}`;
    return { content: [{ type: 'text', text }], isError: true };
  }
}

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method, params } = msg;
  if (method === 'initialize') {
    send({ jsonrpc: '2.0', id, result: { protocolVersion: params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'hunt-sql-eval', version: '1.0.0' } } });
  } else if (typeof method === 'string' && method.startsWith('notifications/')) {
    // nothing to do
  } else if (method === 'ping') {
    send({ jsonrpc: '2.0', id, result: {} });
  } else if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
  } else if (method === 'tools/call') {
    send({ jsonrpc: '2.0', id, result: callTool(params?.name, params?.arguments) });
  } else if (id !== undefined) {
    send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
});
rl.on('close', () => process.exit(0));
