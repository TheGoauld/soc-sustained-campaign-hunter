// Read-only query engine for the hunter evals: one in-memory SQLite database per
// environment, built from dataset.mjs. Every query sees each table limited to the
// time range the caller passes, the way a SIEM query tool applies its time picker.

import { DatabaseSync } from 'node:sqlite';
import { buildEnvironments, SCHEMAS, TABLE_INFO, D } from './dataset.mjs';

export const MAX_ROWS = 100;
const M_ = 60_000;

export class UserError extends Error {}

export const DIALECT = [
  'SQLite 3 SQL. Send one read-only SELECT (or WITH ... SELECT) per call.',
  'The time range you pass limits every table in the query: window like "30d", "3d", "1d" or "2h", or start/end in ISO 8601 UTC. Without one, the last 1 day is used. Each table also has its own lookback cap.',
  'ts columns are ISO 8601 UTC text: day = substr(ts,1,10), hour of day = substr(ts,12,2), one-second bin = substr(ts,1,19), seconds between two times = (julianday(b)-julianday(a))*86400.',
  'LIKE is case-insensitive for ASCII. x REGEXP \'pattern\' is a case-insensitive JavaScript regular expression. instr() is case-sensitive.',
  'Extra functions: ip_is_private(ip) is 1 for RFC 1918 and fc00::/7 addresses; cidr_match(ip, \'cidr\') works for IPv4 and IPv6. Window functions (LAG, ROW_NUMBER) are available.',
  `At most ${MAX_ROWS} rows come back; aggregate first.`,
].join(' ');

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

// ---------------------------------------------------------------- address helpers

function v4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function v6(ip) {
  if (!ip.includes(':')) return null;
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(parts.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    v = (v << 16n) + BigInt(parseInt(g, 16));
  }
  return v;
}

export function cidrMatch(ip, cidr) {
  if (typeof ip !== 'string' || typeof cidr !== 'string') return false;
  const [net, bitsText] = cidr.trim().split('/');
  const a4 = v4(ip.trim());
  const n4 = v4(net);
  if (a4 !== null && n4 !== null) {
    const bits = bitsText === undefined ? 32 : Number(bitsText);
    if (!(bits >= 0 && bits <= 32)) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((a4 & mask) >>> 0) === ((n4 & mask) >>> 0);
  }
  const a6 = v6(ip.trim());
  const n6 = v6(net);
  if (a6 !== null && n6 !== null) {
    const bits = bitsText === undefined ? 128 : Number(bitsText);
    if (!(bits >= 0 && bits <= 128)) return false;
    const all = (1n << 128n) - 1n;
    const mask = bits === 0 ? 0n : all ^ ((1n << BigInt(128 - bits)) - 1n);
    return (a6 & mask) === (n6 & mask);
  }
  return false;
}

const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'];
export const isPrivate = (ip) => PRIVATE.some((c) => cidrMatch(ip, c));

function registerFunctions(db) {
  const cache = new Map();
  db.function('regexp', { deterministic: true }, (pattern, value) => {
    if (value === null || value === undefined || pattern === null) return 0;
    let re = cache.get(pattern);
    if (!re) {
      try { re = new RegExp(String(pattern), 'i'); } catch (e) { throw new Error(`bad REGEXP pattern: ${e.message}`); }
      cache.set(pattern, re);
    }
    return re.test(String(value)) ? 1 : 0;
  });
  db.function('ip_is_private', { deterministic: true }, (ip) => (isPrivate(ip) ? 1 : 0));
  db.function('cidr_match', { deterministic: true }, (ip, cidr) => (cidrMatch(ip, cidr) ? 1 : 0));
}

// ---------------------------------------------------------------- read-only guard

function stripLiterals(sql) {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    const n = sql[i + 1];
    if (c === "'" || c === '"' || c === '`') {
      i++;
      while (i < sql.length) {
        if (sql[i] === c) {
          if (sql[i + 1] === c) { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      out += ' x ';
    } else if (c === '[') {
      const j = sql.indexOf(']', i);
      i = j < 0 ? sql.length : j + 1;
      out += ' x ';
    } else if (c === '-' && n === '-') {
      const j = sql.indexOf('\n', i);
      i = j < 0 ? sql.length : j + 1;
      out += ' ';
    } else if (c === '/' && n === '*') {
      const j = sql.indexOf('*/', i + 2);
      i = j < 0 ? sql.length : j + 2;
      out += ' ';
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

export function readOnlyProblem(sql) {
  const bare = stripLiterals(sql).trim().replace(/;\s*$/, '');
  if (!bare) return 'The query is empty.';
  if (bare.includes(';')) return 'Send one statement per call.';
  if (!/^(select|with|values|\()/i.test(bare)) return 'Only read-only queries are accepted: SELECT, or WITH ... SELECT.';
  const bad = /\b(insert|update|delete|drop|create|alter|attach|detach|pragma|vacuum|reindex|analyze)\b|\breplace\b(?!\s*\()/i.exec(bare);
  if (bad) return `Only read-only queries are accepted (found "${bad[0]}").`;
  return null;
}

// ---------------------------------------------------------------- service

export function openService(now = new Date()) {
  const nowMs = Math.floor(now.getTime() / M_) * M_;
  const envs = new Map();
  for (const [name, env] of Object.entries(buildEnvironments(nowMs))) {
    const db = new DatabaseSync(':memory:');
    registerFunctions(db);
    db.exec("ATTACH DATABASE ':memory:' AS raw");
    const tables = [];
    for (const [table, rows] of Object.entries(env.tables)) {
      const cols = SCHEMAS[table];
      db.exec(`CREATE TABLE raw."${table}" (${cols.map(([c, t]) => `"${c}" ${t}`).join(', ')})`);
      const insert = db.prepare(`INSERT INTO raw."${table}" VALUES (${cols.map(() => '?').join(', ')})`);
      db.exec('BEGIN');
      for (const row of rows) insert.run(...cols.map(([c]) => row[c] ?? null));
      db.exec('COMMIT');
      tables.push({ name: table, rows: rows.length, earliest: rows[0]?.ts ?? null, latest: rows.at(-1)?.ts ?? null });
    }
    envs.set(name, { name, description: env.description, db, tables });
  }
  return { now: nowMs, envs };
}

function resolveWindow(nowMs, { window, start, end }) {
  const endMs = end ? Date.parse(end) : nowMs + M_;
  let startMs;
  if (start) {
    startMs = Date.parse(start);
  } else {
    const w = window ?? '1d';
    const m = /^(\d+(?:\.\d+)?)\s*(m|h|d)$/i.exec(String(w).trim());
    if (!m) throw new UserError(`window must look like 30d, 3d, 1d, 2h or 15m (got "${w}")`);
    startMs = endMs - Number(m[1]) * { m: M_, h: 3_600_000, d: D }[m[2].toLowerCase()];
  }
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) throw new UserError('start and end must be ISO 8601 times, for example 2026-11-20T00:00:00Z');
  if (startMs >= endMs) throw new UserError('start must be before end');
  return { startMs, endMs };
}

export function listSources(service, environment) {
  const pick = environment ? [service.envs.get(environment)] : [...service.envs.values()];
  if (pick.some((e) => !e)) throw new UserError(`Unknown environment "${environment}". Known: ${[...service.envs.keys()].join(', ')}`);
  return {
    now: iso(service.now),
    dialect: DIALECT,
    environments: pick.map((e) => ({
      name: e.name,
      description: e.description,
      tables: e.tables.map((t) => ({
        name: t.name,
        description: TABLE_INFO[t.name].description,
        cap_days: TABLE_INFO[t.name].cap_days,
        rows: t.rows,
        earliest: t.earliest,
        latest: t.latest,
        columns: SCHEMAS[t.name].map(([name, type]) => ({ name, type })),
      })),
    })),
  };
}

export function runQuery(service, { environment, query, window, start, end }) {
  const env = service.envs.get(environment);
  if (!env) throw new UserError(`Unknown environment "${environment}". Known: ${[...service.envs.keys()].join(', ')}`);
  if (typeof query !== 'string') throw new UserError('query must be a string');
  const problem = readOnlyProblem(query);
  if (problem) throw new UserError(problem);
  const { startMs, endMs } = resolveWindow(service.now, { window, start, end });

  const notes = [];
  env.db.exec('PRAGMA query_only = OFF');
  for (const t of env.tables) {
    const capStart = service.now - TABLE_INFO[t.name].cap_days * D;
    const lo = Math.max(startMs, capStart);
    if (startMs < capStart && new RegExp(`\\b${t.name}\\b`, 'i').test(query)) notes.push(`${t.name}: window clamped to its ${TABLE_INFO[t.name].cap_days}-day cap`);
    env.db.exec(`DROP VIEW IF EXISTS temp."${t.name}"`);
    env.db.exec(`CREATE TEMP VIEW "${t.name}" AS SELECT * FROM raw."${t.name}" WHERE ts >= '${iso(lo)}' AND ts < '${iso(endMs)}'`);
  }
  env.db.exec('PRAGMA query_only = ON');

  let rows;
  try {
    rows = env.db.prepare(query.trim().replace(/;\s*$/, '')).all();
  } catch (e) {
    throw new UserError(`SQL error: ${e.message}`);
  }
  return {
    environment,
    window: { start: iso(startMs), end: iso(endMs) },
    row_count: rows.length,
    truncated: rows.length > MAX_ROWS,
    ...(notes.length ? { notes } : {}),
    rows: rows.slice(0, MAX_ROWS),
  };
}
