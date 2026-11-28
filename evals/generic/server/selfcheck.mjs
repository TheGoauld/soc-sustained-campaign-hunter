#!/usr/bin/env node
// Checks that the synthetic data holds each scenario at the agent's documented
// thresholds, and that each benign look-alike falls outside them. Runs reference
// SQL written from the agent's specs; no model and no network involved.
//
//   node evals/generic/server/selfcheck.mjs

import { openService, runQuery } from './engine.mjs';

const svc = openService();
let failed = 0;

function q(environment, window, query) {
  return runQuery(svc, { environment, window, query }).rows;
}

function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
  if (!ok) failed++;
}

const REJECTED = "('50126','50053','50034','50056','50057')";
const UA_FAMILY = "CASE WHEN user_agent LIKE 'Mozilla/%' THEN substr(user_agent,1,140) ELSE substr(user_agent,1,instr(user_agent||' ',' ')-1) END";

// 3a profile table
const profiles = (env) => q(env, '30d', `
  SELECT client_app, ${UA_FAMILY} AS ua_family, count(*) n, count(DISTINCT user_name) users,
         count(DISTINCT source_ip) ips, count(DISTINCT substr(ts,1,10)) days
  FROM idp_signins
  WHERE result_code IN ${REJECTED}
    AND source_ip NOT IN (SELECT source_ip FROM idp_signins WHERE result_code = '0')
  GROUP BY 1, 2 HAVING ips >= 15 AND days >= 3 ORDER BY n DESC`);

const nw = profiles('northwind');
check('northwind 3a: python-requests spray on Azure CLI is a profile', nw.some((r) => r.client_app === 'Microsoft Azure CLI' && r.ua_family === 'python-requests/2.32.3'), JSON.stringify(nw.map((r) => [r.ua_family, r.ips, r.days])));
check('northwind 3a: no other profile qualifies', nw.length === 1);
check('fabrikam 3a: no profile qualifies (benign only)', profiles('fabrikam').length === 0);
check('litware 3a: no profile qualifies (benign only)', profiles('litware').length === 0);
const wg = profiles('woodgrove');
check('woodgrove 3a: spray with injected user agent still forms a profile', wg.some((r) => r.ua_family === 'python-requests/2.32.3'), JSON.stringify(wg.map((r) => [r.ua_family, r.ips, r.days])));

// 3b-2 accepted-credential leg
const ACCEPTED = "('50076','50074','50079','50072','50105','53003','53004','530031','50097','50133','70044','700082')";
const accepted = (env) => q(env, '30d', `
  SELECT client_app, ${UA_FAMILY} AS ua_family, count(*) n, count(DISTINCT source_ip) ips, group_concat(DISTINCT result_code) codes
  FROM idp_signins
  WHERE result_code IN ${ACCEPTED}
    AND source_ip NOT IN (SELECT source_ip FROM idp_signins WHERE result_code = '0')
  GROUP BY 1, 2 HAVING ips >= 3`);
const acc = accepted('northwind');
check('northwind 3b-2: 530031 policy refusals from 3+ never-successful addresses', acc.some((r) => r.ua_family === 'python-requests/2.32.3' && r.codes.includes('530031')), JSON.stringify(acc));
check('fabrikam 3b-2: MFA enrolment from the office does not qualify', accepted('fabrikam').length === 0);

// 3b ladder: no success for the attacker profile
const ladder = q('northwind', '30d', `SELECT result_code, count(*) n FROM idp_signins WHERE client_app = 'Microsoft Azure CLI' AND user_agent = 'python-requests/2.32.3' GROUP BY 1`);
check('northwind 3b: attacker profile never reaches rung 2', !ladder.some((r) => r.result_code === '0'), JSON.stringify(ladder));

// 3a-2 slow single-address testers
const slow = q('northwind', '30d', `
  SELECT source_ip, sum(result_code = '0') ok, sum(result_code IN ${REJECTED}) fails,
         count(DISTINCT user_name) users, count(DISTINCT substr(ts,1,10)) days
  FROM idp_signins GROUP BY source_ip
  HAVING ok = 0 AND days >= 5 AND users >= 5 AND fails >= 8 AND fails <= days * 6`);
check('northwind 3a-2: slow headless tester 192.0.2.200 qualifies', slow.some((r) => r.source_ip === '192.0.2.200'));
check('northwind 3a-2: stale phone 192.0.2.177 does not qualify', !slow.some((r) => r.source_ip === '192.0.2.177'));

// 5 application credentials
const outsiders = q('contoso-apps', '30d', `
  SELECT f.app_name, f.source_ip, count(*) n FROM app_signins f
  WHERE f.result_code IN ('7000215','7000222')
    AND NOT EXISTS (SELECT 1 FROM app_signins s WHERE s.result_code = '0' AND s.app_id = f.app_id AND s.source_ip = f.source_ip)
  GROUP BY 1, 2`);
const has = (app, ip) => outsiders.some((r) => r.app_name === app && r.source_ip === ip);
check('contoso-apps 5: Backup Reporter outsider 198.51.100.150', has('Backup Reporter', '198.51.100.150'));
check('contoso-apps 5: Finance Export outsider 198.51.100.170', has('Finance Export', '198.51.100.170'));
check('contoso-apps 5: TruffleHog on Marketing Site Uploader', has('Marketing Site Uploader', '198.51.100.160'));
check('contoso-apps 5: Acme Ticketing stale client 192.0.2.90', has('Acme Ticketing', '192.0.2.90'));
check('contoso-apps 5: Payroll Connector daily expired-secret failures', has('Payroll Connector', '203.0.113.21'));
const newSuccess = q('contoso-apps', '30d', `SELECT count(*) n FROM app_signins WHERE app_name = 'Finance Export' AND result_code = '0' AND source_ip = '198.51.100.171'`);
check('contoso-apps 5: Finance Export succeeds later from new address 198.51.100.171', newSuccess[0].n === 2);
const rotation = q('contoso-apps', '30d', `SELECT target_name FROM directory_audit WHERE operation LIKE '%Certificates and secrets%'`);
check('contoso-apps 5: only Payroll Connector had a secrets change', rotation.length === 1 && rotation[0].target_name === 'Payroll Connector');

// 6d source fan-out
const PUBLIC = "NOT ip_is_private(client_ip) AND NOT cidr_match(client_ip,'100.64.0.0/10') AND client_ip NOT LIKE '127.%' AND client_ip <> '::1'";
const fan = q('adventure-web', '1d', `
  SELECT client_ip, count(*) miss, count(DISTINCT site) sites, count(DISTINCT user_agent) uas
  FROM web_access WHERE status IN (404,401,403) AND ${PUBLIC}
  GROUP BY client_ip HAVING sites >= 5 ORDER BY sites DESC`);
const src = fan.find((r) => r.client_ip === '198.51.100.200');
check('adventure-web 6d: 198.51.100.200 is a fan-out source (20+ sites)', src && src.sites >= 20, JSON.stringify(src));
check('adventure-web 6d: it presents several client strings', src && src.uas >= 4);
check('adventure-web 6d: no other address reaches 20 sites', fan.filter((r) => r.sites >= 20).length === 1, JSON.stringify(fan.slice(0, 5)));

// 6d one client, several addresses
const shared = q('adventure-web', '1d', `
  SELECT site, substr(ts,1,15) AS bin, count(DISTINCT client_ip) srcs FROM web_access
  WHERE client_ip IN ('198.51.100.200','198.51.100.201') GROUP BY 1, 2 HAVING srcs >= 2`);
check('adventure-web 6d: the two addresses share 3+ windows on 2+ sites', shared.length >= 3 && new Set(shared.map((r) => r.site)).size >= 2, `${shared.length} windows`);

// 6c slow enumeration
const enumRows = q('adventure-web', '1d', `
  SELECT site, client_ip, count(*) miss, count(DISTINCT uri_path) paths, count(DISTINCT substr(ts,1,19)) secs,
         CAST((julianday(max(ts)) - julianday(min(ts))) * 86400 AS INTEGER) span
  FROM web_access WHERE status IN (404,401,403) AND ${PUBLIC}
  GROUP BY site, client_ip HAVING paths >= 30 AND span >= 1800 AND secs * 20 <= span`);
check('adventure-web 6c: slow enumeration of site07 by 198.51.100.200', enumRows.some((r) => r.site === 'site07.adventure.example' && r.client_ip === '198.51.100.200'), JSON.stringify(enumRows));
check('adventure-web 6c: the gobuster wordlist run is not a slow enumeration', !enumRows.some((r) => r.client_ip === '192.0.2.160'));

// 6c pause structure on site07 (window-function cadence)
const cadence = q('adventure-web', '1d', `
  WITH s AS (SELECT DISTINCT substr(ts,1,19) sec FROM web_access WHERE site = 'site07.adventure.example' AND client_ip = '198.51.100.200' AND uri_path NOT IN ('/', '/.well-known/security.txt', '/swagger.json', '/graphql', '/api/health', '/actuator/health', '/api/v1/users') ),
       g AS (SELECT (julianday(sec) - julianday(LAG(sec) OVER (ORDER BY sec))) * 86400 gap FROM s)
  SELECT count(*) active, sum(gap >= 10) p10, sum(gap >= 60) p60 FROM g`);
check('adventure-web 6c: pause structure (10+ pauses of 10s, 3+ of 60s)', cadence[0].p10 >= 10 && cadence[0].p60 >= 3, JSON.stringify(cadence[0]));

// 6a shape lead: stale browser look-alike
const stale = q('adventure-web', '1d', `
  SELECT client_ip, count(*) n, sum(status IN (404,401,403)) miss, count(DISTINCT uri_path) paths
  FROM web_access WHERE user_agent LIKE '%Chrome/1__.%' AND user_agent NOT LIKE '%HeadlessChrome%'
    AND CAST(substr(user_agent, instr(user_agent,'Chrome/')+7, 3) AS INTEGER) BETWEEN 1 AND 136 AND ${PUBLIC}
  GROUP BY client_ip HAVING miss * 2 >= n AND paths >= 10`);
check('adventure-web 6a: stale Chrome 120 look-alike from 198.51.100.200', stale.some((r) => r.client_ip === '198.51.100.200'), JSON.stringify(stale));

// 6b configuration file served by a single-page app: same size as unknown paths
const spa = q('adventure-web', '3d', `
  SELECT DISTINCT bytes FROM web_access WHERE site = 'site12.adventure.example' AND status = 200 AND uri_path IN ('/.git/config', '/.env', '/this-page-does-not-exist-404-check', '/swagger.json')`);
check('adventure-web 6b: site12 answers .git/config with its app shell size', spa.length === 1 && spa[0].bytes === 5123, JSON.stringify(spa));

// 6a host markers
const artex = q('tailspin-hosts', '7d', `
  SELECT device, count(*) n FROM edr_process
  WHERE (command_line REGEXP '(^|[^a-z0-9])artex([^a-z0-9]|$)' AND command_line REGEXP '(^|[^a-z0-9])-addr([^a-z0-9]|$)' AND command_line REGEXP '(^|[^a-z0-9])-proxy([^a-z0-9]|$)')
     OR command_line REGEXP '/data/tasks/[0-9]+/i[0-9]+'
  GROUP BY device`);
check('tailspin-hosts 6a: ARTEX marker only on lab-runner-07', artex.length === 1 && artex[0].device === 'lab-runner-07', JSON.stringify(artex));
const osprobe = q('tailspin-hosts', '7d', `SELECT sum(instr(upper(command_line),'OSPROBE_') > 0) strict, sum(upper(command_line) LIKE '%OSPROBE%') loose FROM edr_process`);
check('tailspin-hosts 6a: monitoring OsProbe script does not match OSPROBE_', osprobe[0].strict === 0 && osprobe[0].loose > 0, JSON.stringify(osprobe[0]));
const children = q('tailspin-hosts', '7d', `SELECT group_concat(DISTINCT process) tools FROM edr_process WHERE parent IN ('artex','antifox') OR grandparent IN ('artex','antifox')`);
check('tailspin-hosts 6a: tools run under the artex server process', /curl/.test(children[0].tools) && /python3/.test(children[0].tools), children[0].tools);
const viaAgent = q('tailspin-hosts', '7d', `
  SELECT device, process FROM edr_process
  WHERE lower(replace(process,'.exe','')) IN ('nmap','httpx','curl','sqlmap','nuclei','ffuf')
    AND (lower(replace(parent,'.exe','')) IN ('claude','codex','qwen','kimi','opencode','hermes','artex','antifox')
      OR lower(replace(grandparent,'.exe','')) IN ('claude','codex','qwen','kimi','opencode','hermes','artex','antifox'))`);
check('tailspin-hosts 6a: the cron nmap compliance scan is not under an agent', !viaAgent.some((r) => r.device === 'app-srv-02'));
check('tailspin-hosts 6a: attack tools under artex on lab-runner-07', viaAgent.some((r) => r.device === 'lab-runner-07'));
const oob = q('tailspin-hosts', '7d', `SELECT device, process FROM edr_network WHERE remote_host REGEXP '(^|[^a-z0-9])oast\\.fun$'`);
check('tailspin-hosts 6a: w3wp.exe on web-iis-03 calls an out-of-band callback host', oob.length === 1 && oob[0].process === 'w3wp.exe', JSON.stringify(oob));
const pairing = q('tailspin-hosts', '7d', `
  SELECT device, count(DISTINCT CASE WHEN remote_host IN ('crt.sh','rdap.org','api.pdtm.sh') THEN remote_host END) recons,
         count(DISTINCT CASE WHEN remote_host = 'api.anthropic.com' THEN remote_host END) models
  FROM edr_network GROUP BY device, substr(ts,1,10) HAVING recons >= 2 AND models >= 1`);
check('tailspin-hosts 6a: recon sources next to a model API only on lab-runner-07', pairing.length >= 1 && pairing.every((r) => r.device === 'lab-runner-07'), JSON.stringify(pairing));

// 7.9 management protocols answering the internet
const PUB_DST = "NOT ip_is_private(dst_ip) AND NOT cidr_match(dst_ip,'100.64.0.0/10') AND NOT cidr_match(dst_ip,'169.254.0.0/16')";
const snmp = q('proseware-fw', '7d', `
  SELECT src_ip, count(DISTINCT dst_ip) dsts, count(DISTINCT substr(ts,1,10)) days FROM firewall
  WHERE src_port IN (161,623,1900,11211) AND lower(action) IN ('allow','accept','permit','built','pass')
    AND (app_protocol REGEXP '(^|[^a-z0-9])(snmp|ipmi|ssdp|memcache)([^a-z0-9]|$)' OR (coalesce(app_protocol,'') = '' AND lower(protocol) IN ('udp','17')))
    AND ip_is_private(src_ip) AND ${PUB_DST}
  GROUP BY src_ip HAVING dsts >= 3`);
check('proseware-fw 7.9: 10.20.30.40 answers SNMP to 7 external addresses', snmp.length === 1 && snmp[0].src_ip === '10.20.30.40' && snmp[0].dsts === 7, JSON.stringify(snmp));
const trap = q('proseware-fw', '7d', `SELECT count(*) n FROM firewall WHERE src_ip IN ('10.20.1.55','10.20.1.56') AND src_port IN (161,1900)`);
check('proseware-fw 7.9: the ephemeral-port client sessions exist and are filtered out', trap[0].n === 10);

// Engine guardrails
const refuse = (sql) => { try { runQuery(svc, { environment: 'northwind', query: sql }); return false; } catch { return true; } };
check('engine: refuses writes', refuse('DELETE FROM idp_signins') && refuse('SELECT 1; DROP TABLE idp_signins') && refuse("WITH x AS (SELECT 1) INSERT INTO idp_signins(ts) VALUES ('x')"));
check('engine: accepts semicolons inside string literals', !refuse("SELECT count(*) n FROM idp_signins WHERE user_agent LIKE '%Windows NT 10.0; Win64%'"));
const narrow = runQuery(svc, { environment: 'northwind', window: '1d', query: 'SELECT min(ts) t FROM idp_signins' }).rows[0].t;
check('engine: the window limits every table', Date.parse(narrow) >= svc.now - 86_400_000, narrow);

console.log(failed ? `\n${failed} check(s) failed` : '\nAll checks passed');
process.exit(failed ? 1 : 0);
