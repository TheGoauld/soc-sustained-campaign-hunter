# soc-sustained-campaign-hunter

A Claude Code subagent that hunts your logs for two things that per-IP and per-day rules miss:

- **Sustained campaigns.** One operator's pressure on one target set, stitched across rotating source addresses and across weeks: low-and-slow password spray, testing of a leaked application secret, a source that stays on a few destinations.
- **AI agent attack frameworks.** The published markers of tools such as ARTEX, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent and Agent Zero. More usefully, it also looks for what an agent-driven attack does, whichever framework is driving it.

It only detects. It runs read-only queries and writes a report, and it changes nothing in your environment.

## Two editions

| File | For | Queries |
|---|---|---|
| [`soc-sustained-campaign-hunter.md`](soc-sustained-campaign-hunter.md) | Microsoft Sentinel / Log Analytics | Literal KQL over the Microsoft tables. These have run on live data, apart from the few the file names. |
| [`soc-sustained-campaign-hunter-generic.md`](soc-sustained-campaign-hunter-generic.md) | Any SIEM or log platform: Splunk, Elastic, Google SecOps, Sumo Logic, a security data lake, or Sentinel | Each query is a precise spec. At the start of a run, the agent maps your platform's fields and your identity provider's result codes, then writes every query in your platform's language. |

Both editions share the same lanes, thresholds and grading. The generic edition's queries are new on every platform, so treat its first run as a test of the translation. On a platform's first run it writes every query it used into the report, so you can keep them as a query pack.

## Where this comes from

This is based on my own testing with ARTEX, an agentic attack framework. I ran it under authorization, recorded what its traffic actually looks like on the wire and on the host it runs from, and rebuilt the agent-framework lane around those measurements instead of around published indicators. Then I ran the agent through my own SOC against live Sentinel workspaces and tuned the queries and thresholds on what came back, false positives included. The generic edition is a translation of that tested Sentinel edition.

What the measurements changed:

- **Marker strings caught almost none of the real traffic.** The model invents its own client names, often from the words of its task, and types browser strings with the version it remembers rather than a current one. The agent looks for those shapes instead of a fixed list.
- **Sessions were mostly `404`s, not `401`s.** An agent with no application bundle to read guesses paths a few at a time and pauses to think between them.
- **One session used several client strings,** so grouping by user agent splits it. The agent groups by client address.
- **The widest activity was a few requests on each of many sites.** No single site sees enough to notice. Only a count per source across sites shows it.

The signature lists started from ThreatDefence's [agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections) (MIT), with later additions from November 2026 vendor reports of ARTEX intrusions. The ThreatDefence notice is at the end of each agent file.

## What it does

| Lane | Looks for |
|---|---|
| Identity | Spray campaigns stitched by tool profile (application plus user agent) over 30 days; slow single-address testers; correct passwords used from addresses that never succeed, including sign-ins refused by policy after the password was accepted; invented client IDs |
| Application credentials | Failed application-secret sign-ins from outsiders, meaning a leaked secret is being tested; activity of application IDs named in an advisory |
| Agent framework | Markers and leads in sign-in, directory, web, gateway, firewall, process and network logs; behaviors the frameworks share (relayed MFA, an app granting itself access, exposed config files); application walks; one source fanning out across many sites |
| Perimeter | Destinations under focused pressure from rotating sources; high-severity signatures that were allowed through; internal devices answering SNMP, IPMI, SSDP or memcached to the internet |

Every campaign is graded on four separate axes: **Sustained**, **Adaptive**, **Progress** (how far up the credential ladder it got) and **Agentic**. The benign reading is tested before anything is reported, and anything that reached a correct credential is reported first.

## Requirements

- Claude Code, or another harness that loads Claude Code subagent files.
- **Sentinel edition:** a read-only tool that runs KQL against a Sentinel / Log Analytics workspace over a time window you give it. Examples: the Azure MCP Server's Log Analytics query tool, the Microsoft Sentinel MCP server, or your own wrapper. Optionally, a tool that lists workspaces.
- **Generic edition:** a read-only tool that runs a query in your platform's own language (SPL, ES|QL, SQL, KQL and so on) over a given time range. Optionally, a tool that lists your indexes, data streams or tables.
- Logs of some of these kinds: identity-provider sign-ins (people and applications), directory audit, web server / proxy / gateway / CDN access, firewall and IPS, endpoint process and network events. A missing log type is reported as a blind spot, never as a clean result.

## Install

1. Copy the edition you want into `.claude/agents/` in a project, or into `~/.claude/agents/` for all your projects.
2. Change the `tools:` line to your own tool names. "Tools and setup" in the file says what each tool must do.

## Use

Ask Claude Code something like:

> Hunt sustained attacks in workspaces `contoso-prod` and `contoso-dev`, deep. Our public ranges are 203.0.113.0/24.

or, with the generic edition:

> Hunt sustained attacks in our Splunk, deep. Sign-ins are in `index=okta` and `index=wineventlog`, web logs in `index=web`. Our public ranges are 203.0.113.0/24.

- **Depths:** `deep` (the default, every step), `sweep` (a lighter pass across many environments) and `markers` (a daily pass of the agent-framework discovery queries).
- **Limits:** at most 8 workspaces or environments per run, and a report of at most 120 lines.
- **Carry forward:** the report ends with a list of addresses and client strings to paste into the next run, because the agent keeps nothing between runs. The generic edition also hands back its field map, so the next run can skip discovery.

If you hunt several organizations' environments, the report names all of them, so handle it accordingly.

## Caveats

- The thresholds come from measured traffic on one estate and one framework. Expect to tune them on yours.
- The Sentinel queries were written for, and have only run through, a guarded query tool: per-table lookback caps, a row cap, hashed identities, and no `let` or `union`. They are plain KQL and should run elsewhere.
- The generic edition gives result-code mappings for Entra ID and Windows AD. With another identity provider, the agent maps its codes onto the same classes at the start of the run and lists the mapping it used. Check that mapping before you trust a rung grade.
- `BEHAVIOUR` means an agent may be driving the activity. Only a marker names a framework, and only the organization that commissioned a test can confirm it was authorized.

## License

MIT; see [LICENSE](LICENSE). The parts adapted from ThreatDefence's agentic-attack-detections keep their own MIT notice, which is at the end of each agent file.
