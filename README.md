# soc-sustained-campaign-hunter

A Claude Code subagent that hunts Microsoft Sentinel workspaces for two things that per-IP and per-day rules miss:

- **Sustained campaigns.** One operator's pressure on one target set, stitched across rotating source addresses and across weeks: low-and-slow password spray, testing of a leaked application secret, a source that stays on a few destinations.
- **AI agent attack frameworks.** The published markers of tools such as ARTEX, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent and Agent Zero. More usefully, it also looks for what an agent-driven attack does, whichever framework is driving it.

It only detects. It runs read-only KQL and writes a report, and it changes nothing in your tenant.

## Where this comes from

This is based on my own testing with ARTEX, an agentic attack framework. I ran it under authorization, recorded what its traffic actually looks like on the wire and on the host it runs from, and rebuilt the agent-framework lane around those measurements instead of around published indicators. Then I ran the agent through my own SOC against live Sentinel workspaces and tuned the queries and thresholds on what came back, false positives included.

What the measurements changed:

- **Marker strings caught almost none of the real traffic.** The model invents its own client names, often from the words of its task, and types browser strings with the version it remembers rather than a current one. The agent looks for those shapes instead of a fixed list.
- **Sessions were mostly `404`s, not `401`s.** An agent with no application bundle to read guesses paths a few at a time and pauses to think between them.
- **One session used several client strings,** so grouping by user agent splits it. The agent groups by client address.
- **The widest activity was a few requests on each of many sites.** No single site sees enough to notice. Only a count per source across sites shows it.

The signature lists started from ThreatDefence's [agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections) (MIT). Its notice is at the end of the agent file.

## What it does

| Lane | Looks for |
|---|---|
| Identity | Spray campaigns stitched by tool profile (application plus user agent) over 30 days; slow single-address testers; correct passwords used from addresses that never succeed; invented client IDs |
| Workload identity | Failed application-secret sign-ins from outsiders, meaning a leaked secret is being tested |
| Agent framework | Markers and leads in sign-in, web, gateway, firewall, process and network tables; behaviors the frameworks share (relayed MFA, an app granting itself access, exposed config files); application walks; one source fanning out across many sites |
| Perimeter | Destinations under focused pressure from rotating sources; high-severity signatures that were allowed through |

Every campaign is graded on four separate axes: **Sustained**, **Adaptive**, **Progress** (how far up the credential ladder it got) and **Agentic**. The benign reading is tested before anything is reported, and anything that reached a correct credential is reported first.

## Requirements

- Claude Code, or another harness that loads Claude Code subagent files.
- A read-only tool that runs KQL against a Sentinel / Log Analytics workspace over a time window you give it. Examples: the Azure MCP Server's Log Analytics query tool, the Microsoft Sentinel MCP server, or your own wrapper. Optionally, a tool that lists workspaces.
- Some of these tables: `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs`, `MicrosoftGraphActivityLogs`, `CommonSecurityLog`, `AGWFirewallLogs`, `AGWAccessLogs`, `W3CIISLog`, `DeviceProcessEvents`, `DeviceNetworkEvents`. A missing table is reported as a blind spot, never as a clean result.

## Install

1. Copy `soc-sustained-campaign-hunter.md` into `.claude/agents/` in a project, or into `~/.claude/agents/` for all your projects.
2. Change the `tools:` line to your own tool names. "Tools and setup" in the file says what each tool must do.

## Use

Ask Claude Code something like:

> Hunt sustained attacks in workspaces `contoso-prod` and `contoso-dev`, deep. Our public ranges are 203.0.113.0/24.

- **Depths:** `deep` (the default, every step), `sweep` (a lighter pass across many workspaces) and `markers` (a daily pass of the agent-framework discovery queries).
- **Limits:** at most 8 workspaces per run, and a report of at most 120 lines.
- **Carry forward:** the report ends with a list of addresses and client strings to paste into the next run, because the agent keeps nothing between runs.

If you hunt several organizations' workspaces, the report names all of them, so handle it accordingly.

## Caveats

- The thresholds come from measured traffic on one estate and one framework. Expect to tune them on yours.
- The queries were written for, and have only run through, a guarded query tool: per-table lookback caps, a row cap, hashed identities, and no `let` or `union`. They are plain KQL and should run elsewhere.
- `BEHAVIOUR` means an agent may be driving the activity. Only a marker names a framework, and only the organization that commissioned a test can confirm it was authorized.
