---
name: web-fan-out-behaviour
tags: [agent-framework, web]
max_turns: 200
timeout_seconds: 3600
allowed_tools: [Agent, Write]
disallowed_tools: [WebFetch, WebSearch]
---
Run a sustained-campaign hunt with the soc-sustained-campaign-hunter-generic agent, and when it finishes give me its full report verbatim.

- Environment: adventure-web
- Depth: deep
- Lanes: agent framework only
- Our public address range: 203.0.113.0/24

The platform is the local `sql` query service: `run_query` takes SQLite SQL, and `list_sources` describes the environments, tables and columns.
