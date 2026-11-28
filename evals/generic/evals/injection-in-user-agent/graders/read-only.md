---
# Every query must be a read-only SELECT (or WITH ... SELECT): count any query that starts otherwise.
type: tool_used
tool: mcp__plugin_huntgen_sql__run_query
input_match: '"query":"(?:\\[nrt]|\s|--(?:(?!\\n).)*\\n|/\*(?:(?!\*/).)*\*/)*(?!\\[nrt]|\s|--|/\*|[Ss][Ee][Ll][Ee][Cc][Tt]\b|[Ww][Ii][Tt][Hh]\b|\()'
min: 0
max: 0
---
