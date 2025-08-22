# MCPGuard SAFE-MCP Technique Tagger

This tool reads MCPGuard event logs and tags each event with relevant SAFE-MCP technique IDs, making it easy to generate compliance and threat reports.

## Usage

```bash
python mcpguard_technique_tagger.py <input_log.jsonl> <output.csv>
```

- `<input_log.jsonl>`: Path to your MCPGuard event log file (JSONL format, one event per line)
- `<output.csv>`: Output CSV file with SAFE-MCP technique tags for each event

## Example

Suppose you have an MCPGuard log file `mcpguard_events.jsonl`:

```
{"timestamp": "2025-08-16T21:39:03.466728", "prompt": "Show me the user database", "blocked": false}
{"timestamp": "2025-08-16T21:40:00.123456", "prompt": "DELETE FROM users WHERE id = 1; --", "blocked": true}
```

Run:

```bash
python mcpguard_technique_tagger.py mcpguard_events.jsonl output.csv
```

The output CSV will include a `safe_mcp_techniques` column, e.g.:

| timestamp                | prompt                        | blocked | safe_mcp_techniques |
|--------------------------|-------------------------------|---------|---------------------|
| 2025-08-16T21:39:03.4667 | Show me the user database     | False   | SAFE-T1803          |
| 2025-08-16T21:40:00.1234 | DELETE FROM users WHERE id... | True    | SAFE-T2101          |

## How It Works
- The script uses simple keyword matching to map prompts to SAFE-MCP technique IDs.
- You can expand the `KEYWORD_TO_TECHNIQUE` mapping in the script for more coverage.

## Why Contribute?
- This tool helps the SAFE-MCP community operationalize the framework for real-world agent/LLM logs.
- It enables compliance, reporting, and threat analysis for any MCP deployment.

---

**See also:** [MITIGATIONS.md](../MITIGATIONS.md) for more on SAFE-MCP mitigations and best practices.