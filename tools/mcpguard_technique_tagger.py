import json
import csv
import sys
from typing import List, Dict

# Map keywords to SAFE-MCP technique IDs (expand as needed)
KEYWORD_TO_TECHNIQUE = {
    "ignore": "SAFE-T1102",  # Prompt Injection
    "leak": "SAFE-T1102",
    "injection": "SAFE-T1102",
    "override": "SAFE-T1102",
    "token": "SAFE-T1202",  # Token Management
    "api key": "SAFE-T1202",
    "plugin": "SAFE-T1002",  # Supply Chain
    "supply chain": "SAFE-T1002",
    "rate limit": "Rate Limiting",
    "delete from": "SAFE-T2101",  # Data Destruction
    "drop table": "SAFE-T2101",
    "user database": "SAFE-T1803",  # Database Dump
}


def tag_techniques(prompt: str) -> List[str]:
    tags = set()
    prompt_l = prompt.lower()
    for k, v in KEYWORD_TO_TECHNIQUE.items():
        if k in prompt_l:
            tags.add(v)
    return list(tags)


def process_log(input_file: str, output_file: str):
    with open(input_file) as f:
        events = [json.loads(line) for line in f if line.strip()]
    for e in events:
        e["safe_mcp_techniques"] = tag_techniques(e.get("prompt", ""))
    # Write to CSV
    if events:
        # Collect all unique keys from all events
        all_keys = set()
        for e in events:
            all_keys.update(e.keys())
        header = list(all_keys)
        with open(output_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            writer.writeheader()
            for e in events:
                writer.writerow(e)
    print(f"Processed {len(events)} events. Output: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python mcpguard_technique_tagger.py <input_log.jsonl> <output.csv>")
        sys.exit(1)
    process_log(sys.argv[1], sys.argv[2])