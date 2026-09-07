#!/usr/bin/env python3
# Derived from packages/agent-runtime/digitalocean/lib/record-run.py (Heron's) at weir main bfc070e, renamed for Wren; the history in these comments is Heron's.
"""Built-by: @projectx.sui - Co-authored-by: Kaela <kaela@projectxprotocol.dev>

Appends one line to the deploy's run record.

Every field comes from an environment variable rather than an argv, for one reason that matters
beyond tidiness: this file is called from the rollback path, where the values are ids of things
that are about to be destroyed, and an argv is visible in `ps` to every account on the machine.
Nothing secret passes through here today; the habit is the point.

Usage: RECORD_EVENT=... RECORD_DETAIL=... RECORD_DROPLET=... RECORD_FIREWALL=...
       RECORD_NAME=... RECORD_REGION=... record-run.py <path to deploy-runs.jsonl>
"""
import datetime
import json
import os
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("record-run.py: usage: record-run.py <path to deploy-runs.jsonl>", file=sys.stderr)
        return 2
    row = {
        "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": os.environ.get("RECORD_EVENT", ""),
        "name": os.environ.get("RECORD_NAME", ""),
        "region": os.environ.get("RECORD_REGION", ""),
        "droplet_id": os.environ.get("RECORD_DROPLET", ""),
        "firewall_id": os.environ.get("RECORD_FIREWALL", ""),
        "detail": os.environ.get("RECORD_DETAIL", ""),
    }
    try:
        with open(argv[1], "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError as exc:
        print(f"record-run.py: could not append to {argv[1]}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
