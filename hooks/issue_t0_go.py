#!/usr/bin/env python3
"""
issue_t0_go.py — mints a T0-GO marker. HUMAN-RUN ONLY.

This script is the intended source of the marker checked by
pre_tool_guard.py and lib/airtable-client.js's requireT0Go(). It is meant to
be run by a human at a keyboard, but nothing enforces that: an agent session
with Bash or file-write access can run it, or write the marker file directly
(docs/THREAT-MODEL.md, T10). Do not wire this into anything an agent session
can invoke on itself — a hook or MCP tool that can both mint and consume its
own authorization is not a gate, it's a formality.

Usage:
  python3 hooks/issue_t0_go.py --decision-id T0-DEC-EXAMPLE-2026-0905 \\
      --scope tblEZ6ctzSoTBsfCW --ttl 600

--scope may be repeated for a marker covering more than one write in one
sitting (e.g. --scope tblsVXX2XnhVLWMVE --scope tblX88U1VOwmK2fF5).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MARKER_PATH = Path(os.environ.get("T0_GO_MARKER_PATH", ".claude/t0-go.json"))


def _is_expired(marker: dict) -> bool:
    try:
        issued_at = datetime.fromisoformat(marker["issued_at"].replace("Z", "+00:00"))
        ttl = int(marker["ttl_seconds"])
    except (KeyError, ValueError, TypeError):
        return True  # malformed marker — treat as not worth protecting
    return (datetime.now(timezone.utc) - issued_at).total_seconds() > ttl


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--decision-id", required=True, help="e.g. T0-DEC-EXAMPLE-2026-0905")
    parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Table ID or sentinel string (github:write, supabase:apply_migration, ...). Repeatable.",
    )
    parser.add_argument("--ttl", type=int, default=600, help="Seconds until this marker expires (default 600).")
    parser.add_argument(
        "--tier",
        type=int,
        choices=[1, 2],
        default=1,
        help="1 = operational write (Session Ledger, ATQ). 2 = governance write (Decision Log). Default 1.",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_MARKER_PATH,
        help=f"Marker file path (default {DEFAULT_MARKER_PATH}).",
    )
    args = parser.parse_args()

    if args.path.exists():
        existing = json.loads(args.path.read_text())
        if not existing.get("consumed") and not _is_expired(existing):
            print(
                f"Refusing to overwrite an existing, unconsumed, unexpired marker at "
                f"{args.path} (decision {existing.get('decision_id')}). Let it be "
                f"consumed or expire first, or pass --path to use a different location.",
                file=sys.stderr,
            )
            sys.exit(1)

    marker = {
        "decision_id": args.decision_id,
        "scope": args.scope,
        "tier": args.tier,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ttl_seconds": args.ttl,
        "consumed": False,
    }

    args.path.parent.mkdir(parents=True, exist_ok=True)
    args.path.write_text(json.dumps(marker, indent=2))
    print(f"T0-GO marker written to {args.path}")
    print(f"  decision_id: {marker['decision_id']}")
    print(f"  scope:       {marker['scope']}")
    print(f"  tier:        {marker['tier']}")
    print(f"  expires:     in {args.ttl}s")


if __name__ == "__main__":
    main()
