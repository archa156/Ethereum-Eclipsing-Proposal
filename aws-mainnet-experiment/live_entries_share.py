#!/usr/bin/env python3
import argparse
import re
import sys
from datetime import datetime

TIMESTAMP_RE = re.compile(r"\[(\d{2}-\d{2}\|\d{2}:\d{2}:\d{2}\.\d{3})\]")
BUCKET_RE = re.compile(r"\bb=(\d+)\b")
ID_RE = re.compile(r"\bid=(\S+)")

REVALIDATED_MARKER = "Node revalidated"
REMOVED_MARKER = "Removed dead node"


def parse_ts(ts_str):
    return datetime.strptime(f"2000-{ts_str}", "%Y-%m-%d|%H:%M:%S.%f")


def is_attacker(node_id, attacker_prefixes):
    if node_id is None:
        return False
    return any(node_id.lower().startswith(p.lower()) for p in attacker_prefixes)


def parse_line(line):
    if REVALIDATED_MARKER not in line and REMOVED_MARKER not in line:
        return None
    bucket_match = BUCKET_RE.search(line)
    if not bucket_match:
        return None
    bucket = int(bucket_match.group(1))
    id_match = ID_RE.search(line)
    node_id = id_match.group(1) if id_match else None
    ts_match = TIMESTAMP_RE.search(line)
    if not ts_match:
        return None
    ts = parse_ts(ts_match.group(1))
    event = "seen" if REVALIDATED_MARKER in line else "removed"
    return ts, bucket, event, node_id


def build_snapshots(path, target_bucket):
    live = set()
    snapshots = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed is None:
                continue
            ts, bucket, event, node_id = parsed
            if bucket != target_bucket or node_id is None:
                continue
            if event == "seen":
                live.add(node_id)
            else:
                live.discard(node_id)
            snapshots.append((ts, frozenset(live)))
    return snapshots


def average_share(snapshots, window_start, window_end, attacker_prefixes):
    totals = []
    attacker_counts = []
    for ts, live in snapshots:
        if ts < window_start or ts > window_end:
            continue
        totals.append(len(live))
        attacker_counts.append(sum(1 for nid in live if is_attacker(nid, attacker_prefixes)))

    if not totals:
        return 0.0, 0.0, 0.0

    avg_total = sum(totals) / len(totals)
    avg_atk = sum(attacker_counts) / len(attacker_counts)
    share_pct = 100.0 * avg_atk / avg_total if avg_total > 0 else 0.0
    return avg_total, avg_atk, share_pct


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--bucket", type=int, required=True)
    ap.add_argument("--attackers", required=True)
    ap.add_argument("--phase", action="append",
                     help='label,start_ts,end_ts (comma-separated). Repeatable.')
    args = ap.parse_args()

    attacker_prefixes = [p.strip() for p in args.attackers.split(",") if p.strip()]

    if not args.phase:
        print("Need at least one --phase \"label,start_ts,end_ts\"", file=sys.stderr)
        sys.exit(1)
    phases = [p.split(",") for p in args.phase]

    snapshots = build_snapshots(args.logfile, args.bucket)
    if not snapshots:
        print(f"No live-entry events found for bucket={args.bucket}.", file=sys.stderr)
        sys.exit(1)

    print(f"bucket={args.bucket}  live-entry events={len(snapshots)}")
    print(f"{'phase':>12} | {'avg total':>10} | {'avg attacker':>13} | {'attacker share':>15}")
    print("-" * 60)

    for label, start_s, end_s in phases:
        start_ts = parse_ts(start_s)
        end_ts = parse_ts(end_s)
        avg_total, avg_atk, share_pct = average_share(snapshots, start_ts, end_ts, attacker_prefixes)
        print(f"{label:>12} | {avg_total:>10.2f} | {avg_atk:>13.2f} | {share_pct:>14.1f}%")

    final_state = snapshots[-1][1]
    atk_now = sorted(nid for nid in final_state if is_attacker(nid, attacker_prefixes))
    honest_now = len(final_state) - len(atk_now)
    print()
    print(f"Current live entries in bucket {args.bucket}: {len(final_state)} total "
          f"({len(atk_now)} attacker, {honest_now} honest)")
    if atk_now:
        print("Attacker IDs currently live:", ", ".join(atk_now))


if __name__ == "__main__":
    main()
