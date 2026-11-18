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


def build_trajectory(path, target_bucket):
    live = set()
    traj = []
    skipped_no_id = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed is None:
                continue
            ts, bucket, event, node_id = parsed
            if bucket != target_bucket:
                continue
            if node_id is None:
                skipped_no_id += 1
                continue
            if event == "seen":
                if node_id not in live:
                    live.add(node_id)
                    traj.append((ts, frozenset(live)))
            else:
                if node_id in live:
                    live.discard(node_id)
                    traj.append((ts, frozenset(live)))
    return traj, skipped_no_id


def time_weighted_avg(traj, window_start, window_end, attacker_prefixes):
    state = frozenset()
    idx = 0
    for ts, snap in traj:
        if ts <= window_start:
            state = snap
            idx += 1
        else:
            break

    t = window_start
    total_area = 0.0
    atk_area = 0.0

    for ts, snap in traj[idx:]:
        if ts >= window_end:
            break
        seg_end = min(ts, window_end)
        dt = (seg_end - t).total_seconds()
        if dt > 0:
            atk_count = sum(1 for nid in state if is_attacker(nid, attacker_prefixes))
            total_area += dt * len(state)
            atk_area += dt * atk_count
            t = seg_end
        state = snap
        t = ts

    if t < window_end:
        dt = (window_end - t).total_seconds()
        atk_count = sum(1 for nid in state if is_attacker(nid, attacker_prefixes))
        total_area += dt * len(state)
        atk_area += dt * atk_count
        t = window_end

    duration = (window_end - window_start).total_seconds()
    if duration <= 0:
        return 0.0, 0.0, 0.0, 0.0
    avg_total = total_area / duration
    avg_atk = atk_area / duration
    return avg_total, avg_atk, avg_total - avg_atk, duration


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
    phases = []
    for p in args.phase:
        label, start_s, end_s = p.split(",")
        phases.append((label, start_s, end_s))

    traj, skipped = build_trajectory(args.logfile, args.bucket)
    if not traj:
        print(f"No live-entry events found for bucket={args.bucket}. "
              "(Either nothing is live yet, or your log doesn't have "
              "--verbosity 4 revalidation lines.)", file=sys.stderr)
        sys.exit(1)

    print(f"bucket={args.bucket}  live-entry transition events={len(traj)}"
          + (f"  (skipped {skipped} events with no id= field)" if skipped else ""))
    print("NOTE: membership is approximated from first-seen revalidation, so "
          "presence that started before this log/window began is undercounted.")
    print()
    print(f"{'phase':>12} | {'avg total':>10} | {'avg attacker':>13} | {'avg honest':>11} | {'attacker share':>15}")
    print("-" * 75)

    for label, start_s, end_s in phases:
        start_ts = parse_ts(start_s)
        end_ts = parse_ts(end_s)
        avg_total, avg_atk, avg_honest, duration = time_weighted_avg(
            traj, start_ts, end_ts, attacker_prefixes)
        share_pct = 100.0 * avg_atk / avg_total if avg_total > 0 else 0.0
        print(f"{label:>12} | {avg_total:>10.2f} | {avg_atk:>13.2f} | {avg_honest:>11.2f} | {share_pct:>14.1f}%"
              f"   ({duration/60:.0f} min window)")

    final_state = traj[-1][1] if traj else frozenset()
    atk_now = sorted(nid for nid in final_state if is_attacker(nid, attacker_prefixes))
    honest_now = len(final_state) - len(atk_now)
    print()
    print(f"Current live entries in bucket {args.bucket}: {len(final_state)} total "
          f"({len(atk_now)} attacker, {honest_now} honest)")
    if atk_now:
        print("Attacker IDs currently live:", ", ".join(atk_now))


if __name__ == "__main__":
    main()
