"""Detect repeated failures followed by a successful login in a rolling window."""
import argparse, json
from collections import defaultdict, deque
from datetime import datetime

def detect(events, threshold=3, window_seconds=300):
    if threshold < 1 or window_seconds < 0:
        raise ValueError("Invalid detector configuration")
    buckets, alerts = defaultdict(deque), []
    parsed = []
    for e in events:
        stamp = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("Timezone required")
        if e["outcome"] not in ("failure", "success"):
            raise ValueError("Invalid outcome")
        parsed.append((stamp, e))
    for stamp, e in sorted(parsed, key=lambda row: row[0]):
        key = (e["user"], e["source_ip"])
        failures = buckets[key]
        while failures and (stamp-failures[0]).total_seconds() > window_seconds:
            failures.popleft()
        if e["outcome"] == "failure":
            failures.append(stamp)
        else:
            if len(failures) >= threshold:
                alerts.append({"rule":"AUTH-001", "user":key[0], "source_ip":key[1],
                               "failures":len(failures), "timestamp":stamp.isoformat(),
                               "reason":"Success after repeated failures; investigate, do not assume compromise"})
            failures.clear()
    return alerts

if __name__ == "__main__":
    p=argparse.ArgumentParser();p.add_argument("events");a=p.parse_args()
    with open(a.events) as f:
        print(json.dumps(detect([json.loads(line) for line in f if line.strip()]), indent=2))
