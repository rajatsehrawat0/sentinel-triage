"""Detect repeated failures followed by a successful login in a rolling window."""
import argparse, json, math, sys
from ipaddress import ip_address
from collections import defaultdict, deque
from datetime import datetime

def validate_event(event):
    """Validate without including raw records or personal values in errors."""
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")
    for field in ("timestamp", "user", "source_ip", "outcome"):
        if not isinstance(event.get(field), str) or not event[field].strip():
            raise ValueError(f"{field} must be a nonempty string")
    try:
        stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be ISO 8601") from None
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    try:
        address = str(ip_address(event["source_ip"]))
    except ValueError:
        raise ValueError("source_ip must be an IPv4 or IPv6 address") from None
    if event["outcome"] not in ("failure", "success"):
        raise ValueError("outcome must be failure or success")
    return stamp, {**event, "source_ip": address}


def read_events(path):
    """Report physical JSONL line numbers and reject the entire invalid input."""
    events = []
    with open(path, encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f"line {number}: invalid JSON") from None
            try:
                validate_event(event)
            except ValueError as error:
                raise ValueError(f"line {number}: {error}") from None
            events.append(event)
    return events


def detect(events, threshold=3, window_seconds=300):
    if type(threshold) is not int or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if (type(window_seconds) not in (int, float)
            or not math.isfinite(window_seconds) or window_seconds < 0):
        raise ValueError("window_seconds must be finite and nonnegative")
    buckets, alerts = defaultdict(deque), []
    parsed = []
    for number, event in enumerate(events, 1):
        try:
            parsed.append(validate_event(event))
        except ValueError as error:
            raise ValueError(f"event {number}: {error}") from None
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

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", help="UTF-8 JSONL authentication events")
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--window-seconds", type=float, default=300)
    args = parser.parse_args(argv)
    try:
        alerts = detect(read_events(args.events), args.threshold, args.window_seconds)
    except (ValueError, UnicodeError) as error:
        # Unicode decode errors can contain input bytes; keep them generic.
        detail = "input must be valid UTF-8" if isinstance(error, UnicodeError) else str(error)
        print(f"error: {detail}", file=sys.stderr)
        return 2
    except OSError:
        print("error: unable to read input file", file=sys.stderr)
        return 2
    print(json.dumps(alerts, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
