#!/usr/bin/env python3
"""Detect SSH brute-force attempts in a Linux auth.log (MITRE ATT&CK T1110).

Flags any source IP with >= THRESHOLD failed logins inside a sliding time window.
"""
import argparse
import csv
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_time(raw: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def detect(path: str, threshold: int, window: int, year: int):
    attempts = defaultdict(deque)
    alerts = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = FAILED.match(line)
            if not m:
                continue
            ts, ip = parse_time(m["ts"], year), m["ip"]
            q = attempts[ip]
            q.append(ts)
            while q and ts - q[0] > timedelta(seconds=window):
                q.popleft()
            if len(q) >= threshold:
                prev = alerts.get(ip)
                alerts[ip] = {
                    "ip": ip,
                    "first_seen": prev["first_seen"] if prev else q[0],
                    "last_seen": ts,
                    "peak_in_window": max(len(q), prev["peak_in_window"] if prev else 0),
                }
    return list(alerts.values())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=5, help="failures needed to alert")
    p.add_argument("--window", type=int, default=60, help="window in seconds")
    p.add_argument("--year", type=int, default=datetime.now().year, help="auth.log has no year")
    p.add_argument("--csv", help="write alerts to this CSV file")
    a = p.parse_args()

    alerts = detect(a.logfile, a.threshold, a.window, a.year)
    if not alerts:
        print("No brute-force activity detected.")
    for al in alerts:
        print(f"ALERT {al['ip']}: {al['peak_in_window']} failed logins within {a.window}s "
              f"({al['first_seen']} to {al['last_seen']}) - T1110 Brute Force")
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["ip", "first_seen", "last_seen", "peak_in_window"])
            w.writeheader()
            w.writerows(alerts)
        print(f"Wrote {len(alerts)} alert(s) to {a.csv}")


if __name__ == "__main__":
    main()
