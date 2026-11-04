# SSH Brute-Force Detector (Python)

A small detection script that reads a Linux `auth.log` and flags source IPs with many failed SSH logins in a short time window. Maps to MITRE ATT&CK **T1110 - Brute Force**.

## Usage
```bash
python3 detect_bruteforce.py sample_auth.log --year 2026
python3 detect_bruteforce.py sample_auth.log --year 2026 --threshold 8 --window 30 --csv alerts.csv
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--threshold` | 5 | failed logins needed to raise an alert |
| `--window` | 60 | sliding window in seconds |
| `--year` | current | auth.log has no year, so supply one |
| `--csv` | none | write alerts to a CSV file |

## Sample data
`sample_auth.log` is **synthetic** test data I generated. The attacker address uses the documentation range `203.0.113.0/24` and the legitimate user uses `192.0.2.0/24`. It contains normal logins, one typo and one brute-force burst.

## Limitations
- Only matches OpenSSH "Failed password" lines. It does not cover failed public-key attempts or other services.
- Slow attacks spread over hours stay under the window and are missed.
- Shared NAT addresses could cause false positives.

## Ideas to extend
- Detect "success after many failures" (possible compromise)
- Look up flagged IPs with a free threat-intelligence API
- Support Windows Event ID 4625 exports
