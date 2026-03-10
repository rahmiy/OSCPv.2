#!/usr/bin/env python3
# uniexec.py
#
# Safe, authorized wrapper that:
#  - Scans common ports to detect services (multi-threaded)
#  - Accepts username + (password OR hash)
#  - Automatically runs default per-service workflows (no flags):
#       * SMB: RID brute / users / shares (configurable)
#       * LDAP / LDAPS: RootDSE / users / groups / computers (configurable)
#       * MSSQL (SQL Server): version / databases / logins (configurable)
#
# NOTE: Replace placeholders with your authorized logic. No exploitation is included.

import argparse
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional

# =========================
# Built-in service catalog
# =========================
# Map ports to (service_key, human_name)
PORT_SERVICE_MAP: Dict[int, Tuple[str, str]] = {
    22:   ("ssh",   "SSH"),
    23:   ("telnet","Telnet"),
    80:   ("http",  "HTTP"),
    88:   ("kerberos", "Kerberos"),
    110:  ("pop3",  "POP3"),
    111:  ("portmap", "Portmapper"),
    123:  ("ntp",   "NTP"),
    135:  ("rpc",   "MS RPC"),
    139:  ("netbios","NetBIOS"),
    143:  ("imap",  "IMAP"),
    161:  ("snmp",  "SNMP"),
    389:  ("ldap",  "LDAP"),
    443:  ("https", "HTTPS"),
    445:  ("smb",   "SMB"),
    464:  ("kpasswd","Kerberos kpasswd"),
    512:  ("rexec", "Rexec"),
    513:  ("rlogin","Rlogin"),
    514:  ("rsh",   "Rsh"),
    587:  ("smtp",  "SMTP (submission)"),
    636:  ("ldaps", "LDAPS"),
    853:  ("dot",   "DNS over TLS"),
    873:  ("rsync", "Rsync"),
    990:  ("ftps",  "FTPS"),
    993:  ("imaps", "IMAPS"),
    995:  ("pop3s", "POP3S"),
    1025: ("rpc-ephemeral", "RPC Ephemeral"),
    1433: ("mssql", "Microsoft SQL Server"),
    1521: ("oracle","Oracle TNS Listener"),
    1723: ("pptp",  "PPTP"),
    2049: ("nfs",   "NFS"),
    2375: ("docker","Docker (unencrypted)"),
    2376: ("docker-tls","Docker (TLS)"),
    27017:("mongodb","MongoDB"),
    3000: ("http-alt","HTTP (alt)"),
    3306: ("mysql", "MySQL"),
    3389: ("rdp",   "RDP"),
    4444: ("metasploit","Metasploit handler"),
    5000: ("http-alt","HTTP (alt) / Flask default"),
    5432: ("postgres","PostgreSQL"),
    5601: ("kibana","Kibana"),
    5900: ("vnc",   "VNC"),
    5985: ("winrm", "WinRM (HTTP)"),
    5986: ("winrm-https","WinRM (HTTPS)"),
    6379: ("redis", "Redis"),
    8000: ("http-alt","HTTP (alt)"),
    8080: ("http-proxy","HTTP Proxy/Alt"),
    8443: ("https-alt","HTTPS (alt)"),
    9200: ("elasticsearch","Elasticsearch"),
    11211:("memcached","Memcached"),
}

DEFAULT_TIMEOUT = 1.0  # seconds per port connect
MAX_WORKERS = 200      # tune concurrency as needed

# =========================
# Built-in default actions
# =========================
# Adjust these defaults to change what runs when the service is detected—no flags required.

SMB_DEFAULT_ACTIONS = {
    "rid_brute": True,     # run RID brute (placeholder)
    "enum_users": True,    # enumerate users (placeholder)
    "enum_shares": True    # enumerate shares (placeholder)
}

LDAP_DEFAULT_ACTIONS = {
    "enum_rootdse": True,   # read RootDSE info (placeholder)
    "enum_users": True,     # enumerate users (placeholder)
    "enum_groups": True,    # enumerate groups (placeholder)
    "enum_computers": False # enumerate computers (placeholder)
}

MSSQL_DEFAULT_ACTIONS = {
    "enum_version": True,   # get server/version info (placeholder)
    "enum_databases": True, # list databases (placeholder)
    "enum_logins": False    # list logins (placeholder)
}

# Optional: local JSON config auto-loaded (no flags).
# If ./uniexec.json exists, it can override defaults like:
# {
#   "smb":   { "rid_brute": false, "enum_users": true, "enum_shares": true },
#   "ldap":  { "enum_rootdse": true, "enum_users": true, "enum_groups": false, "enum_computers": false },
#   "mssql": { "enum_version": true, "enum_databases": true, "enum_logins": true }
# }
LOCAL_CONFIG_FILENAME = "uniexec.json"


def load_local_config() -> Dict:
    """Load local JSON config if present. Returns {} if not present/invalid."""
    try:
        if os.path.exists(LOCAL_CONFIG_FILENAME):
            with open(LOCAL_CONFIG_FILENAME, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        pass  # Ignore config errors and use built-ins
    return {}


def merge_actions(defaults: Dict[str, bool], local_cfg: Dict, service_key: str) -> Dict[str, bool]:
    """Merge local config overrides for a given service into its defaults."""
    merged = dict(defaults)
    svc_cfg = local_cfg.get(service_key)
    if isinstance(svc_cfg, dict):
        for k, v in svc_cfg.items():
            if k in merged and isinstance(v, bool):
                merged[k] = v
    return merged


def parse_args():
    parser = argparse.ArgumentParser(
        description="Unified, authorized service-aware wrapper. Auto-detects services and runs safe workflows."
    )
    parser.add_argument("-t", "--target", required=True, help="Target host or IP")
    parser.add_argument("-u", "--username", required=True, help="Username for authentication")

    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument("-p", "--password", help="Password credential")
    auth.add_argument("-H", "--hash", help="Hashed credential (e.g., NTLM hash)")

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated custom port list (overrides default catalog). Example: 22,80,443,445"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Max concurrent port checks (default: {MAX_WORKERS})"
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Display closed/filtered ports during scan"
    )
    return parser.parse_args()


def check_port(host: str, port: int, timeout: float) -> bool:
    """Attempt a TCP connect; return True if open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((host, port)) == 0
        except (socket.timeout, OSError):
            return False


def scan_ports(host: str, ports: List[int], timeout: float, max_workers: int, show_closed: bool) -> Dict[int, bool]:
    """Concurrent TCP connect scan across provided ports."""
    results: Dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                is_open = fut.result()
                results[port] = is_open
                if is_open:
                    svc = PORT_SERVICE_MAP.get(port, (str(port), f"Port {port}"))[1]
                    print(f"[OPEN] {port:<5} {svc}")
                elif show_closed:
                    print(f"[----] {port:<5} closed/filtered")
            except Exception as e:
                results[port] = False
                if show_closed:
                    print(f"[ERR ] {port:<5} {e}")
    return results


def autodetect_services(host: str, timeout: float, max_workers: int, custom_ports: List[int], show_closed: bool) -> List[str]:
    """Scan and map open ports to logical service keys."""
    ports = custom_ports if custom_ports else sorted(PORT_SERVICE_MAP.keys())
    print(f"[i] Scanning {host} across {len(ports)} ports (timeout={timeout}s, concurrency={max_workers})")
    open_map = scan_ports(host, ports, timeout, max_workers, show_closed)

    detected: List[str] = []
    for port, is_open in open_map.items():
        if is_open:
            key = PORT_SERVICE_MAP.get(port, (f"port-{port}", f"Port {port}"))[0]
            if key not in detected:
                detected.append(key)

    print("\n[i] Detected services:", ", ".join(detected) if detected else "None")
    return detected


# =========================
# Service Workflows (safe)
# =========================

def smb_workflow(args, smb_actions: Dict[str, bool]) -> None:
    """SAFE placeholder for SMB logic (no flags; uses defaults/config)."""
    plan = [name for name, enabled in [
        ("RID brute", smb_actions.get("rid_brute", False)),
        ("Enumerate users", smb_actions.get("enum_users", False)),
        ("Enumerate shares", smb_actions.get("enum_shares", False)),
    ] if enabled]

    print("\n--- SMB :: Plan ---")
    if plan:
        for step in plan:
            print(f"  [*] {step}")
    else:
        print("  [*] No SMB actions enabled by defaults/config.")

    # ---- Placeholders for your authorized SMB logic ----
    if smb_actions.get("rid_brute", False):
        print("  [+] Running authorized SMB RID-brute checks... (placeholder)")
    if smb_actions.get("enum_users", False):
        print("  [+] Running authorized SMB user enumeration... (placeholder)")
    if smb_actions.get("enum_shares", False):
        print("  [+] Running authorized SMB share enumeration... (placeholder)")
    if not plan:
        print("  [+] Running authorized generic SMB checks... (placeholder)")


def ldap_workflow(args, ldap_actions: Dict[str, bool], secure: bool) -> None:
    """SAFE placeholder for LDAP/LDAPS logic (no flags; uses defaults/config)."""
    proto = "LDAPS" if secure else "LDAP"
    plan = [name for name, enabled in [
        ("RootDSE information", ldap_actions.get("enum_rootdse", False)),
        ("Enumerate users", ldap_actions.get("enum_users", False)),
        ("Enumerate groups", ldap_actions.get("enum_groups", False)),
        ("Enumerate computers", ldap_actions.get("enum_computers", False)),
    ] if enabled]

    print(f"\n--- {proto} :: Plan ---")
    if plan:
        for step in plan:
            print(f"  [*] {step}")
    else:
        print(f"  [*] No {proto} actions enabled by defaults/config.")

    # ---- Placeholders for your authorized LDAP logic ----
    if ldap_actions.get("enum_rootdse", False):
        print(f"  [+] {proto}: Fetching RootDSE attributes... (placeholder)")
    if ldap_actions.get("enum_users", False):
        print(f"  [+] {proto}: Enumerating users... (placeholder)")
    if ldap_actions.get("enum_groups", False):
        print(f"  [+] {proto}: Enumerating groups... (placeholder)")
    if ldap_actions.get("enum_computers", False):
        print(f"  [+] {proto}: Enumerating computers... (placeholder)")
    if not plan:
        print(f"  [+] {proto}: Running authorized generic checks... (placeholder)")


def mssql_workflow(args, mssql_actions: Dict[str, bool]) -> None:
    """SAFE placeholder for MSSQL logic (no flags; uses defaults/config)."""
    plan = [name for name, enabled in [
        ("Server/version info", mssql_actions.get("enum_version", False)),
        ("List databases", mssql_actions.get("enum_databases", False)),
        ("List logins", mssql_actions.get("enum_logins", False)),
    ] if enabled]

    print("\n--- MSSQL :: Plan ---")
    if plan:
        for step in plan:
            print(f"  [*] {step}")
    else:
        print("  [*] No MSSQL actions enabled by defaults/config.")

    # ---- Placeholders for your authorized MSSQL logic ----
    if mssql_actions.get("enum_version", False):
        print("  [+] MSSQL: Retrieving server/version info... (placeholder)")
    if mssql_actions.get("enum_databases", False):
        print("  [+] MSSQL: Enumerating databases... (placeholder)")
    if mssql_actions.get("enum_logins", False):
        print("  [+] MSSQL: Enumerating logins... (placeholder)")
    if not plan:
        print("  [+] MSSQL: Running authorized generic checks... (placeholder)")


def generic_workflow(service_key: str, args) -> None:
    """Generic safe placeholder for non-specific services."""
    print(f"[*] Executing authorized {service_key} checks... (placeholder)")


def run_service_workflow(service_key: str, args,
                         smb_actions: Dict[str, bool],
                         ldap_actions: Dict[str, bool],
                         mssql_actions: Dict[str, bool]) -> None:
    """Dispatch per-service workflows."""
    print(f"\n=== {service_key.upper()} :: Workflow Start ===")
    print(f"Target   : {args.target}")
    print(f"Username : {args.username}")
    if args.password:
        print("Auth     : Password provided")
    if args.hash:
        print("Auth     : Hash provided")

    if service_key == "smb":
        smb_workflow(args, smb_actions)
    elif service_key in ("ldap", "ldaps"):
        ldap_workflow(args, ldap_actions, secure=(service_key == "ldaps"))
    elif service_key == "mssql":
        mssql_workflow(args, mssql_actions)
    else:
        generic_workflow(service_key, args)

    print(f"=== {service_key.upper()} :: Workflow End ===")


def parse_custom_ports(ports_str: Optional[str]) -> List[int]:
    if not ports_str:
        return []
    try:
        return sorted({int(p.strip()) for p in ports_str.split(",") if p.strip()})
    except ValueError:
        raise SystemExit("[-] Invalid --ports value. Use comma-separated integers, e.g., 22,80,443")


def main():
    args = parse_args()

    print("\n========== Unified Exec Wrapper (Safe) ==========")
    print(f"Target   : {args.target}")
    print(f"Username : {args.username}")
    print(f"Auth     : {'Password' if args.password else 'Hash'}")
    print("=================================================\n")

    # Load local config (if any) and resolve per-service defaults
    local_cfg = load_local_config()
    smb_actions   = merge_actions(SMB_DEFAULT_ACTIONS,   local_cfg, "smb")
    ldap_actions  = merge_actions(LDAP_DEFAULT_ACTIONS,  local_cfg, "ldap")
    mssql_actions = merge_actions(MSSQL_DEFAULT_ACTIONS, local_cfg, "mssql")

    # Optional info display
    print("[i] Effective default actions:")
    print("    SMB  :", smb_actions)
    print("    LDAP :", ldap_actions)
    print("    MSSQL:", mssql_actions)

    custom_ports = parse_custom_ports(args.ports)
    detected_services = autodetect_services(
        host=args.target,
        timeout=args.timeout,
        max_workers=args.max_workers,
        custom_ports=custom_ports,
        show_closed=args.show_closed
    )

    if not detected_services:
        print("[!] No services detected from the scanned catalog. You can try --ports to expand.")
        return

    for svc in detected_services:
        run_service_workflow(svc, args, smb_actions, ldap_actions, mssql_actions)

    print("\n[+] All workflows complete.\n")


if __name__ == "__main__":
    main()
