import argparse
import sys

# don't forget to install python-nmap 
# pip install python-nmap

try:
    import nmap  # python-nmap
except ImportError:
    print("[-] Missing dependency: python-nmap. Install with: pip install python-nmap")
    sys.exit(1)


def get_args():
    parser = argparse.ArgumentParser(
        description="Nmap wrapper: scan targets for open ports and services."
    )
    parser.add_argument(
        "-t", "--target",
        dest="targets",
        required=True,
        help="Target(s): IP, DNS name, CIDR (e.g., 192.168.1.0/24), or comma-separated list"
    )
    parser.add_argument(
        "-p", "--ports",
        dest="ports",
        default="1-1024",
        help="Ports to scan (e.g., 22,80,443 or 1-65535). Default: 1-1024"
    )
    parser.add_argument(
        "-a", "--arguments",
        dest="nmap_args",
        default="-sS -Pn -T4",
        help="Additional Nmap arguments (default: '-sS -Pn -T4')"
    )
    parser.add_argument(
        "-o", "--os-detect",
        dest="os_detect",
        action="store_true",
        help="Enable OS detection (adds '-O'). Requires sudo/root on many systems."
    )
    return parser.parse_args()


def run_nmap_scan(targets: str, ports: str, nmap_args: str, os_detect: bool = False):
    """
    Executes an nmap scan using python-nmap and returns the raw results.
    """
    nm = nmap.PortScanner()


    args = nmap_args.strip()
    if os_detect and "-O" not in args.split():
        args = f"{args} -O"

    try:
        # nmap.scan(targets, ports, arguments=...)
        # Note: targets can be comma-separated hosts or CIDR.
        print(f"[+] Running: nmap {args} -p {ports} {targets}")
        nm.scan(hosts=targets, ports=ports, arguments=args)
        return nm
    except nmap.PortScannerError as e:
        print(f"[-] Nmap error: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(3)


def display_results(nm: "nmap.PortScanner"):
    """
    Pretty-prints scan results: host state, MAC, open ports with service info,
    and OS guesses if available.
    """
    print("\n================= Scan Results =================")
    for host in nm.all_hosts():
        state = nm[host].state() if 'status' in nm[host] else "unknown"
        hostname = nm[host].hostname() or "-"
        print(f"\nHost: {host} ({hostname})\nState: {state}")

        # MAC address (if found in hostscript/ARP/NSE)
        mac = None
        try:
            if "addresses" in nm[host] and "mac" in nm[host]["addresses"]:
                mac = nm[host]["addresses"]["mac"]
        except Exception:
            pass
        if mac:
            print(f"MAC: {mac}")

        # Ports per protocol
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            ports = sorted(lport)
            if not ports:
                continue
            print(f"\nProtocol: {proto}")
            print("PORT\tSTATE\tSERVICE\tVERSION")
            for p in ports:
                entry = nm[host][proto][p]
                state = entry.get("state", "-")
                name = entry.get("name", "-")
                product = entry.get("product", "")
                version = entry.get("version", "")
                extrainfo = entry.get("extrainfo", "")
                version_str = " ".join(x for x in [product, version, extrainfo] if x).strip() or "-"
                print(f"{p}\t{state}\t{name}\t{version_str}")

        # OS detection results (if -O used and accessible)
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            print("\nOS Guesses:")
            for osguess in nm[host]["osmatch"][:5]:  # top 5 guesses
                name = osguess.get("name", "-")
                acc = osguess.get("accuracy", "-")
                print(f" - {name} (accuracy: {acc}%)")

    print("\n================================================\n")


def main():
    args = get_args()
    nm = run_nmap_scan(
        targets=args.targets,
        ports=args.ports,
        nmap_args=args.nmap_args,
        os_detect=args.os_detect
    )
    display_results(nm)


if __name__ == "__main__":
    main()
