# autorecon-engine/main.py

from modules.subenum import run_subdomain_enum
from modules.prober import run_prober
from modules.vulnscan import run_vulnscan
from modules.logger import setup_logging
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="AutoRecon Engine - Automate Reconnaissance")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-l", "--list", help="List of domains")
    args = parser.parse_args()

    if not args.domain and not args.list:
        print("[!] Provide a domain (-d) or list of domains (-l)")
        return

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.list:
        with open(args.list, 'r') as f:
            domains.extend([line.strip() for line in f.readlines()])

    for domain in domains:
        print(f"[*] Starting recon on: {domain}")
        out_dir = os.path.join("output", domain)
        os.makedirs(out_dir, exist_ok=True)

        setup_logging(out_dir)
        subs = run_subdomain_enum(domain, out_dir)
        alive_hosts = run_prober(subs, out_dir)
        run_vulnscan(alive_hosts, out_dir)


if __name__ == "__main__":
    main()
