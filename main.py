import sys
import host_preproc
import argparse
import port_scanning

if __name__ == '__main__':
    print("NPT Automation")
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--resolve", action="store_true", help="Used to resolve IPs for the given host")
    parser.add_argument("-p", "--portscan", action="store_true", help="Perform port scanning for te host IPs")
    parser.add_argument("-t", "--target", help="Host to scan")

    args = parser.parse_args()
    if not args.target:
        print("Host name required to run the scan")
        sys.exit(-1)

    if args.resolve:
        print(host_preproc.resolve_ip(args.resolve))

    if args.portscan:
        print("Scanning ports for " + args.target + ":")
        for ip in host_preproc.resolve_ip(args.target):
            port_scanning.full_scan(ip)

