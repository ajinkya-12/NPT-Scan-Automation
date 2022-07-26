import sys
import nmap
import host_preproc
import json

nm = nmap.PortScanner()


def quick_scan(ip: str):
    scan_results = nm.scan(ip)
    print("Scan started at: " + scan_results["nmap"]["scanstats"]["timestr"])
    host_ip = list(scan_results['scan'].keys())[0]
    print("Host IP: " + host_ip)
    if scan_results['scan'][host_ip]['status']['state'] == "up":
        print("Server status: UP")
        print("List of open ports: ")
        tcp_results = scan_results['scan'][host_ip]['tcp']
        print("Port number \t Status \t Service \t Version")
        for port in tcp_results.keys():
            print(str(port) + " \t\t " + tcp_results[port]['state'] + " \t\t " + tcp_results[port]['product'] + " \t " + tcp_results[port]['version'])

    else:
        print("Server is down")
        sys.exit(-1)


# noinspection PyTypeChecker
def full_scan(ip: str):
    scan_results = nm.scan(ip, arguments="-p 1-65535 -T4 -A -v")
    print("Scan started at: " + scan_results["nmap"]["scanstats"]["timestr"])
    host_ip = list(scan_results['scan'].keys())[0]
    print("Host IP: " + host_ip)
    if scan_results['scan'][host_ip]['status']['state'] == "up":
        print("Server status: UP")
        print("List of open ports: ")
        tcp_results = scan_results['scan'][host_ip]['tcp']
        print("Port number \t Status \t Service \t Version")
        for port in tcp_results.keys():
            # Add validation for version details
            if tcp_results[port]['state'] == "open":
                print(str(port) + " \t\t " + tcp_results[port]['state'] + " \t\t " + tcp_results[port]['product'] + " \t " + tcp_results[port]['version'])
    else:
        print("Server is down")
        sys.exit(-1)

