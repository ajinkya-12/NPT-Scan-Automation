import sys
import requests
import os
import json
import time
import time
from host_preproc import is_valid_ip

API_endpoint = "https://api.ssllabs.com/api/v3/"


def send_api_request(path: str, payload: dir):
    endpoint = API_endpoint + path
    try:
        response = requests.get(endpoint, params=payload)
    except requests.exceptions.RequestException:
        print("Unable to send request.")
        sys.exit(-1)
    data = response.json()
    return data


def new_scan(host):
    print("*********** Starting SSLlab Scan *************")
    path = "analyze"
    payload = {
        "host": host,
        "publish": "off",
        "startNew": "on",
        "all": "done",
        "ignoreMismatch": "on"
    }
    result = send_api_request(path, payload)
    payload.pop("startNew")     # To recursively check the scan status
    while result["status"] != 'READY' and result["status"] != 'ERROR':
        print("Scan in progress...")
        time.sleep(15)
        result = send_api_request(path, payload)
    if os.path.exists("report_ssllab.json"):
        os.remove("report_ssllab.json")
    with open("report_ssllab.json", "w") as outfile:
        result_json = json.dumps(result, indent=4)
        outfile.write(result_json)
    print(json.dumps(result, indent=4))
    return result


def cached_scan(host):
    path = "analyze"
    payload = {
        "host": host,
        "publish": "off",
        "startNew": "off",
        "fromCache": "on",
        "all": "done"
    }
    result = send_api_request(path, payload)
    if os.path.exists("report_ssllab.json"):
        os.remove("report_ssllab.json")
    with open("report_ssllab.json", "w") as outfile:
        result_json = json.dumps(result, indent=4)
        outfile.write(result_json)
    # print(json.dumps(result, indent=4))
    return result


def parse_results(report: dict):
    for endpoint in report["endpoints"]:
        if is_valid_ip(endpoint["ipAddress"]):
            print("Results of IP: " + endpoint["ipAddress"])
            get_supported_tls_protocols(endpoint)
            get_supported_ciphers(endpoint)
    validate_expired_certs(report)


def get_supported_tls_protocols(endpoint):
    tls_versions = {
        "1.0": False,
        "1.1": False,
        "1.2": False,
        "1.3": False
    }
    print("TLS protocols supported by the server:")
    for protocol in endpoint["details"]["protocols"]:
        tls_versions[protocol["version"]] = True
    for pro in tls_versions.keys():
        if tls_versions[pro]:
            if pro in ["1.0", "1.1"]:
                print("TLS v" + pro + " supported. [VULNERABLE]")   # Add Colour for the tags
            else:
                print("TLS v" + pro + " supported.")
        else:
            print("TLS v" + pro + " not supported.")


def get_supported_ciphers(endpoint):
    tls_code = {
        "1.0": 0,
        "1.1": 0,
        "1.2": 0,
        "1.3": 0
    }
    for protocol in endpoint["details"]["protocols"]:
        tls_code[protocol["version"]] = protocol["id"]
    tls = 0
    for pro in endpoint["details"]["suites"]:
        for ver, code in tls_code.items():
            if code == pro["protocol"]:
                tls = ver
        print("\nCiphers supported by TLS v" + tls + ":")
        for cipher in pro["list"]:
            print(cipher["name"])   # Add a check for cipher strength and colour code


def check_cipher_strength(cipher):
    pass


def validate_expired_certs(result):
    for cert in result["certs"]:
        if cert["notAfter"] > time.time():
            pass
        else:
            print("The server uses a expired certificate.")     # Add colour
            return
    print("\nServer does not use a expired certificate.")


parse_results(cached_scan("www.google.com"))
