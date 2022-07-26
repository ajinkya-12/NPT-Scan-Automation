import socket
import sys
import logging


def resolve_ip(host: str) -> [str]:
    ip_list = []
    try:
        ais = socket.getaddrinfo(host, 0, 0, 0, 0)
        for res in ais:
            if is_valid_ip(res[-1][0]):
                ip_list.append(res[-1][0])
        return list(set(ip_list))
    except Exception as e:
        print("Exception occurred: " + str(e))
        print("Enter valid hostname.")
        sys.exit(-1)


def is_valid_ip(address: str) -> bool:
    try:
        socket.inet_aton(address)
        return True
    except:
        return False
