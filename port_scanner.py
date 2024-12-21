import socket
import ipaddress
from common_ports import ports_and_services

def get_open_ports(target, port_range, verbose=False):
    def is_valid_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def is_valid_hostname(hostname):
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False

    # Validate target
    ip = None
    if is_valid_ip(target):
        ip = target
    elif is_valid_hostname(target):
        ip = socket.gethostbyname(target)
    else:
        if target.replace('.', '').isdigit():
            return "Error: Invalid IP address"
        return "Error: Invalid hostname"

    open_ports = []

    # Scan ports in the range
    for port in range(port_range[0], port_range[1] + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue

    # If verbose mode, format output
    if verbose:
        host_info = target if is_valid_hostname(target) else ip
        result = f"Open ports for {host_info} ({ip})\nPORT     SERVICE"
        for port in open_ports:
            service = ports_and_services.get(port, "unknown")
            result += f"\n{port:<9}{service}"
        return result

    return open_ports

# Example usage
if __name__ == "__main__":
    print(get_open_ports("scanme.nmap.org", [20, 80], True))
