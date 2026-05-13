import socket
import concurrent.futures

# ==========================================================
# Common Ports Dictionary
# ==========================================================

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask Server",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy"
}

# ==========================================================
# High Risk Ports
# ==========================================================

HIGH_RISK_PORTS = [21, 23, 445, 3389, 3306]

# ==========================================================
# Scan Single Port
# ==========================================================

def scan_port(ip, port):

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:

            service = COMMON_PORTS.get(port, "Unknown")

            banner = grab_banner(sock, port)

            risk = calculate_risk(port)

            sock.close()

            return {
                "Port": port,
                "Service": service,
                "Banner": banner,
                "Risk": risk,
                "Status": "Open"
            }

        sock.close()

    except Exception:
        pass

    return None


# ==========================================================
# Banner Grabbing
# ==========================================================

def grab_banner(sock, port):

    try:

        # ==================================================
        # HTTP / WEB SERVICES
        # ==================================================

        if port in [80, 8080, 8000, 5000, 443]:

            sock.send(
                b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )

        # ==================================================
        # SMTP SERVICES
        # ==================================================

        elif port in [25, 465, 587]:

            sock.send(
                b"HELO test\r\n"
            )

        # ==================================================
        # DEFAULT REQUEST
        # ==================================================

        else:

            sock.send(b"\r\n")

        # ==================================================
        # RECEIVE BANNER
        # ==================================================

        banner = sock.recv(1024).decode(
            errors="ignore"
        ).strip()

        # Remove line breaks
        banner = banner.replace("\r", " ")
        banner = banner.replace("\n", " ")

        # Limit size
        banner = banner[:120]

        if banner:
            return banner

        return "No Banner"

    except Exception:

        return "No Banner"


# ==========================================================
# Calculate Risk
# ==========================================================

def calculate_risk(port):

    if port in HIGH_RISK_PORTS:

        return "HIGH"

    elif port in [80, 443, 8080, 5000]:

        return "LOW"

    else:

        return "MEDIUM"


# ==========================================================
# Scan Target
# ==========================================================

def scan_target(ip):

    print(f"\nScanning Target: {ip}\n")

    print(
        f"{'Port':<10}"
        f"{'Service':<20}"
        f"{'Risk':<10}"
        f"{'Status'}"
    )

    print("-" * 60)

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:

        futures = []

        for port in COMMON_PORTS.keys():

            futures.append(
                executor.submit(scan_port, ip, port)
            )

        for future in concurrent.futures.as_completed(futures):

            result = future.result()

            if result:

                open_ports.append(result)

                print(
                    f"{str(result['Port']):<10}"
                    f"{result['Service']:<20}"
                    f"{result['Risk']:<10}"
                    f"{result['Status']}"
                )

    # Sort ports
    open_ports.sort(key=lambda x: x["Port"])

    return open_ports


# ==========================================================
# Flask Compatible Function
# ==========================================================

def scan_ports(ip):

    return scan_target(ip)


# ==========================================================
# Main
# ==========================================================

if __name__ == "__main__":

    target = input("Enter Target IP: ")

    scan_target(target)
