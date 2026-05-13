import socket
import subprocess
import ipaddress
import platform
import concurrent.futures
import re
import time
import uuid

# ==========================================================
# Get Local IP
# ==========================================================

def get_local_ip():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:

        s.connect(("8.8.8.8", 80))

        local_ip = s.getsockname()[0]

    finally:

        s.close()

    return local_ip


# ==========================================================
# Get Own MAC Address
# ==========================================================

def get_own_mac():

    mac = ':'.join([
        '{:02x}'.format(
            (uuid.getnode() >> ele) & 0xff
        )
        for ele in range(0, 8 * 6, 8)
    ][::-1])

    return mac.upper().replace(":", "-")


# ==========================================================
# Generate Subnet
# ==========================================================

def get_subnet():

    local_ip = get_local_ip()

    network = ipaddress.ip_network(
        local_ip + "/24",
        strict=False
    )

    return network


# ==========================================================
# Ping Device
# ==========================================================

def ping(ip):

    system = platform.system().lower()

    if system == "windows":

        command = [
            "ping",
            "-n",
            "1",
            "-w",
            "1000",
            str(ip)
        ]

    else:

        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            str(ip)
        ]

    start = time.time()

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    end = time.time()

    success = result.returncode == 0

    latency = round((end - start) * 1000, 2)

    return success, latency


# ==========================================================
# Better Hostname Detection
# ==========================================================

def _resolve_hostname_reverse_dns(ip):

    try:

        hostname = socket.gethostbyaddr(ip)[0]

        if hostname and hostname != ip:
            return hostname

    except Exception:
        pass

    return None


def _resolve_hostname_netbios(ip):

    try:

        result = subprocess.check_output(
            f"nbtstat -A {ip}",
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL
        )

        for line in result.splitlines():

            if "<20>" in line or "<00>" in line:

                parts = line.split()

                if parts:

                    hostname = parts[0].strip()

                    if hostname != "GROUP":

                        return hostname

    except Exception:
        pass

    return None


def _resolve_hostname_ping(ip):

    try:

        result = subprocess.check_output(
            f"ping -a -n 1 {ip}",
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL
        )

        first_line = result.splitlines()[0]

        if "Pinging" in first_line:

            hostname = first_line.split()[1]

            if hostname != ip:

                return hostname

    except Exception:
        pass

    return None


def get_hostname(ip):

    for resolver in (

        _resolve_hostname_reverse_dns,
        _resolve_hostname_netbios,
        _resolve_hostname_ping,

    ):

        hostname = resolver(ip)

        if hostname:

            # Remove fake/service-based names
            blocked_names = [
                "mail",
                "mailserver",
                "smtp",
                "imap",
                "pop3"
            ]

            if hostname.lower() not in blocked_names:

                return hostname

    return "Unknown"


# ==========================================================
# Get MAC Address
# ==========================================================

def get_mac(ip):

    try:

        arp_output = subprocess.check_output(
            "arp -a",
            text=True
        )

        pattern = rf"{re.escape(str(ip))}\s+([a-fA-F0-9\-:]+)"

        match = re.search(pattern, arp_output)

        if match:

            return match.group(1).upper()

    except Exception:
        pass

    return "---"


# ==========================================================
# Vendor Detection
# ==========================================================

def get_vendor(mac):

    try:

        if mac == "---":
            return "Unknown"

        prefix = mac.replace(
            ":",
            ""
        ).replace(
            "-",
            ""
        ).upper()[:6]

        print("Checking MAC:", prefix)

        with open("macvendors.txt", "r") as f:

            for line in f:

                vendor_prefix, vendor_name = line.strip().split(" ", 1)

                if prefix == vendor_prefix:

                    return vendor_name

    except Exception:
        pass

    return "Unknown"


# ==========================================================
# Smart Device Identification
# ==========================================================

def identify_device(open_ports):

    ports = []

    for p in open_ports:

        if isinstance(p, dict):

            ports.append(p["Port"])

        else:

            ports.append(p)

    if 25 in ports and 110 in ports and 143 in ports:
        return "Mail Server"

    if 445 in ports or 139 in ports:
        return "Windows Device"

    if 80 in ports or 443 in ports:
        return "Web Server"

    if 3306 in ports:
        return "MySQL Server"

    if 5432 in ports:
        return "PostgreSQL Server"

    if 22 in ports:
        return "Linux/SSH Device"

    if 3389 in ports:
        return "Remote Desktop Host"

    return "Unknown Device"


# ==========================================================
# Scan Single Device
# ==========================================================

def scan_device(ip):

    success, latency = ping(ip)

    if success:

        local_ip = get_local_ip()

        hostname = get_hostname(ip)

        # ==================================================
        # LOCAL DEVICE MAC FIX
        # ==================================================

        if str(ip) == local_ip:

            mac = get_own_mac()

        else:

            mac = get_mac(ip)

        vendor = get_vendor(mac)

        # ==================================================
        # LOCAL DEVICE NAME
        # ==================================================

        if str(ip) == local_ip:

            hostname = socket.gethostname()

        return {

            "IP": str(ip),

            "Hostname": hostname,

            "MAC": mac,

            "Vendor": vendor,

            "Latency": f"{latency} ms",

            "Status": "Online"
        }

    return None


# ==========================================================
# Discover Devices
# ==========================================================

def discover_devices():

    network = get_subnet()

    devices = []

    print(f"\nScanning Network: {network}\n")

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=100
    ) as executor:

        results = executor.map(
            scan_device,
            network.hosts()
        )

        for device in results:

            if device:

                devices.append(device)

                print(
                    f"{device['IP']:15}"
                    f"{device['Hostname']:25}"
                    f"{device['MAC']:20}"
                    f"{device['Vendor']:15}"
                    f"{device['Latency']:12}"
                    f"{device['Status']}"
                )

    return devices


# ==========================================================
# Flask Compatible Function
# ==========================================================

def scan_network():

    return discover_devices()


# ==========================================================
# Main
# ==========================================================

if __name__ == "__main__":

    print(
        f"{'IP':15}"
        f"{'Hostname':25}"
        f"{'MAC':20}"
        f"{'Vendor':15}"
        f"{'Latency':12}"
        f"Status"
    )

    print("-" * 100)

    discover_devices()