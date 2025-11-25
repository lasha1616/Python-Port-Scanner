import socket
import datetime

scan_time = datetime.datetime.now()


def check_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.01)

    try:
        # Network operation is safely wrapped
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            return port

    except Exception as e:
        # Catches all system/network errors and allows the program to continue
        return None

    return None


# ======================================================================
# WELCOME AND INFORMATION SCREEN
# ======================================================================

print("<======        IPv4 Port Scanner Tool        ======>")
print("[*] Scans TCP ports range from 1 to 65535.")
print(
    "[*] IT can scan any IPv4 address ports but IP range works only to FOURTH octet! (In other words xxx.xxx.xxx.0-255)."
)
print("[*] It saves results in port-scan-result.txt file, included timestamp.")
print("[*] Each port scan time is 0.01 seconds (defined by s.settimeout(0.01))")
print(
    "[*] IMPORTANT: If this tool doesn't find open ports (for a lot of reasons) it doesn't mean host of the IP is offline!"
)
print(
    """
Well-Known TCP Ports (0-1023) by the Internet Assigned Numbers Authority (IANA)
22 - SSH (Secure Shell)
23 - Telnet
25 - SMTP (Simple Mail Transfer Protocol)
53 - DNS (Domain Name System)
80 - HTTP (Hypertext Transfer Protocol)
110 - POP3 (Post Office Protocol v3)
443 - HTTPS (HTTP Secure)
3389 - RDP (Remote Desktop Protocol)
"""
)

# ======================================================================
# INPUT VALIDATION BLOCKS
# ======================================================================

## 🛡️ 1. Start IP Address Input Validation (Format and Range)

while True:
    start_ip_string = input(
        "Please input IPv4 address range. First Ip address to start port scan is the ip address you enter here: (IPv4 format example: 192.168.1.1): "
    ).split(".")
    valid_range = True

    if len(start_ip_string) != 4:
        print(
            "ERROR: Invalid IP format. Must have exactly four parts separated by dots."
        )
        continue

    for octet_str in start_ip_string:
        try:
            octet_int = int(octet_str)
            if not (0 <= octet_int <= 255):
                print(f"ERROR: Octet '{octet_str}' is outside the valid range (0-255).")
                valid_range = False
                break
        except ValueError:
            print(f"ERROR: Octet '{octet_str}' is not a valid number.")
            valid_range = False
            break

    if valid_range:
        print("Start IP address successfully validated.")
        break

# ----------------------------------------------------------------------

## 🛡️ 2. Host Last IP Input Validation (Number, Range, and Logic)

while True:
    try:
        host_last_ip = int(
            input(
                f"Please input last IP address range of {start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{start_ip_string[3]} - "
            )
        )

        # Check 1: 0-255 Range
        if not (0 <= host_last_ip <= 255):
            print("ERROR: The last octet must be between 0 and 255.")
            continue

        # Check 2: End IP >= Start IP
        start_host_ip = int(start_ip_string[3])
        if host_last_ip < start_host_ip:
            print(
                f"ERROR: The last IP address you input - ({host_last_ip}) must be greater than or equal to the first IP address - ({start_host_ip}). Please try again.",
            )
            continue

        print("End IP address successfully validated.")
        break

    except ValueError:
        print("ERROR: The last octet must be a whole number. Please try again.")

# ----------------------------------------------------------------------

## 🛡️ 3a. First Port Input Validation (Immediate Feedback)

while True:
    try:
        port_first = int(input("Input first port. Valid range (1-65535): "))

        # Check 1: Valid Range (1 to 65535)
        if not (1 <= port_first <= 65535):
            print(
                "ERROR: First port is outside the valid range (1-65535). Please try again."
            )
            continue  # Re-prompt immediately

        break  # Success! Exit this loop

    except ValueError:
        print("ERROR: Port inputs must be whole numbers. Please try again.")

# ----------------------------------------------------------------------

## 🛡️ 3b. Last Port Input Validation (Immediate Feedback)

while True:
    try:
        port_last = int(
            input(
                f"Input last port. Equal or greater than {port_first} and less than 65535: "
            )
        )

        # Check 1: Valid Range (1 to 65535)
        if not (1 <= port_last <= 65535):
            print(
                "ERROR: Last port is outside the valid range (1-65535). Please try again."
            )
            continue  # Re-prompt immediately

        # Check 2: Order (First Port <= Last Port)
        if port_first > port_last:
            print(
                f"ERROR: Last port you input {port_last} must be greater than or equal to the first {port_first} port. Please try again."
            )
            continue  # Re-prompt immediately

        break  # Success! Exit this loop

    except ValueError:
        print("ERROR: Port inputs must be whole numbers. Please try again.")

# ======================================================================
# SCANNING LOGIC
# ======================================================================

with open("port-scan-result.txt", "a") as file:

    for ip_octets in range(int(start_ip_string[3]), host_last_ip + 1, 1):

        ip_address = f"{start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{ip_octets}"

        file.write(
            f"\n--- SCAN STARTED AT: {scan_time.strftime('%d.%m.%Y %H:%M:%S')} ---\n"
            f"Scanned IP range is: {start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{int(start_ip_string[3])} to .{host_last_ip}\n"
            f"Current IP: {ip_address}\nOpen Ports are:\n"
        )

        for port_num in range(port_first, port_last + 1, 1):

            open_port = check_port(ip_address, port_num)

            if open_port is not None:
                file.write(f"{open_port}\n")
