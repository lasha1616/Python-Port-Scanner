# ======================================================================
# IMPORTS AND INITIAL SETUP
# ======================================================================

import socket  #  Module for handling network connections (creating the TCP scanner).
import datetime  #  Module for working with dates and times (used for timestamps).

# Record the current time when the script starts. This timestamp is used
# later in the output file to mark when the scan began.
scan_time = datetime.datetime.now()


# ======================================================================
# WELCOME AND INFORMATION SCREEN
# ======================================================================

# Print a decorative banner for the tool.
print("<==================IPv4 Port Scanner Tool==================>")

# Print key tool information points for the user.
print("[*] Scans TCP ports range from 1 to 65535.")
print(
    "[*] It can scan any IPv4 address ports but IP range works only in FOURTH octet (xxx.xxx.xxx.0-255)."
)
print("[*] It saves results in port-scan-result.txt file, included timestamp.")
print("[*] Each port scan time is 0.01 seconds (defined by s.settimeout(0.01))")
print(
    "[*] IMPORTANT: If this tool doesn't find open ports (for a lot of reasons) it doesn't mean host of the IP is offline!"
)

# Print lists of informational data (Private Ranges and Well-Known Ports)
# using a multi-line string (triple quotes) for clean formatting.
print(
    """
Private IPv4 address ranges:                | Prefix length:
Class A: 10.0.0.0     to 10.255.255.255     | 10.0.0.0/8
Class B: 172.16.0.0   to 172.31.255.255     | 172.16.0.0/12
Class C: 192.168.0.0  to 192.168.255.255    | 192.168.0.0/16


Well-Known TCP Ports (0-1023) by the Internet Assigned Numbers Authority (IANA):
22 - SSH (Secure Shell)
23 - Telnet
25 - SMTP (Simple Mail Transfer Protocol)
53 - DNS (Domain Name System)
80 - HTTP (Hypertext Transfer Protocol)
110 - POP3 (Post Office Protocol v3)
443 - HTTPS (HTTP Secure)
445 - MS SMB (Microsoft Server Message Block)
3389 - RDP (Remote Desktop Protocol)
"""
)


# ======================================================================
# CORE FUNCTION: CHECK PORT STATUS
# ======================================================================


def check_port(ip, port):
    # Create a new socket object:
    # socket.AF_INET specifies the IPv4 address family.
    # socket.SOCK_STREAM specifies the TCP protocol (connection-oriented).
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set a timeout for the connection attempt (0.01 seconds).
    # This prevents the scanner from hanging on unresponsive ports.
    s.settimeout(0.01)

    try:
        # The entire network operation is safely wrapped in a try/except block.

        # s.connect_ex() attempts to connect to the given IP and port.
        # It is non-blocking and returns an error code (non-zero) or 0 on success.
        result = s.connect_ex((ip, port))

        # Always close the socket immediately after the attempt to free system resources.
        s.close()

        # Check if the connection was successful. A result code of 0 means the port is OPEN.
        if result == 0:
            return port  # Return the port number to indicate it's open.

    except Exception as e:
        # Catches all possible system/network errors that occur during the attempt
        # (e.g., host unreachable, firewall issue).
        # It allows the program to continue scanning instead of crashing.
        return None  # Return None to indicate the port is not open/accessible.

    # If connect_ex() returned a non-zero error code (port closed/filtered), return None.
    return None


# ======================================================================
# INPUT VALIDATION BLOCKS
# ======================================================================

## 1. Start IP Address Input Validation (Format and Range)

# Start an infinite loop that runs until a valid input breaks it.
while True:
    # Prompt user for the start IP address. .split(".") separates the string into a list of four octet strings.
    start_ip_string = input(
        "Please input IPv4 address range to perform scanning. \n\nEnter first IP address to start port scan: "
    ).split(".")
    valid_range = True  # Flag to track if validation is successful.

    # Check 1: Must have exactly four parts (octets) separated by dots.
    if len(start_ip_string) != 4:
        print(
            "ERROR: Invalid IP format. Must have exactly four parts separated by dots."
        )
        continue  # Skip to the next loop iteration (re-prompt).

    # Check 2 & 3: Iterate through each octet string to check value and type.
    for octet_str in start_ip_string:
        try:
            # Attempt to convert the octet string to an integer. Fails if non-numeric (ValueError).
            octet_int = int(octet_str)

            # Check 3: Ensure the integer is within the valid range (0 to 255).
            if not (0 <= octet_int <= 255):
                print(f"ERROR: Octet '{octet_str}' is outside the valid range (0-255).")
                valid_range = False
                break  # Stop checking and break out of the 'for' loop.

        except ValueError:
            # Catches if the input was not a valid number (e.g., letters).
            print(f"ERROR: Octet '{octet_str}' is not a valid number.")
            valid_range = False
            break  # Stop checking and break out of the 'for' loop.

    # If the flag is still True (no errors found).
    if valid_range:
        print("Start IP address successfully validated.")
        break  # Exit the 'while' loop.

# ----------------------------------------------------------------------

## 2. Host Last IP Input Validation (Number, Range, and Logic)

while True:
    try:
        # Prompt user for the last octet of the end IP.
        host_last_ip = int(
            input(
                f"\nPlease input last IP address range of {start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{start_ip_string[3]} - "
            )
        )

        # Check 1: Must be within the 0-255 range.
        if not (0 <= host_last_ip <= 255):
            print("ERROR: The last octet must be between 0 and 255.")
            continue

        # Check 2: End IP must be greater than or equal to the Start IP (in the last octet).
        start_host_ip = int(
            start_ip_string[3]
        )  # Get the last octet of the start IP for comparison.
        if host_last_ip < start_host_ip:
            print(
                f"ERROR: The last IP address you input - ({host_last_ip}) must be greater than or equal to the first IP address - ({start_host_ip}). Please try again.",
            )
            continue

        print("End IP address successfully validated.")
        break  # Exit the 'while' loop.

    except ValueError:
        # Catches if the input was not a whole number.
        print("ERROR: The last octet must be a whole number. Please try again.")

# ----------------------------------------------------------------------

## 3a. First Port Input Validation (Immediate Feedback)

while True:
    try:
        port_first = int(input("\nInput first port. Valid range (1-65535): "))

        # Check 1: Must be within the valid port range.
        if not (1 <= port_first <= 65535):
            print(
                "ERROR: First port is outside the valid range (1-65535). Please try again."
            )
            continue  # Re-prompt immediately

        break  # Success! Exit this loop

    except ValueError:
        print("ERROR: Port inputs must be whole numbers. Please try again.")

# ----------------------------------------------------------------------

## 3b. Last Port Input Validation (Immediate Feedback)

while True:
    try:
        # Prompt uses the validated port_first value for context.
        port_last = int(
            input(
                f"\nInput last port. Equal or greater than {port_first} and less than 65535: "
            )
        )

        # Check 1: Must be within the valid port range.
        if not (1 <= port_last <= 65535):
            print(
                "ERROR: Last port is outside the valid range (1-65535). Please try again."
            )
            continue  # Re-prompt immediately

        # Check 2: Last port must be greater than or equal to the first port.
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

# Open the output file in append mode ('a') to add new results without deleting old ones.
with open("port-scan-result.txt", "a") as file:

    # Outer loop: Iterates through the IP address range (from start octet to end octet, inclusive).
    for ip_octets in range(int(start_ip_string[3]), host_last_ip + 1, 1):

        # Reconstruct the full IP address string for the current host being scanned.
        ip_address = f"{start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{ip_octets}"

        # Write log header information to the output file.
        file.write(
            f"\n--- SCAN STARTED AT: {scan_time.strftime('%d.%m.%Y %H:%M:%S')} ---\n"
            f"Scanned IP range is: {start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{int(start_ip_string[3])} to .{host_last_ip}\n"
            f"Current IP: {ip_address}\nOpen Ports are:\n"
        )

        # Inner loop: Iterates through the port range (from port_first to port_last, inclusive).
        for port_num in range(port_first, port_last + 1, 1):

            # Call the core function to check the current port on the current IP.
            open_port = check_port(ip_address, port_num)

            # If the result is a port number (not None), it means the port is open.
            if open_port is not None:
                # Write the found open port number to the output file.
                file.write(f"{open_port}\n")
