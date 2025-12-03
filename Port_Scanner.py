import socket
import datetime
import sys

scan_time = datetime.datetime.now()
print("<==================IPv4 Port Scanner Tool==================>")
print("[*] Scans TCP ports range from 1 to 65535.")
print(
    "[*] It can scan any IPv4 address ports but IP range works only in FOURTH octet (xxx.xxx.xxx.0-255)."
)
print("[*] It saves results in port-scan-result.txt file, included timestamp.")
print("[*] Each port scan time is 0.01 seconds (defined by s.settimeout(0.01))")
print(
    "[*] IMPORTANT: If this tool doesn't find open ports (for a lot of reasons) it doesn't mean host of the IP is offline!"
)
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


def check_port(ip, port):
    # შექიმნა სოკეტი s სადაც socket.AF_INET აღნიშნავს IPv4-ს, ხოლო socket.SOCK_STREAM აღნიშნავს TCP-ს.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # სკანირების დაყოვნება თითოეულ იტერაციაზე 10 მილიწამი
    s.settimeout(0.01)

    # პირველი ნაბიჯი სადაც იწყება IP-ზე და პორტზე, TCP კავშირის დამყარება SYN პაკეტის გაგზავნით (TCP 3-way handshake)
    # კავშირის დამყარების მცდელობის შემდეგ s.close()-ით აუცილებელია სოკეტის დახურვა, რესურსის გამოსათავისუფლებლად, მიუხედავად იმისა მოხდა თუ არა წარმატებით დაკავშირება
    # if result == 0: return port - ნიშნავს თუ დაბრუნდა კოდი 0 ე.ი. მოპასუხე ჰოსტისგან წარმატებით მივიღეთ პასუხი SYN-ACK პაკეტით, რაც ნიშნავს რომ პორტი ღიაა და ჰოსტი უსმენს, წინააღმდეგ შემთხვევაში ნიშნავს რომ პორტი ღია არაა.
    try:
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return port
    except Exception as e:
        return None
    return None


# პირველი IP მისამართის შეყვანა. ვალიდაცია და შეცდომების კონტროლი.
while True:

    # შეყვანილი IP მისამართი გამოყოფილი აუცილებლად წერტილებით, განცალკევდება split-ით და მიიღება list ოთხი სტრინგ ელემენტით.
    start_ip_string = input(
        "Please input IPv4 address range to perform scanning. \n\nEnter first IP address to start port scan: "
    ).split(".")
    valid_range = True

    # პირველი ვალიდაცია
    # თუ კი შეყვანილი IP მისამართი არ იქნება აუცილებლად ოთხი ოქტეტი, ანუ არ იქნება ოთხი ელემენტის მქონე ლისტი, continue ახლიდან გაუშვებს ციკლს.
    if len(start_ip_string) != 4:
        print(
            "ERROR: Invalid IP format. Must have exactly four parts separated by dots."
        )
        continue

    # მეორე ვალიდაცია
    # მოწმდება თითოეული ოქტეტის (ელემენტის) ვალიდაცია 0-დან 255-მდე, რათა გამოირიცხოს უარყოფითი ან 255-ზე მეტი რიცხვის შეყვანა
    for octet_str in start_ip_string:
        try:
            # გადაჰყავს "octet_str" string-დან integer-ში
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

# ბოლო IP მისამართის შეყვანა
while True:
    try:
        host_last_ip = int(
            input(
                f"\nPlease input last IP address range of {start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{start_ip_string[3]} - "
            )
        )
        if not (0 <= host_last_ip <= 255):
            print("ERROR: The last octet must be between 0 and 255.")
            continue
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


# პირველი პორტის შეყვანა
while True:
    try:
        port_first = int(input("\nInput first port. Valid range (1-65535): "))

        ## პორტის მინიმალური და მაქსიმალური დიაპაზონია 1-დან 65535-მდე
        if not (1 <= port_first <= 65535):
            print(
                "ERROR: First port is outside the valid range (1-65535). Please try again."
            )
            continue
        break
    # თუ არ შევიყვანთ integer რიცხვს, დაგვიბეჭდავს შესაბამის შეცდომას
    except ValueError:
        print("ERROR: Port inputs must be whole numbers. Please try again.")

# ბოლო პორტის შეყვანა
while True:
    try:
        port_last = int(
            input(
                f"\nInput last port. Equal or greater than {port_first} and less than 65535: "
            )
        )
        if not (1 <= port_last <= 65535):
            print(
                "ERROR: Last port is outside the valid range (1-65535). Please try again."
            )
            continue
        # არ შეიძლება ბოლო პორტის რიცხვითი მნიშვნელობა ნაკლები იყოს პირველ პორტზე
        if port_first > port_last:
            print(
                f"ERROR: Last port you input {port_last} must be greater than or equal to the first {port_first} port. Please try again."
            )
            continue
        break
    except ValueError:
        print("ERROR: Port inputs must be whole numbers. Please try again.")

# შედეგის შენახვა ფაილის სახით, კერძოდ IP-ისა და შესაბამისი ღია პორტების და თარიღის მითითება
# with open("port-scan-result.txt", "a") as file: გახსნის ფაილს სახელწოდებით port-scan-result.txt და ბოლო ხაზიდან დაამატებს ახალ ჩანაწერებს, შემდეგ კი დახურავს.
with open("port-scan-result.txt", "a") as file:

    # გარე ციკლი (IP მისამართებისთვის) მეოთხე start_ip_string[3] ოქტეტისათვის. იწყება პირველი IP-დან და ასრულებს ბოლო IP-ით. იტერაცია იზრდება +1-ით.
    for ip_octets in range(int(start_ip_string[3]), host_last_ip + 1, 1):

        # პირველი, მეორე და მესამე ელემენტების გაერთიანებით, ემატება მეოთხე ip_octets, რომლებიც გამოიყოფა წერტილებით
        ip_address = f"{start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{ip_octets}"

        # ამ ფორმატით ჩაიწერება IP მისამართები და სკანირების დრო, ვიდრე დაიწყება პორტების სკანირება - კონტექსტ მენეჯერის გამოყენებით
        file.write(
            f"\n--- SCAN STARTED AT: {scan_time.strftime('%d.%m.%Y %H:%M:%S')} ---\n"
            f"Scanned IP range is: {start_ip_string[0]}.{start_ip_string[1]}.{start_ip_string[2]}.{int(start_ip_string[3])} to .{host_last_ip}\n"
            f"Current IP: {ip_address}\nOpen Ports are:\n"
        )
        # შიდა ციკლი (პორტებისათვის) არსებული IP მისამართისთვის, საწყისი და საბოლოო პორტების სკანირების სრული ციკლი.
        for port_num in range(port_first, port_last + 1, 1):

            # ბეჭდავს სკანირების პროცესს. ყოველ ჯერზე \r (carriage return) გადაიტანს კურსორს საწყის ხაზზე და წინა ინფორმაციას თავზე გადააწერს ახალი ინფორმაციით.
            print(f"[*] Scanning {ip_address}:{port_num}...", end="\r")
            sys.stdout.flush()  # ყოველ იტერაციაზე ასუფთავებს buffer-ს

            # იძახებს check_port() ფუნქციას, რომელიც კონკრეტულ IP მისამართს და კონკრეტულ პორტის ნომერს ამოწმებს
            open_port = check_port(ip_address, port_num)

            # ამოწმებს შედეგს check_port() ფუნქციიდან. თუ შედეგი არ არის None (ანუ ღია პორტის ნომერი დაბრუნებულია), ამ პორტის ნომერი ჩაიწერება ფაილში ახალი ხაზიდან.
            if open_port is not None:
                file.write(f"{open_port}\n")
