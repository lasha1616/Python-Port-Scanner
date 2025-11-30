# IPv4 TCP პორტ სკანერი

ეს ინსტრუმენტი შექმნილია Python-ით, რომლის მიზანია IPv4 TCP პორტების სკანირება.
აღნიშნული ინსტრუმენტი საშუალებას იძლევა სწრაფად შეამოწმოს თითეულ IP მისამართზე პორტი არის თუ არა ღია.
IP მისამართები და შესაბამისი ღია პორტები, დროის მითითებით შეინახება ტექსტურ ფაილში სახელად `port-scan-result.txt`, შემდგომი ანალიზისთვის. 

------------------------------------------------------------------------

## ფუნქციონალის მოკლე აღწერა

-    TCP პორტებს სკანირების დიაპაზონი:  1 - 65535
-    IPv4 მისამართი - ნებისმიერი (A, B, C კლასი)
-    IP მისამართის სკანირების დიაპაზონი **მხოლოდ IV ოქტეტი** - (xxx.xxx.xxx.**0-255**)
-    თითოეული პორტის შემოწმების დრო **0.01 წამი**
-    სკანირების შედეგი ინახება ფაილში `port-scan-result.txt`
-    დაცულია შეცდომებისგან - IP მისამართის და პორტების არასწორად შეყვანის შემთხვევაში
-    მოიცავს დეტალურ input‑validation ბლოკებს (IP, ჰოსტი, პორტი)

------------------------------------------------------------------------

# მოთხოვნები

## სკრიპტი იყენებს მხოლოდ სტანდარტულ Python ბიბლიოთეკებს (Python 3.x), ამიტომ არ არის საჭირო გარე დამოკიდებულებების დაყენება.

``` python
import socket
import datetime
```

------------------------------------------------------------------------

# საწყისი ინფორმაციული ბანერი
``` python
<==================IPv4 Port Scanner Tool==================>
[*] Scans TCP ports range from 1 to 65535.
[*] It can scan any IPv4 address ports but IP range works only in FOURTH octet (xxx.xxx.xxx.0-255).
[*] It saves results in port-scan-result.txt file, included timestamp.
[*] Each port scan time is 0.01 seconds (defined by s.settimeout(0.01))
[*] IMPORTANT: If this tool doesn't find open ports (for a lot of reasons) it doesn't mean host of the IP is offline!

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
```
------------------------------------------------------------------------


# გამოყენების ინსტრუქცია

1.  გაუშვი ფაილი შემდეგი ბრძანებით:

``` bash
python3 Port_Scanner.py (from Linux)
```
```powershell
python Port_Scanner.py (from Windows)
```

2. შეიყვანე პირველი IP მისამართი: **Enter first IP address to start port scan:**
3. შეიყვანე ბოლო IP მისამართი: **Please input last IP address range of**
4. შეიყვანე პირველი პორტი: **Input first port. Valid range (1-65535):**
5. შეიყვანე ბოლო პორტი: **Input last port**
5. შედეგები შეინახება ფაილში: `port-scan-result.txt`

------------------------------------------------------------------------
