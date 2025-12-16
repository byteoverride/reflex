# Reflex

**Reflex** is a high-performance XSS reflection checker tool written in Go. It is designed to aid bug bounty hunters and security professionals in identifying reflected parameters on web pages efficiently.

## 🚀 Features

* **Fast & Multi-threaded:** Scans multiple URLs concurrently with adjustable threading.
* **Smart 403 Handling:** Automatically pauses and initiates a cooldown if excessive 403 Forbidden errors are detected (WAF evasion).
* **Custom Headers:** Dynamically inject custom headers (e.g., for authentication or bug bounty program identification).
* **Payload Injection:** Automatically identifies reflection points and saves ready-to-use URLs.
* **Stdin Support:** Pipe URLs directly from other tools (like waybackurls or gau).

## 📦 Installation

To install Reflex, ensure you have **Go** installed and run:

```bash
go install [github.com/byteoverride/reflex@latest](https://github.com/byteoverride/reflex@latest)

```

##🛠️ Usage###Basic Scan```bash
reflex -f urls.txt

```

###Scan with Custom HeadersUseful for authenticated scans or program-specific headers.

```bash
reflex -f urls.txt -H "Cookie: session=12345" -H "X-Bug-Bounty: byteoverride"

```

###Piping from Stdin```bash
cat urls.txt | reflex -t 30

```
## 📋 Options

| Flag       | Description                                   | Default         |
|------------|-----------------------------------------------|-----------------|
| `-f`       | Path to the text file containing URLs          | `stdin`        |
| `-o`       | Output file for results                        | `xss_go.txt`   |
| `-t`       | Number of concurrent threads                  | `20`            |
| `-timeout` | HTTP timeout in seconds                       | `10`            |
| `-H`       | Custom header (can be used multiple times)     | `None`         |
| `-v`       | Enable verbose mode for debugging              | `False`        |


##⚠️ DisclaimerThis tool is strictly for educational purposes and authorized security testing. The author is not responsible for any misuse or damage caused by this tool.


