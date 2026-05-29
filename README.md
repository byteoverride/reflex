# Reflex

**Reflex** is a high-performance XSS reflection checker written in Go. It identifies reflected parameters on web pages and classifies the reflection context — purpose-built for bug bounty hunters and security professionals.

## Features

- **Concurrent scanning** with adjustable thread count
- **Reflection context detection** — identifies whether canary reflects in HTML body, attribute, `<script>` tag, comment, or response header
- **Randomized canary** per request — avoids static-string WAF signatures
- **Smart 403 handling** — auto-pauses with cooldown on WAF detection, retries with jitter (capped at 3 retries per URL)
- **Proxy support** — route through Burp, Caido, or any HTTP/SOCKS5 proxy
- **Per-host rate limiting** — avoid triggering rate limits on individual targets
- **JSONL output** — machine-readable output for tool chaining
- **User-Agent rotation** — randomized per request from a pool of common browsers
- **URL deduplication** — skips duplicate URLs automatically
- **Parameter name reflection** — optionally tests if the parameter name itself is reflected
- **Response header reflection** — checks if canary appears in response headers
- **Body size limit** — caps response reads at 5MB to prevent OOM on large pages
- **Stdin support** — pipe URLs from waybackurls, gau, katana, etc.
- **Progress stats** — periodic updates on processed/reflected/errors/skipped counts
- **Graceful shutdown** — Ctrl+C prints summary before exiting

## Installation

```bash
go install github.com/byteoverride/reflex@latest
```

## Usage

### Basic scan

```bash
reflex -f urls.txt
```

### Scan with custom headers

```bash
reflex -f urls.txt -H "Cookie: session=12345" -H "X-Bug-Bounty: byteoverride"
```

### Pipe from other tools

```bash
cat urls.txt | reflex -t 30
```

```bash
echo "https://target.com" | gau | reflex -rate 10 -json -o results.jsonl
```

### Through Burp/Caido proxy

```bash
reflex -f urls.txt -proxy http://127.0.0.1:8080
```

### JSON output for tool chaining

```bash
reflex -f urls.txt -json -o results.jsonl
```

### Rate-limited scan with param name checks

```bash
reflex -f urls.txt -rate 5 -check-names
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `-f` | File containing URLs | stdin |
| `-o` | Output file for results | `reflex_out.txt` |
| `-t` | Number of concurrent threads | `20` |
| `-timeout` | HTTP timeout in seconds | `10` |
| `-H` | Custom header (repeatable) | — |
| `-proxy` | HTTP/SOCKS5 proxy URL | — |
| `-json` | Output results as JSONL | `false` |
| `-rate` | Max requests/sec per host (0 = unlimited) | `0` |
| `-check-names` | Test if parameter names are reflected | `false` |
| `-no-color` | Disable ANSI colored output | `false` |
| `-silent` | Suppress banner and progress output | `false` |
| `-v` | Verbose mode (show errors) | `false` |

## Output Format

### Text (default)

```
https://target.com/search?q={payload} [html-body]
https://target.com/page?name={payload} [html-attr,script]
```

### JSONL (`-json`)

```json
{"url":"https://target.com/search?q={payload}","parameter":"q","contexts":["html-body"],"timestamp":"2025-01-15T12:00:00Z"}
```

### Reflection Contexts

| Context | Meaning |
| --- | --- |
| `html-body` | Reflected in HTML body text |
| `html-attr` | Reflected inside an HTML tag attribute |
| `script` | Reflected inside a `<script>` block |
| `comment` | Reflected inside an HTML comment |
| `header:<Name>` | Reflected in a response header |

## Disclaimer

This tool is strictly for educational purposes and authorized security testing. The author is not responsible for any misuse or damage caused by this tool.
