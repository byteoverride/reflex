package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	CanaryPrefix   = "rfx"
	PayloadMarker  = "{payload}"
	MaxRetries     = 3
	BackoffSeconds = 60
	ErrorThreshold = 10
	MaxBodySize    = 5 << 20 // 5MB
	ScannerBufSize = 512 << 10
)

const (
	CtxBody    = "html-body"
	CtxAttr    = "html-attr"
	CtxScript  = "script"
	CtxComment = "comment"
	CtxHeader  = "header"
)

var (
	cGreen  = "\033[92m"
	cRed    = "\033[91m"
	cBlue   = "\033[94m"
	cYellow = "\033[93m"
	cCyan   = "\033[96m"
	cReset  = "\033[0m"
)

var (
	statsProcessed int64
	statsReflected int64
	statsErrors    int64
	statsSkipped   int64
)

var (
	consecutive403s int32
	isPaused        int32
	pauseMu         sync.Mutex
	pauseCond       = sync.NewCond(&pauseMu)
)

var (
	retryCount sync.Map // string -> int
)

type arrayFlags []string

func (a *arrayFlags) String() string { return strings.Join(*a, ", ") }
func (a *arrayFlags) Set(v string) error {
	*a = append(*a, v)
	return nil
}

type Result struct {
	URL       string   `json:"url"`
	Param     string   `json:"parameter"`
	Contexts  []string `json:"contexts"`
	Timestamp string   `json:"timestamp"`
}

var (
	threads       int
	inputFile     string
	outputFile    string
	verbose       bool
	timeout       int
	customHeaders arrayFlags
	proxyURL      string
	jsonOut       bool
	noColor       bool
	silent        bool
	ratePerHost   int
	checkNames    bool
)

func main() {
	parseFlags()
	if noColor {
		disableColors()
	}
	if !silent {
		printBanner()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	seen := make(map[string]bool)
	jobs := make(chan string, 1000)
	results := make(chan Result, 100)
	var wg sync.WaitGroup

	writerDone := make(chan struct{})
	go func() {
		saveResults(results)
		close(writerDone)
	}()

	stopProgress := make(chan struct{})
	if !silent {
		go reportProgress(stopProgress)
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	go func() {
		readInput(jobs, seen)
		close(jobs)
	}()

	go func() {
		<-sig
		if !silent {
			printSummary()
		}
		os.Exit(0)
	}()

	wg.Wait()
	close(results)
	<-writerDone
	close(stopProgress)

	if !silent {
		printSummary()
	}
}

func parseFlags() {
	flag.IntVar(&threads, "t", 20, "Number of concurrent threads")
	flag.StringVar(&inputFile, "f", "", "File containing URLs (defaults to stdin)")
	flag.StringVar(&outputFile, "o", "reflex_out.txt", "Output file for results")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.IntVar(&timeout, "timeout", 10, "HTTP timeout in seconds")
	flag.Var(&customHeaders, "H", "Custom header (repeatable, e.g. -H 'Cookie: sess=abc')")
	flag.StringVar(&proxyURL, "proxy", "", "HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)")
	flag.BoolVar(&jsonOut, "json", false, "JSONL output format")
	flag.BoolVar(&noColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&silent, "silent", false, "Suppress banner and progress")
	flag.IntVar(&ratePerHost, "rate", 0, "Max requests/sec per host (0 = unlimited)")
	flag.BoolVar(&checkNames, "check-names", false, "Test if parameter names are reflected")
	flag.Parse()
}

func disableColors() {
	cGreen, cRed, cBlue, cYellow, cCyan, cReset = "", "", "", "", "", ""
}

func generateCanary() string {
	b := make([]byte, 8)
	rand.Read(b)
	return CanaryPrefix + hex.EncodeToString(b)
}

func readInput(jobs chan<- string, seen map[string]bool) {
	var scanner *bufio.Scanner
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Error opening file: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintf(os.Stderr, "Usage: cat urls.txt | reflex [flags]  or  reflex -f urls.txt [flags]\n")
			flag.PrintDefaults()
			os.Exit(1)
		}
		scanner = bufio.NewScanner(os.Stdin)
	}

	scanner.Buffer(make([]byte, ScannerBufSize), ScannerBufSize)

	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "https://" + u
		}
		if seen[u] {
			atomic.AddInt64(&statsSkipped, 1)
			continue
		}
		seen[u] = true
		jobs <- u
	}
}

type hostLimiter struct {
	mu      sync.Mutex
	minGap  time.Duration
	lastReq time.Time
}

func (hl *hostLimiter) wait() {
	hl.mu.Lock()
	defer hl.mu.Unlock()
	if gap := time.Since(hl.lastReq); gap < hl.minGap {
		time.Sleep(hl.minGap - gap)
	}
	hl.lastReq = time.Now()
}

var hostLimiters sync.Map

func waitRateLimit(host string) {
	if ratePerHost <= 0 {
		return
	}
	gap := time.Second / time.Duration(ratePerHost)
	val, _ := hostLimiters.LoadOrStore(host, &hostLimiter{minGap: gap})
	val.(*hostLimiter).wait()
}

func buildClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	if proxyURL != "" {
		p, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Invalid proxy URL: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		tr.Proxy = http.ProxyURL(p)
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
}

func randUA() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	return userAgents[n.Int64()]
}

func worker(jobs chan string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	client := buildClient()

	for rawURL := range jobs {
		checkPause()

		parsed, err := url.Parse(rawURL)
		if err != nil {
			atomic.AddInt64(&statsErrors, 1)
			continue
		}

		params := parsed.Query()
		if len(params) == 0 {
			atomic.AddInt64(&statsSkipped, 1)
			continue
		}

		waitRateLimit(parsed.Hostname())

		for param := range params {
			canary := generateCanary()
			tmp := cloneValues(params)
			tmp.Set(param, canary)

			testURL := cloneURL(parsed)
			testURL.RawQuery = tmp.Encode()

			contexts := checkReflection(client, testURL.String(), canary, rawURL, jobs)
			if len(contexts) > 0 {
				tmp.Set(param, PayloadMarker)
				q := strings.ReplaceAll(tmp.Encode(), url.QueryEscape(PayloadMarker), PayloadMarker)
				testURL.RawQuery = q

				r := Result{
					URL:       testURL.String(),
					Param:     param,
					Contexts:  contexts,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}
				fmt.Fprintf(os.Stderr, "%s[+] Reflected: %s [%s] param=%s%s\n",
					cGreen, testURL.String(), strings.Join(contexts, ","), param, cReset)
				results <- r
				atomic.AddInt64(&statsReflected, 1)
			}
		}

		if checkNames {
			for param := range params {
				canary := generateCanary()
				tmp := cloneValues(params)
				origVal := tmp.Get(param)
				tmp.Del(param)
				tmp.Set(canary, origVal)

				testURL := cloneURL(parsed)
				testURL.RawQuery = tmp.Encode()

				contexts := checkReflection(client, testURL.String(), canary, rawURL, jobs)
				if len(contexts) > 0 {
					tmp.Del(canary)
					tmp.Set(PayloadMarker, origVal)
					q := strings.ReplaceAll(tmp.Encode(), url.QueryEscape(PayloadMarker), PayloadMarker)
					testURL.RawQuery = q

					r := Result{
						URL:       testURL.String(),
						Param:     param + " (name)",
						Contexts:  contexts,
						Timestamp: time.Now().UTC().Format(time.RFC3339),
					}
					fmt.Fprintf(os.Stderr, "%s[+] Param name reflected: %s [%s] param=%s%s\n",
						cGreen, testURL.String(), strings.Join(contexts, ","), param, cReset)
					results <- r
					atomic.AddInt64(&statsReflected, 1)
				}
			}
		}

		atomic.AddInt64(&statsProcessed, 1)
	}
}

func checkReflection(client *http.Client, targetURL, canary, origURL string, jobs chan string) []string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		atomic.AddInt64(&statsErrors, 1)
		return nil
	}

	req.Header.Set("User-Agent", randUA())
	for _, h := range customHeaders {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "%s[!] %v%s\n", cRed, err, cReset)
		}
		atomic.AddInt64(&statsErrors, 1)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		handle403(origURL, jobs)
		return nil
	}
	atomic.StoreInt32(&consecutive403s, 0)

	var contexts []string

	for name, vals := range resp.Header {
		for _, v := range vals {
			if strings.Contains(v, canary) {
				contexts = append(contexts, CtxHeader+":"+name)
			}
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
	if err != nil {
		atomic.AddInt64(&statsErrors, 1)
		return contexts
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, canary) {
		return contexts
	}

	contexts = append(contexts, analyzeContexts(bodyStr, canary)...)
	return contexts
}

func analyzeContexts(body, canary string) []string {
	seen := make(map[string]bool)
	var out []string

	idx := 0
	for {
		pos := strings.Index(body[idx:], canary)
		if pos == -1 {
			break
		}
		pos += idx
		ctx := classifyContext(body, pos)
		if !seen[ctx] {
			seen[ctx] = true
			out = append(out, ctx)
		}
		idx = pos + len(canary)
	}

	if len(out) == 0 {
		out = append(out, CtxBody)
	}
	return out
}

func classifyContext(body string, pos int) string {
	before := body[:pos]

	if lastOpen, lastClose := strings.LastIndex(before, "<!--"), strings.LastIndex(before, "-->"); lastOpen > lastClose {
		return CtxComment
	}

	lowerBefore := strings.ToLower(before)
	if lastOpen, lastClose := strings.LastIndex(lowerBefore, "<script"), strings.LastIndex(lowerBefore, "</script"); lastOpen > lastClose {
		return CtxScript
	}

	lastTagOpen := strings.LastIndex(before, "<")
	lastTagClose := strings.LastIndex(before, ">")
	if lastTagOpen > lastTagClose {
		tagFragment := before[lastTagOpen:]
		lastEq := strings.LastIndex(tagFragment, "=")
		if lastEq != -1 {
			afterEq := tagFragment[lastEq:]
			if strings.Count(afterEq, "\"")%2 == 1 || strings.Count(afterEq, "'")%2 == 1 {
				return CtxAttr
			}
		}
		return CtxAttr
	}

	return CtxBody
}

func cloneValues(src url.Values) url.Values {
	dst := make(url.Values, len(src))
	for k, v := range src {
		dst[k] = append([]string(nil), v...)
	}
	return dst
}

func cloneURL(u *url.URL) *url.URL {
	u2 := *u
	return &u2
}

func handle403(failedURL string, jobs chan string) {
	newVal := atomic.AddInt32(&consecutive403s, 1)
	if newVal >= ErrorThreshold {
		if atomic.CompareAndSwapInt32(&isPaused, 0, 1) {
			go triggerCoolDown()
		}
	}

	val, _ := retryCount.LoadOrStore(failedURL, 0)
	count := val.(int)
	if count >= MaxRetries {
		if verbose {
			fmt.Fprintf(os.Stderr, "%s[-] Dropping after %d retries: %s%s\n", cYellow, MaxRetries, failedURL, cReset)
		}
		atomic.AddInt64(&statsErrors, 1)
		return
	}
	retryCount.Store(failedURL, count+1)

	go func() {
		jitter := time.Duration(500+mrand.Intn(3000)) * time.Millisecond
		time.Sleep(jitter)
		func() {
			defer func() { recover() }()
			jobs <- failedURL
		}()
	}()
}

func checkPause() {
	pauseMu.Lock()
	for atomic.LoadInt32(&isPaused) == 1 {
		pauseCond.Wait()
	}
	pauseMu.Unlock()
}

func triggerCoolDown() {
	fmt.Fprintf(os.Stderr, "\n%s[!] High 403 rate (%d consecutive). Cooling down %ds...%s\n",
		cRed, ErrorThreshold, BackoffSeconds, cReset)
	time.Sleep(time.Duration(BackoffSeconds) * time.Second)

	atomic.StoreInt32(&consecutive403s, 0)
	pauseMu.Lock()
	atomic.StoreInt32(&isPaused, 0)
	pauseCond.Broadcast()
	pauseMu.Unlock()

	fmt.Fprintf(os.Stderr, "%s[*] Resuming...%s\n", cBlue, cReset)
}

func saveResults(results <-chan Result) {
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] Error creating output file: %v%s\n", cRed, err, cReset)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for r := range results {
		if jsonOut {
			line, _ := json.Marshal(r)
			w.Write(line)
			w.WriteByte('\n')
		} else {
			fmt.Fprintf(w, "%s [%s]\n", r.URL, strings.Join(r.Contexts, ","))
		}
	}
}

func reportProgress(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			fmt.Fprintf(os.Stderr, "%s[*] %d processed | %d reflected | %d errors | %d skipped%s\n",
				cCyan,
				atomic.LoadInt64(&statsProcessed),
				atomic.LoadInt64(&statsReflected),
				atomic.LoadInt64(&statsErrors),
				atomic.LoadInt64(&statsSkipped),
				cReset)
		}
	}
}

func printSummary() {
	fmt.Fprintf(os.Stderr, "\n%s[+] Done. %d processed | %d reflected | %d errors | %d skipped%s\n",
		cGreen, statsProcessed, statsReflected, statsErrors, statsSkipped, cReset)
}

func printBanner() {
	fmt.Fprintf(os.Stderr, `
%s    ╔═══════════════════════════════════════╗
    ║            REFLEX  v2.0              ║
    ║        XSS Reflection Auditor        ║
    ╚═══════════════════════════════════════╝%s
`, cGreen, cReset)
}
