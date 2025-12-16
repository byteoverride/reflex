package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Configuration constants
const (
	CanaryValue    = "ReflectCheckXSS"
	PayloadMarker  = "{payload}"
	MaxRetries     = 3
	BackoffSeconds = 60
	ErrorThreshold = 10
)

// ANSI Colors
const (
	ColorGreen = "\033[92m"
	ColorRed   = "\033[91m"
	ColorBlue  = "\033[94m"
	ColorReset = "\033[0m"
)

// Global State
var (
	consecutive403s int32
	isPaused        int32 // 0 = running, 1 = paused
	pauseMutex      sync.Mutex
	pauseCond       = sync.NewCond(&pauseMutex)
)

// Custom Type for Multi-value Flags
type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Flags
var (
	threads       int
	inputFile     string
	outputFile    string
	verbose       bool
	timeout       int
	customHeaders arrayFlags // Stores multiple -H flags
)

func main() {
	printBanner()
	parseFlags()

	// Channels
	jobs := make(chan string, 1000)
	results := make(chan string)
	var wg sync.WaitGroup

	// Output Writer
	go saveResults(results)

	// Worker Pool
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	// Input Reader
	go func() {
		readInput(jobs)
		close(jobs)
	}()

	wg.Wait()
	close(results)
	fmt.Printf("\n%s[+] Scan completed.%s\n", ColorGreen, ColorReset)
}

func parseFlags() {
	flag.IntVar(&threads, "t", 20, "Number of concurrent threads")
	flag.StringVar(&inputFile, "f", "", "File containing URLs (optional, defaults to stdin)")
	flag.StringVar(&outputFile, "o", "xss_go.txt", "Output file for results")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.IntVar(&timeout, "timeout", 10, "HTTP timeout in seconds")
	
	// Register the custom header flag
	flag.Var(&customHeaders, "H", "Custom headers (can be used multiple times, e.g. -H 'Key: Value')")
	
	flag.Parse()
}

func readInput(jobs chan<- string) {
	var scanner *bufio.Scanner
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Printf("%s[!] Error opening file: %v%s\n", ColorRed, err, ColorReset)
			os.Exit(1)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		// Read from Stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Println("Usage: cat urls.txt | ./tool -H 'X-Bug-Bounty: Me' or ./tool -f urls.txt")
			os.Exit(1)
		}
		scanner = bufio.NewScanner(os.Stdin)
	}

	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr != "" {
			jobs <- urlStr
		}
	}
}

func saveResults(results <-chan string) {
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%s[!] Error creating output file: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer f.Close()

	for res := range results {
		if _, err := f.WriteString(res + "\n"); err != nil {
			fmt.Printf("%s[!] Error writing to file: %v%s\n", ColorRed, err, ColorReset)
		}
	}
}

func worker(jobs chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	for rawURL := range jobs {
		checkPause() // Check if we need to wait due to 403s

		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		queryParams := parsed.Query()
		if len(queryParams) == 0 {
			continue // Skip if no parameters
		}

		// If user only provided key without value (e.g., ?q), ensure it's handled
		for k, v := range queryParams {
			if len(v) == 0 {
				queryParams.Set(k, "")
			}
		}

		for param := range queryParams {
			// Create a copy of params to modify
			tempParams := url.Values{}
			for k, v := range queryParams {
				tempParams[k] = v
			}

			// Inject Canary
			tempParams.Set(param, CanaryValue)
			parsed.RawQuery = tempParams.Encode()
			targetURL := parsed.String()

			// --- NEW: Create Request with Custom Headers ---
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				continue
			}

			// Add User-Agent default if not overridden
			req.Header.Set("User-Agent", "Go-Reflection-Sentinel/1.0")

			// Inject Custom Headers from Flags
			for _, h := range customHeaders {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					req.Header.Set(key, val)
				}
			}

			// Perform Request
			resp, err := client.Do(req)
			if err != nil {
				if verbose {
					fmt.Printf("%s[!] Error: %v%s\n", ColorRed, err, ColorReset)
				}
				continue
			}

			// Safety Measure: 403 Handling
			if resp.StatusCode == 403 {
				resp.Body.Close()
				handle403(rawURL, jobs) // Trigger safety logic and re-queue
				continue
			} else {
				// Reset 403 counter on success
				atomic.StoreInt32(&consecutive403s, 0)
			}

			// Check Reflection
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			if strings.Contains(string(bodyBytes), CanaryValue) {
				// Success: Reconstruct URL with {payload}
				tempParams.Set(param, PayloadMarker)
				finalQuery := strings.ReplaceAll(tempParams.Encode(), "%7Bpayload%7D", "{payload}")
				parsed.RawQuery = finalQuery
				resultURL := parsed.String()

				fmt.Printf("%s[+] Reflection found: %s%s\n", ColorGreen, resultURL, ColorReset)
				results <- resultURL
			}
		}
	}
}

// checkPause blocks the worker if the system is in a paused state
func checkPause() {
	pauseMutex.Lock()
	for atomic.LoadInt32(&isPaused) == 1 {
		pauseCond.Wait()
	}
	pauseMutex.Unlock()
}

// handle403 manages the error counter and triggers the pause mechanism
func handle403(failedURL string, jobs chan string) {
	newVal := atomic.AddInt32(&consecutive403s, 1)
	
	if newVal >= ErrorThreshold {
		// Only one goroutine should trigger the pause
		if atomic.CompareAndSwapInt32(&isPaused, 0, 1) {
			go triggerCoolDown()
		}
	}

	// Re-queue the failed URL to try again later
	go func() {
		// Add a slight jitter before requeuing
		time.Sleep(time.Duration(rand.Intn(2000)) * time.Millisecond)
		jobs <- failedURL
	}()
}

// triggerCoolDown handles the sleep and resume logic
func triggerCoolDown() {
	fmt.Printf("\n%s[!] High 403 Error Rate detected (%d consecutive). Pausing for %d seconds...%s\n", 
		ColorRed, ErrorThreshold, BackoffSeconds, ColorReset)
	
	time.Sleep(BackoffSeconds * time.Second)

	// Reset counters
	atomic.StoreInt32(&consecutive403s, 0)
	
	// Resume workers
	pauseMutex.Lock()
	atomic.StoreInt32(&isPaused, 0)
	pauseCond.Broadcast() // Wake up all waiting workers
	pauseMutex.Unlock()

	fmt.Printf("%s[INFO] Resuming operations...%s\n", ColorBlue, ColorReset)
}

func printBanner() {
	banner := `
    %s#########################################%s
    %s#                                       #%s
    %s#                REFLEX                 #%s
    %s#         XSS Reflection Auditor        #%s
    %s#                                       #%s
    %s#########################################%s
    `
	fmt.Printf(banner, ColorGreen, ColorReset, ColorGreen, ColorReset, ColorGreen, ColorReset, ColorGreen, ColorReset, ColorGreen, ColorReset, ColorGreen, ColorReset)
	fmt.Println()
}
