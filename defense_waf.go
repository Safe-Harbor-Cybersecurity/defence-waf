package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
)

type WAFConfig struct {
    Port            int      `json:"port"`
    TargetURL       string   `json:"target_url"`
    RateLimit       int      `json:"rate_limit"`       // Requests per minute
    MaxRequestSize  int64    `json:"max_request_size"` // In bytes
    BlockedIPs      []string `json:"blocked_ips"`
    AllowedPaths    []string `json:"allowed_paths"`
    AllowedMethods  []string `json:"allowed_methods"`
    SQLInjectionPatterns []string `json:"sql_injection_patterns"`
    XSSPatterns     []string `json:"xss_patterns"`
}

type RequestTracker struct {
    Count     int
    LastReset time.Time
}

type WAF struct {
    config            WAFConfig
    sqlPatterns       []*regexp.Regexp
    xssPatterns       []*regexp.Regexp
    requestTrackers   map[string]*RequestTracker
    trackerMutex     sync.RWMutex
    blockedIPs       map[string]bool
    allowedPaths     map[string]bool
    allowedMethods   map[string]bool
}

func NewWAF(configPath string) (*WAF, error) {
    // Read configuration file
    file, err := os.ReadFile(configPath)
    if err != nil {
        return nil, fmt.Errorf("error reading config: %v", err)
    }

    var config WAFConfig
    if err := json.Unmarshal(file, &config); err != nil {
        return nil, fmt.Errorf("error parsing config: %v", err)
    }

    waf := &WAF{
        config:          config,
        requestTrackers: make(map[string]*RequestTracker),
        blockedIPs:     make(map[string]bool),
        allowedPaths:   make(map[string]bool),
        allowedMethods: make(map[string]bool),
    }

    // Compile regex patterns
    for _, pattern := range config.SQLInjectionPatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid SQL injection pattern %s: %v", pattern, err)
        }
        waf.sqlPatterns = append(waf.sqlPatterns, re)
    }

    for _, pattern := range config.XSSPatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid XSS pattern %s: %v", pattern, err)
        }
        waf.xssPatterns = append(waf.xssPatterns, re)
    }

    // Initialize allowed paths and methods
    for _, path := range config.AllowedPaths {
        waf.allowedPaths[path] = true
    }
    for _, method := range config.AllowedMethods {
        waf.allowedMethods[method] = true
    }
    for _, ip := range config.BlockedIPs {
        waf.blockedIPs[ip] = true
    }

    return waf, nil
}

func (w *WAF) checkRateLimit(ip string) bool {
    w.trackerMutex.Lock()
    defer w.trackerMutex.Unlock()

    now := time.Now()
    tracker, exists := w.requestTrackers[ip]

    if !exists {
        w.requestTrackers[ip] = &RequestTracker{
            Count:     1,
            LastReset: now,
        }
        return true
    }

    // Reset counter if minute has passed
    if now.Sub(tracker.LastReset) > time.Minute {
        tracker.Count = 1
        tracker.LastReset = now
        return true
    }

    if tracker.Count >= w.config.RateLimit {
        return false
    }

    tracker.Count++
    return true
}

func (w *WAF) detectSQLInjection(input string) bool {
    for _, pattern := range w.sqlPatterns {
        if pattern.MatchString(input) {
            return true
        }
    }
    return false
}

func (w *WAF) detectXSS(input string) bool {
    for _, pattern := range w.xssPatterns {
        if pattern.MatchString(input) {
            return true
        }
    }
    return false
}

func (w *WAF) inspectRequest(r *http.Request) (bool, string) {
    // Check if path is allowed
    if len(w.allowedPaths) > 0 && !w.allowedPaths[r.URL.Path] {
        return false, "Path not allowed"
    }

    // Check if method is allowed
    if len(w.allowedMethods) > 0 && !w.allowedMethods[r.Method] {
        return false, "Method not allowed"
    }

    // Check request size
    if r.ContentLength > w.config.MaxRequestSize {
        return false, "Request too large"
    }

    // Check query parameters for SQL injection and XSS
    for key, values := range r.URL.Query() {
        for _, value := range values {
            if w.detectSQLInjection(value) {
                return false, "SQL injection detected in query parameter"
            }
            if w.detectXSS(value) {
                return false, "XSS detected in query parameter"
            }
        }
        // Also check parameter names
        if w.detectSQLInjection(key) || w.detectXSS(key) {
            return false, "Attack detected in parameter name"
        }
    }

    // Check headers for suspicious content
    for header, values := range r.Header {
        for _, value := range values {
            if w.detectXSS(value) {
                return false, "XSS detected in header"
            }
        }
    }

    // Check cookies
    for _, cookie := range r.Cookies() {
        if w.detectXSS(cookie.Value) {
            return false, "XSS detected in cookie"
        }
    }

    return true, ""
}

func (w *WAF) logRequest(r *http.Request, allowed bool, reason string) {
    log.Printf("[%s] %s %s from %s - Allowed: %v, Reason: %s",
        time.Now().Format(time.RFC3339),
        r.Method,
        r.URL.Path,
        r.RemoteAddr,
        allowed,
        reason)
}

func (w *WAF) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    clientIP := strings.Split(r.RemoteAddr, ":")[0]

    // Check if IP is blocked
    if w.blockedIPs[clientIP] {
        w.logRequest(r, false, "IP blocked")
        http.Error(rw, "Forbidden", http.StatusForbidden)
        return
    }

    // Check rate limit
    if !w.checkRateLimit(clientIP) {
        w.logRequest(r, false, "Rate limit exceeded")
        http.Error(rw, "Rate limit exceeded", http.StatusTooManyRequests)
        return
    }

    // Inspect request for malicious content
    allowed, reason := w.inspectRequest(r)
    w.logRequest(r, allowed, reason)

    if !allowed {
        http.Error(rw, "Forbidden", http.StatusForbidden)
        return
    }

    // Forward request to target
    target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        client := &http.Client{}
        r.RequestURI = ""
        r.URL.Scheme = "http"
        r.URL.Host = w.config.TargetURL
        resp, err := client.Do(r)
        if err != nil {
            http.Error(w, "Error forwarding request", http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()

        // Copy response headers
        for key, values := range resp.Header {
            for _, value := range values {
                rw.Header().Add(key, value)
            }
        }
        rw.WriteHeader(resp.StatusCode)
        http.Copy(rw, resp.Body)
    })

    target.ServeHTTP(rw, r)
}

func main() {
    waf, err := NewWAF("waf_config.json")
    if err != nil {
        log.Fatal(err)
    }

    server := &http.Server{
        Addr:    fmt.Sprintf(":%d", waf.config.Port),
        Handler: waf,
    }

    log.Printf("WAF started on port %d", waf.config.Port)
    if err := server.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}
