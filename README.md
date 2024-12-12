# defense-waf
A defensive Web Application Firewall (WAF) focusing on protecting against common web attacks.

This WAF implements several defensive features:

1. Request Filtering:
   - SQL injection detection
   - XSS detection
   - Path whitelisting
   - Method restrictions
   - Request size limits

2. Access Control:
   - IP blocking
   - Rate limiting
   - Method restrictions

3. Monitoring:
   - Detailed request logging
   - Attack detection logging
   - Performance monitoring

To use this WAF, create a waf_config.json file:

```json
{
    "port": 8080,
    "target_url": "localhost:8081",
    "rate_limit": 60,
    "max_request_size": 1048576,
    "blocked_ips": ["192.168.1.100"],
    "allowed_paths": ["/api", "/static"],
    "allowed_methods": ["GET", "POST"],
    "sql_injection_patterns": [
        "(?i)(\\b)SELECT(\\b).*(\\b)FROM(\\b)",
        "(?i)(\\b)INSERT(\\b).*(\\b)INTO(\\b)",
        "(?i)(\\b)UPDATE(\\b).*(\\b)SET(\\b)",
        "(?i)(\\b)DELETE(\\b).*(\\b)FROM(\\b)",
        "(?i)(\\b)DROP(\\b).*(\\b)TABLE(\\b)",
        "(?i)(\\b)UNION(\\b).*(\\b)SELECT(\\b)"
    ],
    "xss_patterns": [
        "(?i)<script[^>]*>",
        "(?i)javascript:",
        "(?i)onerror=",
        "(?i)onload=",
        "(?i)eval\\(",
        "(?i)alert\\("
    ]
}
```

To enhance security further, consider:
1. Adding TLS/SSL support
2. Implementing more attack pattern detection
3. Adding request body inspection
4. Implementing response filtering
5. Adding API security features
