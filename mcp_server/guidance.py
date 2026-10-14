"""
GuidanceEngine — The brain that explains findings, suggests next steps,
and tells you when something looks suspicious even when automated tools
can't go further.

No API calls. No external dependencies. Pure domain knowledge.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# ── Suspicious subdomain prefixes ────────────────────────────────────────────
SUSPICIOUS_PREFIXES = {
    "dev":       ("Development environment", "high", "Often has debug features, weak auth, or unpatched software."),
    "staging":   ("Staging environment", "high", "Frequently mirrors production with relaxed security controls."),
    "stage":     ("Staging environment", "high", "Same as staging — investigate auth and configuration."),
    "test":      ("Test environment", "medium", "May have test credentials or skip security checks."),
    "uat":       ("UAT environment", "medium", "User acceptance testing — often forgotten and unpatched."),
    "admin":     ("Admin interface", "critical", "High-priority target. Check for default creds and auth bypass."),
    "manager":   ("Management interface", "high", "Potential admin panel. Test authentication thoroughly."),
    "api":       ("API endpoint", "high", "Check authentication, rate limiting, and IDOR."),
    "internal":  ("Internal endpoint", "critical", "Should not be internet-facing. Check for sensitive data exposure."),
    "intranet":  ("Intranet endpoint", "critical", "Same as internal — possibly exposed accidentally."),
    "vpn":       ("VPN gateway", "high", "Check for known CVEs (Pulse Secure, Fortinet, Cisco)."),
    "backup":    ("Backup system", "critical", "May expose database dumps, config files, or credentials."),
    "old":       ("Legacy endpoint", "medium", "Legacy software often runs outdated, unpatched versions."),
    "legacy":    ("Legacy endpoint", "medium", "Older endpoints frequently skip modern security practices."),
    "portal":    ("Portal / gateway", "medium", "Client portals often have weak password policies."),
    "login":     ("Login page", "high", "Direct entry point. Test for brute force, 2FA bypass."),
    "auth":      ("Auth service", "high", "OAuth/SSO misconfigurations are common here."),
    "sso":       ("SSO endpoint", "high", "Test for SAML vulnerabilities, redirect abuse."),
    "jenkins":   ("Jenkins CI/CD", "critical", "Default no-auth setups frequently exposed. Check /api/json."),
    "gitlab":    ("GitLab instance", "critical", "Check for public repos, unauthenticated API access."),
    "jira":      ("Jira instance", "high", "Check for public issues exposing internal info."),
    "confluence": ("Confluence wiki", "high", "Often contains sensitive internal documentation."),
    "grafana":   ("Grafana dashboard", "critical", "Default admin/admin is very common."),
    "kibana":    ("Kibana / ELK", "critical", "Unauthenticated access exposes all log data."),
    "elastic":   ("Elasticsearch", "critical", "Often exposed with no auth. Contains sensitive indexed data."),
    "mongo":     ("MongoDB", "critical", "If exposed, likely unauthenticated. Immediate finding."),
    "redis":     ("Redis", "critical", "Unauthenticated Redis = RCE via config command."),
    "phpmyadmin": ("phpMyAdmin", "critical", "Direct database access. Check default creds."),
    "ftp":       ("FTP server", "high", "Test for anonymous login, directory traversal."),
    "mail":      ("Mail server", "medium", "Check SPF/DMARC, open relay, and SMTP auth."),
    "smtp":      ("SMTP server", "medium", "Test for open relay and credential exposure."),
    "cdn":       ("CDN edge", "info", "Note CDN provider for WAF bypass research."),
    "s3":        ("S3-like endpoint", "high", "Check for public bucket misconfiguration."),
    "store":     ("Storage endpoint", "high", "Potential object storage — check public access."),
    "upload":    ("Upload endpoint", "high", "File upload functionality — test for unrestricted upload."),
    "assets":    ("Asset server", "low", "Check for directory listing and sensitive file exposure."),
    "static":    ("Static file server", "low", "Check for directory listing."),
    "demo":      ("Demo instance", "medium", "Demo environments often share credentials across tenants."),
    "sandbox":   ("Sandbox", "medium", "May have reduced security for testing purposes."),
}

# ── Suspicious file/path patterns ────────────────────────────────────────────
SUSPICIOUS_PATHS = {
    ".env":             ("Environment file", "critical", "May contain credentials, API keys, DB passwords."),
    "config.php":       ("PHP config", "critical", "Database credentials often hardcoded."),
    "wp-config.php":    ("WordPress config", "critical", "Contains DB credentials and secret keys."),
    ".git/config":      ("Git repository", "critical", "Source code exposure. Run git-dumper."),
    ".git/HEAD":        ("Git repository", "critical", "Source code exposure. Run git-dumper."),
    "backup.zip":       ("Backup archive", "critical", "May contain full application source + DB."),
    "backup.sql":       ("Database dump", "critical", "Direct database exposure."),
    "phpinfo.php":      ("PHP info page", "high", "Reveals server config, PHP version, paths."),
    "info.php":         ("PHP info page", "high", "Reveals server configuration."),
    "debug.php":        ("Debug page", "high", "May allow arbitrary PHP execution."),
    "test.php":         ("Test file", "medium", "Leftover test files often have loose security."),
    "swagger.json":     ("API documentation", "high", "Full API spec — enumerate all endpoints."),
    "openapi.json":     ("API documentation", "high", "Full API spec — enumerate all endpoints."),
    "/api/v1/":         ("API v1 endpoint", "medium", "Test for IDOR, auth bypass, excessive data exposure."),
    "/admin/":          ("Admin panel", "critical", "Direct admin access. Test all auth controls."),
    "/.well-known/":    ("Well-known endpoint", "info", "Check security.txt and other disclosures."),
    "robots.txt":       ("Robots.txt", "info", "Often lists hidden paths. Always check this."),
    "/actuator/":       ("Spring Boot actuator", "critical", "Check /actuator/env and /actuator/heapdump."),
    "/console":         ("H2 DB console", "critical", "H2 web console can lead to RCE."),
    "/.DS_Store":       ("macOS metadata", "medium", "Reveals directory structure."),
    "crossdomain.xml":  ("Flash crossdomain", "medium", "May allow cross-origin data access."),
    "sitemap.xml":      ("Sitemap", "info", "Useful for URL enumeration."),
    "server-status":    ("Apache status", "high", "Reveals active connections and internal paths."),
    "server-info":      ("Apache info", "high", "Reveals server configuration details."),
}

# ── High-value ports ─────────────────────────────────────────────────────────
INTERESTING_PORTS = {
    21:   ("FTP", "high", "Test for anonymous login, check version for known CVEs."),
    22:   ("SSH", "medium", "Check version. Test for weak/default credentials if in scope."),
    23:   ("Telnet", "critical", "Plaintext protocol. Credentials exposed in transit."),
    25:   ("SMTP", "medium", "Check for open relay. Test authentication."),
    53:   ("DNS", "medium", "Test for zone transfer: `dig axfr @target domain`"),
    80:   ("HTTP", "medium", "Unencrypted. All traffic visible. Check for redirect to HTTPS."),
    110:  ("POP3", "medium", "Email protocol. Check for plaintext credential transmission."),
    143:  ("IMAP", "medium", "Email access. Test for credential brute force."),
    443:  ("HTTPS", "info", "Standard web port. Run full web scanning."),
    445:  ("SMB", "critical", "Test for EternalBlue, unauthenticated access, null sessions."),
    1433: ("MSSQL", "critical", "Database port. Test for SA account with blank/default password."),
    1521: ("Oracle DB", "critical", "Database port. Check for default SYS/SYSTEM credentials."),
    2049: ("NFS", "high", "Test for unauthenticated mounts: `showmount -e target`"),
    2181: ("ZooKeeper", "critical", "Often completely unauthenticated. Direct cluster access."),
    3306: ("MySQL", "critical", "Database port. Test for unauthenticated access, root with no password."),
    3389: ("RDP", "high", "Remote desktop. Test for BlueKeep (CVE-2019-0708) and credential brute force."),
    4443: ("HTTPS alt", "medium", "Alternative HTTPS — often dev/staging services."),
    4848: ("GlassFish admin", "critical", "Default admin:adminadmin is common."),
    5432: ("PostgreSQL", "critical", "Database port. Test for unauthenticated access."),
    5601: ("Kibana", "critical", "Elasticsearch dashboard. Often exposed without auth."),
    5900: ("VNC", "high", "Remote desktop. Test for no-auth mode."),
    6379: ("Redis", "critical", "If reachable: likely no-auth. Test with `redis-cli -h target ping`"),
    7001: ("WebLogic", "critical", "Known for critical RCE vulnerabilities. Check CVEs."),
    8080: ("HTTP alt", "medium", "Dev/staging web service. Run full web scan."),
    8443: ("HTTPS alt", "medium", "Alternative HTTPS. Run full web scan."),
    8888: ("Jupyter Notebook", "critical", "Often no-auth. Direct code execution on server."),
    9000: ("PHP-FPM / SonarQube", "high", "Check for unauthenticated SonarQube access."),
    9090: ("Prometheus / Cockpit", "high", "Prometheus: metrics exposure. Cockpit: server management."),
    9200: ("Elasticsearch", "critical", "Likely no-auth. `curl http://target:9200/_cat/indices`"),
    9300: ("Elasticsearch cluster", "critical", "Cluster communication port. Should never be public."),
    27017:("MongoDB", "critical", "No-auth MongoDB exposes all databases. `mongo target:27017`"),
    27018:("MongoDB", "critical", "MongoDB shard server."),
}


class GuidanceEngine:
    """
    Analyzes tool output and generates actionable guidance.
    All logic is local — no API calls.
    """

    # ── Main generate() dispatcher ────────────────────────────────────────────

    def generate(self, ctx: dict) -> dict:
        tool = ctx.get("tool", "")
        guidance: dict[str, Any] = {
            "risk_level": "info",
            "summary": "",
            "suspicious_items": [],
            "next_steps": [],
            "manual_steps": [],
            "limitations": "",
        }

        if tool == "subdomain_enum":
            self._guidance_subdomain_enum(ctx, guidance)
        elif tool == "alive_check":
            self._guidance_alive_check(ctx, guidance)
        elif tool == "port_scan":
            self._guidance_port_scan(ctx, guidance)
        elif tool == "nuclei_scan":
            self._guidance_nuclei(ctx, guidance)
        elif tool == "dir_fuzz":
            self._guidance_dir_fuzz(ctx, guidance)
        elif tool == "wayback":
            self._guidance_wayback(ctx, guidance)
        elif tool == "full_recon":
            self._guidance_full_recon(ctx, guidance)
        elif ctx.get("error"):
            self._guidance_error(ctx, guidance)
        else:
            guidance["next_steps"] = ["Review the raw output above for findings."]

        return guidance

    # ── Per-tool guidance ─────────────────────────────────────────────────────

    def _guidance_subdomain_enum(self, ctx: dict, g: dict) -> None:
        found = ctx.get("found", 0)
        domain = ctx.get("target", "")

        if found == 0:
            g["risk_level"] = "info"
            g["summary"] = "No subdomains found via passive recon."
            g["limitations"] = "Passive-only recon cannot find subdomains with no public footprint."
            g["next_steps"] = [
                "Try active brute-force: use subdomain_brute tool",
                f"Search certificate logs: cert_search tool, or visit https://crt.sh/?q=%.{domain}",
                f"Google dorking: site:*.{domain} -www",
                f"Shodan: shodan_search tool with query 'hostname:{domain}'",
                f"VirusTotal: https://www.virustotal.com/gui/domain/{domain}/relations",
                f"SecurityTrails: https://securitytrails.com/domain/{domain}/subdomains",
            ]
        elif found < 10:
            g["risk_level"] = "low"
            g["summary"] = f"Found {found} subdomains. Small attack surface."
            g["next_steps"] = [
                "Run alive_check to see which are live",
                "Run cert_search to find more via certificate logs",
                "Try subdomain_brute for active discovery",
            ]
        elif found < 50:
            g["risk_level"] = "medium"
            g["summary"] = f"Found {found} subdomains. Moderate attack surface."
            g["next_steps"] = [
                "Run alive_check to filter to live targets",
                "Look for dev/staging/admin patterns in the list",
                "Check for subdomain takeover potential on each",
                "Run full_recon on the most interesting ones",
            ]
        else:
            g["risk_level"] = "high"
            g["summary"] = f"Found {found} subdomains. Large attack surface — prioritize carefully."
            g["next_steps"] = [
                "Run alive_check to find live hosts (many will be dead)",
                "Focus on dev/staging/admin/api subdomains first",
                "Check for wildcard DNS that might allow subdomain takeover",
                "Run nuclei_scan on alive hosts for quick wins",
            ]

        g["manual_steps"] = [
            f"DNS brute force: `for sub in $(cat wordlist.txt); do host $sub.{domain}; done | grep 'has address'`",
            f"Zone transfer attempt: `dig axfr {domain} @ns1.{domain}`",
            f"Reverse DNS lookup: `for ip in $(host {domain} | awk '{{print $4}}'); do host $ip; done`",
        ]

    def _guidance_alive_check(self, ctx: dict, g: dict) -> None:
        alive_count = ctx.get("alive_count", 0)
        interesting = ctx.get("interesting_count", 0)

        if interesting > 0:
            g["risk_level"] = "high"
            g["summary"] = f"{interesting} interesting endpoints found (admin/login/dashboard/API titles)."
            g["next_steps"] = [
                "Investigate the 'interesting' hosts first — they often have admin panels or APIs",
                "Run tech_detect on interesting hosts to identify the stack",
                "Run nuclei_scan on interesting hosts",
                "Take screenshots with the screenshot tool",
                "Manually browse the interesting endpoints",
            ]
        elif alive_count > 0:
            g["risk_level"] = "medium"
            g["summary"] = f"{alive_count} live hosts found."
            g["next_steps"] = [
                "Run tech_detect to identify technology stacks",
                "Run nuclei_scan for automatic vulnerability detection",
                "Take screenshots for visual review",
                "Run dir_fuzz on web servers to find hidden paths",
            ]
        else:
            g["summary"] = "No live hosts found."
            g["limitations"] = "All targets may be behind a firewall, down, or using non-standard ports."
            g["next_steps"] = [
                "Try with HTTP instead of HTTPS (or vice versa)",
                "Run port_scan to check if non-standard ports are open",
                "Try direct IP addresses instead of hostnames",
            ]

    def _guidance_port_scan(self, ctx: dict, g: dict) -> None:
        ports = ctx.get("ports", [])

        suspicious_found = []
        for port in ports:
            p = int(port) if str(port).isdigit() else port
            if p in INTERESTING_PORTS:
                service, risk, note = INTERESTING_PORTS[p]
                suspicious_found.append({
                    "port": p,
                    "service": service,
                    "risk": risk,
                    "action": note,
                })

        if suspicious_found:
            max_risk = "critical" if any(s["risk"] == "critical" for s in suspicious_found) else "high"
            g["risk_level"] = max_risk
            g["summary"] = f"Found {len(suspicious_found)} interesting services."
            g["suspicious_items"] = suspicious_found
            g["next_steps"] = [
                f"Port {s['port']} ({s['service']}): {s['action']}"
                for s in suspicious_found
            ]
        else:
            g["risk_level"] = "low"
            g["summary"] = f"Found {len(ports)} open ports. No immediately critical services."
            g["next_steps"] = [
                "Expand scan to top-1000 ports if only top-100 was scanned",
                "Run service version detection: `nmap -sV -p {','.join(str(p) for p in ports)} target`",
                "Run nuclei_scan on any discovered web services",
            ]

        g["manual_steps"] = [
            "Banner grab: `nc -v target <port>`",
            f"Service version: `nmap -sV -p {','.join(str(p) for p in ports[:20])} target`",
            "Check if services have default credentials",
        ]

    def _guidance_nuclei(self, ctx: dict, g: dict) -> None:
        total = ctx.get("total", 0)
        severities = ctx.get("severities", {})

        if severities.get("critical", 0) > 0 or severities.get("high", 0) > 0:
            g["risk_level"] = "critical" if severities.get("critical", 0) > 0 else "high"
            g["summary"] = (
                f"🚨 CRITICAL findings: {severities.get('critical', 0)} critical, "
                f"{severities.get('high', 0)} high severity issues."
            )
            g["next_steps"] = [
                "Manually verify each critical/high finding before reporting",
                "Use explain_finding tool on each critical finding for write-up guidance",
                "Capture screenshots and request/response pairs as evidence",
                "Check if findings are exploitable in context (false positives exist)",
                "Generate a report with generate_report tool",
            ]
        elif total > 0:
            g["risk_level"] = "medium"
            g["summary"] = f"Found {total} vulnerabilities ({severities})."
            g["next_steps"] = [
                "Verify medium-severity findings manually",
                "Use explain_finding for write-up guidance",
            ]
        else:
            g["summary"] = "No vulnerabilities found by Nuclei."
            g["limitations"] = "Nuclei template-based scanning may miss logic bugs, business logic flaws, and custom vulnerabilities."
            g["next_steps"] = [
                "Run with broader severity (add 'info,low' to severity filter)",
                "Try targeted template tags: nuclei_scan with templates='misconfig'",
                "Try templates='cve' for known CVE checks",
                "Manual testing is essential for business logic issues not covered by templates",
                "Check: IDOR, broken access control, rate limiting, account enumeration",
            ]
            g["manual_steps"] = [
                "Manual IDOR test: modify object IDs in requests (1, 2, 3, GUID+1...)",
                "Auth test: access endpoints without JWT/session cookie",
                "Rate limit test: send 100 requests to login endpoint rapidly",
                "Mass assignment: add admin:true to JSON body in user update requests",
                "Check for Host header injection: modify Host: header to evil.com",
            ]

    def _guidance_dir_fuzz(self, ctx: dict, g: dict) -> None:
        found = ctx.get("found", 0)

        if found > 0:
            g["risk_level"] = "medium"
            g["summary"] = f"Found {found} paths. Investigate for sensitive files."
            g["next_steps"] = [
                "Manually browse each found path",
                "Check for backup files (.bak, .old, ~)",
                "Look for exposed config files",
                "Run nuclei_scan on the target to check for known vulnerabilities at found paths",
            ]
        else:
            g["summary"] = "No paths found."
            g["limitations"] = "WAF may be blocking directory brute-force. Generic wordlist may not match target's tech stack."
            g["next_steps"] = [
                "Try a larger wordlist (raft-large or common-plus)",
                "Target-specific wordlist: `cewl https://target.com -w wordlist.txt`",
                "Try technology-specific wordlists (WordPress, Laravel, Spring...)",
                "Check robots.txt and sitemap.xml manually",
                "Bypass WAF: add extension variation, change User-Agent, throttle requests",
            ]

    def _guidance_wayback(self, ctx: dict, g: dict) -> None:
        total = ctx.get("total", 0)
        interesting = ctx.get("interesting", 0)

        if interesting > 0:
            g["risk_level"] = "high"
            g["summary"] = f"Found {interesting} potentially sensitive historical URLs."
            g["next_steps"] = [
                "Check if any historical sensitive files still exist at their URLs",
                "Look for old API endpoints that may still be active",
                "Search for historical credential exposure in URL parameters",
                "Look for backup and config files in historical URLs",
            ]
        elif total > 0:
            g["summary"] = f"Found {total} historical URLs."
            g["next_steps"] = [
                "Filter for parameters: interesting for testing injection",
                "Look for .js files to analyze for secrets",
                "Check for API versioning patterns (v1, v2, v3)",
            ]
        g["manual_steps"] = [
            "Extract unique parameters: `cat urls.txt | grep '?' | sed 's/=.*/=/' | sort -u`",
            "Find JS files: `cat urls.txt | grep '\\.js$'`",
            "Look for API keys in JS: `grep -iE '(api[_-]?key|token|secret|password)' js_files/*.js`",
        ]

    def _guidance_full_recon(self, ctx: dict, g: dict) -> None:
        subs = ctx.get("subdomains", 0)
        alive = ctx.get("alive", 0)

        g["summary"] = f"Full recon complete: {subs} subdomains → {alive} alive hosts."
        g["next_steps"] = [
            "Review screenshots for interesting UIs",
            "Run nuclei_scan on alive hosts for quick vulnerability wins",
            "Run dir_fuzz on web servers",
            "Check tech_detect results for outdated/vulnerable software",
            "Investigate any dev/staging/admin subdomains first",
            "Use analyze_findings after collecting more data",
        ]

    def _guidance_error(self, ctx: dict, g: dict) -> None:
        error = ctx.get("error", "")
        tool = ctx.get("tool", "")

        g["summary"] = f"Tool '{tool}' encountered an error."

        if "not found" in error.lower() or "127" in str(error):
            g["next_steps"] = [
                "Tool binary missing. Rebuild Docker: `docker-compose build --no-cache`",
                "Or install manually inside container: `docker exec -it bugbounty-mcp /bin/bash`",
            ]
        elif "timeout" in error.lower():
            g["next_steps"] = [
                "Target may be slow or filtering scans. Increase timeout parameter.",
                "Try scanning fewer targets at once.",
                "Check if target is behind a WAF.",
            ]
        elif "permission" in error.lower():
            g["next_steps"] = [
                "Run inside Docker container which has correct permissions.",
                "Check if target is blocking your IP — try from a different network.",
            ]
        else:
            g["next_steps"] = [
                "Check the raw error message above for specific details.",
                "Verify target is accessible from your network.",
                "Try manual approach: run the tool directly in the container (`docker exec -it bugbounty-mcp bash`).",
            ]

    # ── Subdomain analysis ────────────────────────────────────────────────────

    def flag_suspicious_subdomains(self, subdomains: list[str]) -> list[dict]:
        """Flag subdomains that match high-value patterns."""
        flagged = []
        for sub in subdomains:
            for prefix, (name, risk, note) in SUSPICIOUS_PREFIXES.items():
                if sub.startswith(prefix + ".") or sub.startswith(prefix + "-"):
                    flagged.append({
                        "subdomain": sub,
                        "type": name,
                        "risk": risk,
                        "note": note,
                    })
                    break
        return flagged

    # ── Collection analysis ───────────────────────────────────────────────────

    def analyze_collection(self, findings: list[dict], target: str) -> dict:
        """Analyze multiple findings from different tools and prioritize."""
        critical = []
        high = []
        medium = []
        low_info = []

        for f4 in findings:
            # Support findings from nuclei (have 'severity' key)
            sev = (
                f4.get("severity")
                or f4.get("risk_level")
                or f4.get("risk")
                or "info"
            ).lower()

            if sev == "critical":
                critical.append(f4)
            elif sev == "high":
                high.append(f4)
            elif sev == "medium":
                medium.append(f4)
            else:
                low_info.append(f4)

        attack_chain = self._suggest_attack_chain(critical + high)

        return {
            "summary": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low_info": len(low_info),
                "total": len(findings),
            },
            "priority_findings": critical + high,
            "attack_chain_suggestion": attack_chain,
            "reporting_tips": [
                "Always manually verify before reporting — false positives are common",
                "Capture screenshots + request/response for every finding",
                "Write a clear impact statement: what could an attacker do with this?",
                "Assign CVSS score if the program requires it",
                "Include reproduction steps detailed enough for a developer to reproduce",
            ],
            "manual_checks_remaining": [
                "Business logic flaws (no automated tool covers these)",
                "IDOR across multiple accounts",
                "Race conditions on checkout / transfer endpoints",
                "Account takeover via password reset flow",
                "2FA bypass",
                "OAuth misconfigurations",
                "API rate limiting",
                "Privilege escalation between user roles",
            ],
        }

    def _suggest_attack_chain(self, high_sev_findings: list[dict]) -> list[str]:
        """Suggest possible attack chains from high-severity findings."""
        chain = []
        finding_names = " ".join(
            str(f4.get("template_id", "") or f4.get("name", "")).lower()
            for f4 in high_sev_findings
        )

        if "ssrf" in finding_names:
            chain.append("SSRF → Internal network access → AWS metadata → Credentials")
        if "xss" in finding_names:
            chain.append("Stored XSS → Admin session hijack → Account takeover")
        if "sqli" in finding_names:
            chain.append("SQLi → Database dump → Credential extraction → Account takeover")
        if "rce" in finding_names or "code-exec" in finding_names:
            chain.append("RCE → Shell → Internal pivot → Full environment compromise")
        if "xxe" in finding_names:
            chain.append("XXE → SSRF → Internal file read → Credential exposure")
        if "lfi" in finding_names:
            chain.append("LFI → /etc/passwd read → config files → Credentials")
        if "open-redirect" in finding_names:
            chain.append("Open Redirect → Phishing / OAuth token theft")

        if not chain:
            chain = ["No obvious automated attack chain. Manual investigation of individual findings recommended."]

        return chain

    # ── Finding explainer ─────────────────────────────────────────────────────

    def explain(self, finding: dict) -> dict:
        template_id = str(finding.get("template-id") or finding.get("template_id") or "")
        name = str(finding.get("name") or finding.get("info", {}).get("name") or template_id)
        severity = str(finding.get("severity") or finding.get("info", {}).get("severity") or "unknown")
        url = str(finding.get("matched-at") or finding.get("url") or "")

        explanation = {
            "what_it_is": f"{name} — a {severity}-severity vulnerability found at {url}",
            "impact": self._impact_for(template_id, name),
            "manual_verification": self._verify_steps(template_id, name, url),
            "report_write_up": self._report_template(name, severity, url),
            "cvss_guide": self._cvss_hint(severity),
            "fix_reference": f"https://owasp.org/www-project-top-ten/ — search for '{name}'",
        }
        return explanation

    def _impact_for(self, template_id: str, name: str) -> str:
        t = (template_id + name).lower()
        if "xss" in t:
            return "An attacker can inject malicious JavaScript that runs in victims' browsers, potentially stealing sessions, cookies, or credentials."
        if "sqli" in t or "sql-injection" in t:
            return "An attacker can read, modify, or delete database contents, potentially extracting all user credentials and PII."
        if "ssrf" in t:
            return "An attacker can make the server issue requests to internal services, potentially accessing AWS metadata, internal APIs, or credentials."
        if "rce" in t or "command-exec" in t:
            return "An attacker can execute arbitrary commands on the server, leading to full system compromise."
        if "lfi" in t or "local-file" in t:
            return "An attacker can read arbitrary files on the server including /etc/passwd, configuration files, and source code."
        if "open-redirect" in t:
            return "An attacker can redirect users to malicious sites, enabling phishing or OAuth token theft."
        if "cors" in t:
            return "A malicious website can make authenticated requests on behalf of the victim, potentially exfiltrating data."
        if "xxe" in t:
            return "An attacker can read internal files or make server-side requests by injecting malicious XML."
        if "idor" in t:
            return "An attacker can access or modify other users' data by changing object IDs in requests."
        if "default-cred" in t or "default-login" in t:
            return "The service uses default credentials, allowing immediate unauthorized access."
        if "exposed" in t or "disclosure" in t:
            return "Sensitive information is publicly exposed, which may help attackers plan further attacks."
        return "This vulnerability may allow unauthorized access, data exposure, or system compromise."

    def _verify_steps(self, template_id: str, name: str, url: str) -> list[str]:
        t = (template_id + name).lower()
        if "xss" in t:
            return [
                f"Visit: {url}",
                "Look for reflection points in the URL or page",
                "Try payload: <script>alert(document.domain)</script>",
                "If filtered, try: <img src=x onerror=alert(1)>",
                "Use Burp Suite to inject into all parameters",
            ]
        if "sqli" in t:
            return [
                f"Visit: {url}",
                "Add ' to the vulnerable parameter and check for SQL errors",
                "Try: ' OR '1'='1",
                "Use sqlmap: `sqlmap -u '{url}' --dbs`",
                "Verify error-based vs blind injection",
            ]
        if "ssrf" in t:
            return [
                f"Identify the vulnerable parameter at: {url}",
                "Try: http://169.254.169.254/latest/meta-data/ (AWS metadata)",
                "Try: http://localhost/admin",
                "Use Burp Collaborator to confirm out-of-band SSRF",
                "Try protocol wrappers: file:///etc/passwd, dict://",
            ]
        if "cors" in t:
            return [
                f"Send request to: {url}",
                "Add header: Origin: https://evil.com",
                "Check if Access-Control-Allow-Origin: https://evil.com in response",
                "Also check: Access-Control-Allow-Credentials: true",
                "PoC JS: fetch(target, {credentials:'include'}).then(r=>r.text()).then(console.log)",
            ]
        return [
            f"Manually browse to: {url}",
            "Replicate the conditions described in the Nuclei template",
            "Capture request/response with Burp Suite as evidence",
        ]

    def _report_template(self, name: str, severity: str, url: str) -> str:
        return f"""## {name}

**Severity:** {severity.upper()}
**Affected URL:** {url}

### Description
[Describe what the vulnerability is and how it was found]

### Steps to Reproduce
1. Navigate to: {url}
2. [Describe exact steps]
3. Observe: [describe the vulnerable behavior]

### Impact
[Explain what an attacker could do with this vulnerability]

### Proof of Concept
[Add screenshots, request/response, or PoC code here]

### Remediation
[Suggest a fix — OWASP reference: https://owasp.org]
"""

    def _cvss_hint(self, severity: str) -> str:
        ranges = {
            "critical": "9.0–10.0 — Network-accessible, no authentication, high impact",
            "high":     "7.0–8.9 — Limited interaction needed, significant data access",
            "medium":   "4.0–6.9 — Authentication required or limited impact",
            "low":      "0.1–3.9 — Minimal exploitability or minimal impact",
            "info":     "0.0 — Informational — no direct security impact",
        }
        return ranges.get(severity.lower(), "Assign CVSS based on exploitability and impact metrics")

    # ── Report renderer ───────────────────────────────────────────────────────

    def render_report(self, target: str, findings: list[dict], program: str) -> str:
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        critical = [f4 for f4 in findings if (f4.get("severity") or "").lower() == "critical"]
        high     = [f4 for f4 in findings if (f4.get("severity") or "").lower() == "high"]
        medium   = [f4 for f4 in findings if (f4.get("severity") or "").lower() == "medium"]
        low      = [f4 for f4 in findings if (f4.get("severity") or "").lower() in ("low", "info")]

        sections = [f"# Bug Bounty Report — {target}\n",
                    f"**Program:** {program}  ",
                    f"**Date:** {now}  ",
                    f"**Target:** {target}\n",
                    "---\n",
                    "## Executive Summary\n",
                    "| Severity | Count |",
                    "|----------|-------|",
                    f"| 🔴 Critical | {len(critical)} |",
                    f"| 🟠 High     | {len(high)} |",
                    f"| 🟡 Medium   | {len(medium)} |",
                    f"| 🔵 Low/Info | {len(low)} |",
                    f"| **Total**   | **{len(findings)}** |\n",
                    "---\n",
                    "## Findings\n"]

        for idx, f4 in enumerate(critical + high + medium + low, 1):
            name = f4.get("name") or f4.get("template_id") or "Finding"
            sev  = (f4.get("severity") or "unknown").upper()
            url  = f4.get("url") or f4.get("matched-at") or "N/A"
            desc = f4.get("description") or ""
            sections.append(f"### {idx}. {name} ({sev})\n")
            sections.append(f"**URL:** `{url}`  ")
            if desc:
                sections.append(f"**Description:** {desc}\n")
            sections.append("**Steps to Reproduce:** [Add here]\n")
            sections.append("**Impact:** [Add here]\n")
            sections.append("**PoC:** [Add screenshot/request here]\n")
            sections.append("---\n")

        sections.append("## Methodology\n")
        sections.append("- Subdomain enumeration (subfinder, crt.sh)\n")
        sections.append("- Alive host detection (httpx)\n")
        sections.append("- Port scanning (naabu)\n")
        sections.append("- Vulnerability scanning (Nuclei)\n")
        sections.append("- Manual verification of all findings\n")
        sections.append("\n---\n*Report generated by Bug Bounty MCP Server*\n")

        return "\n".join(sections)
