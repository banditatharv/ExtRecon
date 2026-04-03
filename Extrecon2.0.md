# 🔍 Recon 2.0: Advanced External Reconnaissance Playbook
_The Final Expansion | Public-Source Intelligence Mastery | 2025_

```bash
┌─────────────────────────────────────────────────────────┐
│  RECON 2.0 = DEEPER • WIDER • SMARTER • AUTOMATED       │
│                                                         │
│  Builds on Recon 1.0 → Adds 10+ advanced layers         │
│  Focus: Public data only • No auth required • Ethical   │
└─────────────────────────────────────────────────────────┘
```

> ⚠️ Disclaimer: For authorized security testing only. Always obtain written permission. Follow rules of engagement. This document does not contain "secret" or non-public information — only underutilized public-source techniques.

# 📋 Table of Contents
- 🔄 [What's New in Recon 2.0]()
- 🐙 [Advanced GitHub & Source Code Recon]()
- 🕰️ [Wayback Machine & Historical URL Mining]()
- 📜 [JavaScript File Analysis for Endpoint Discovery]()
- ☁️ [Azure/Entra ID Enumeration (Post-Patch Methods)]()
- 🌐 [Multi-Cloud Asset Discovery]()
- 🔗 [Supply Chain & Third-Party Recon]()
- 🔌 [API Discovery & Shadow API Enumeration]()
- 📄 [Document & Metadata Harvesting]()
- 👥 [Advanced User/Identity Enumeration]()
- 🤖 [Automation & Intelligence Correlation]()
- 🧰 [Tool Summary & Quick Reference]()
- ⚡ [One-Liner Setup Script]()

# 🔄 What's New in Recon 2.0
```bash
Recon 1.0 Foundation:
├─ Domain discovery • Azure tenant enum • DNS records
├─ Basic user enum • Subdomain scraping • Tech fingerprinting

Recon 2.0 Advanced Layers:
├─ 🐙 GitHub secret/config leakage hunting
├─ 🕰️ Historical URL/parameter extraction from archives
├─ 📜 JS file parsing for hidden endpoints & API keys
├─ ☁️ Azure tenant mapping (post-August 2025 patch workarounds)
├─ 🌐 AWS/Azure/GCP bucket brute-forcing + misconfig checks
├─ 🔗 Supply chain mapping via SPF includes, JS imports, OAuth
├─ 🔌 Shadow API discovery via traffic analysis patterns
├─ 📄 PDF/DOCX metadata extraction for internal intel
├─ 👥 Cross-platform identity correlation (LinkedIn + breaches)
├─ 🤖 Python orchestrator for deduplication + scoring
└─ 🎯 Findings prioritization matrix (exploitability × exposure)
```

> 💡 Key Philosophy: Recon 2.0 doesn't replace Recon 1.0 — it layers advanced techniques on top. Run the basics first, then deepen with these methods.

# 🐙 Advanced GitHub & Source Code Recon
### 🔍 Why GitHub Matters

Developers accidentally leak: API keys, database credentials, internal URLs, employee emails, and config files in public repos

### 🎯 Search Techniques
```bash
# Basic domain + secret keyword
site:github.com "target.com" "api_key"
site:github.com "target.com" "password" "mysql"

# JSON-formatted secret patterns (higher precision)
site:github.com "target.com" "\"apiKey\":"
site:github.com "target.com" "\"aws_secret_access_key\":"

# Config file hunting
site:github.com "target.com" "config.js" OR ".env" OR "settings.py"

# Organization-specific search (if org is public)
org:target-company "secret" OR "token" OR "credential"
```

### 🛠️ Automated Tools
| 🛠️ Tool        | 🔍 Purpose                                   | ⚙️ Installation Command                                      |
|---------------|----------------------------------------------|-------------------------------------------------------------|
| truffleHog    | Searches git history for high-entropy strings| pip install truffleHog                                      |
| GitRob        | GitHub org recon + secret scanning           | gem install gitrob                                          |
| Gitleaks      | Fast, configurable secret scanner            | go install github.com/zricethezav/gitleaks/v8@latest         |
| SecretFinder  | JS file secret extraction                    | pip install SecretFinder                                    |

### 🎯 truffleHog Example
```bash
# Scan a public repo for secrets
trufflehog github --repo https://github.com/target/public-repo --only-verified

# Scan multiple repos from a list
cat repos.txt | xargs -I {} trufflehog github --repo {} --json >> secrets_found.json
```
> ⚠️ Correction: GitHub's native secret scanning 
GitHub
 only alerts repo owners. As an external researcher, you must use OSINT tools — GitHub won't notify you of leaks in other orgs.

# 🕰️ Wayback Machine & Historical URL Mining
### 🔍 Why Historical Data Matters

Old URLs reveal: deprecated endpoints, forgotten admin panels, test parameters, and exposed API routes that may still be live

### 🎯 Wayback URL Extraction
```bash
# Basic waybackurls (from projectdiscovery)
waybackurls target.com | sort -u > wayback_all.txt

# Filter for interesting filetypes
cat wayback_all.txt | grep -E "\.(js|json|xml|php|asp|aspx|do|action)" > wayback_scripts.txt

# Extract potential API endpoints
cat wayback_all.txt | grep -iE "api|v[0-9]|graphql|rest|soap" > wayback_apis.txt

# Find admin/panel paths
cat wayback_all.txt | grep -iE "admin|login|dashboard|panel|manage" > wayback_admin.txt
```

### 🔄 Advanced: waymore (more comprehensive)
```bash
# GitHub: https://github.com/xnl-h4ck3r/waymore [[63]]
git clone https://github.com/xnl-h4ck3r/waymore
cd waymore
python3 waymore.py -i target.com -mode U -o waymore_results.txt

# Extract parameters from archived URLs
python3 waymore.py -i target.com -mode P -o parameters_found.txt
```

### 🎯 Parameter Extraction & Fuzzing Prep
```bash
# Extract unique parameters from Wayback URLs
cat wayback_all.txt | grep -oE '\?[^\s#]+' | tr '&' '\n' | sort -u | \
  sed 's/?//' | cut -d'=' -f1 | sort -u > params_list.txt

# Use with ffuf for parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" -w params_list.txt -mc 200,302,403
```
> 💡 Pro Tip: Combine Wayback data with httpx to check which historical URLs are still live — these are high-value targets.

# 📜 JavaScript File Analysis for Endpoint Discovery
### 🔍 Why JS Files Are Goldmines

Client-side JS often contains: API endpoints, internal routes, hardcoded tokens, and parameter names that aren't in the main HTML 

### 🎯 JS File Discovery
```bash
# Extract JS files from live site + Wayback
cat live_hosts.txt | httpx -silent -js-crawl | grep -oE 'https?://[^"]+\.js' | sort -u > js_files.txt

# Add Wayback-discovered JS files
cat wayback_all.txt | grep -E '\.js$' | sort -u >> js_files.txt
```

### 🛠️ Analysis Tools
| 🛠️ Tool        | 🔍 Purpose                          | 💻 Command Example                                      |
|---------------|-------------------------------------|--------------------------------------------------------|
| LinkFinder    | Extract endpoints from JS            | python3 linkfinder.py -i file.js -o cli                |
| JShunter      | Advanced JS security analysis        | jshunter -u https://target.com/app.js                  |
| InspectJS     | Endpoint + secret extraction         | inspectjs -f app.js --extract-endpoints                |
| SecretFinder  | Find API keys in JS                  | python3 SecretFinder.py -i app.js -o cli               |

### 🎯 LinkFinder Bulk Scan
```bash
# Process all discovered JS files
cat js_files.txt | while read url; do
    echo "[*] Analyzing: $url"
    python3 linkfinder.py -i "$url" -o cli | grep -v "^$" >> endpoints_found.txt
done

# Dedupe and sort
sort -u endpoints_found.txt > endpoints_clean.txt
```

### 🎯 Extract High-Value Patterns
```bash
# Find API-like endpoints
cat endpoints_clean.txt | grep -iE "api|graphql|rest|v[0-9]" > api_endpoints.txt

# Find potential auth endpoints
cat endpoints_clean.txt | grep -iE "login|auth|token|oauth|saml" > auth_endpoints.txt

# Find internal-looking paths
cat endpoints_clean.txt | grep -iE "internal|admin|dev|staging|test" > internal_paths.txt
```

> ⚠️ Correction: Not all JS endpoints are externally accessible. Always validate with httpx -status-code before assuming they're attackable.

# 🌐 Multi-Cloud Asset Discovery
### 🔍 Beyond Azure: AWS + GCP Enumeration
__AWS S3 Bucket Brute-Forcing__
```bash
# Using cloud_enum (supports AWS)
python3 cloud_enum.py -k target -b aws --disable-azure --disable-gcp

# Manual pattern testing
for pattern in "target" "target-dev" "target-prod" "target-backup" "target-logs"; do
    curl -s -I "https://$pattern.s3.amazonaws.com" | grep -q "200\|403" && echo "[+] Found: $pattern.s3.amazonaws.com"
done
```

__Azure Blob Storage Enumeration__
```bash
# Predictable naming patterns
for pattern in "target" "targetcompany" "target-corp"; do
    for endpoint in "blob.core.windows.net" "file.core.windows.net"; do
        curl -s -I "https://$pattern.$endpoint" | grep -q "200\|403" && \
          echo "[+] Found: https://$pattern.$endpoint"
    done
done
```

__GCP Cloud Storage Checks__
```bash
# Using GCPBucketBrute
git clone https://github.com/Rhynorater/GCPBucketBrute
cd GCPBucketBrute
python3 gcpbucketbrute.py -k target -p read,write,list

# Manual check
curl -s "https://storage.googleapis.com/target-bucket-name" | grep -q "AccessDenied\|ListBucket" && echo "[+] Bucket exists"
```

### 🔄 Complementary Tools
| 🛠️ Tool        | ☁️ Cloud     | 💪 Strength                                      |
|---------------|--------------|--------------------------------------------------|
| MicroBurst    | Azure        | PowerShell-native, storage + SQL enum           |
| Pacu          | AWS          | Modular exploitation framework                  |
| ScoutSuite    | Multi-cloud  | Rule-based misconfig detection                  |
| cloud_enum    | Multi-cloud  | Keyword brute-forcing + DNS checks              |

> 💡 Pro Tip: Cloud assets often follow naming conventions: `{company}-{env}-{service}`. Build wordlists from OSINT-derived company names + common envs (`dev`, `staging`, `prod`).

# 🔗 Supply Chain & Third-Party Recon
### 🔍 Why Supply Chain Matters
Third-party integrations expand attack surface: SaaS tools, CDNs, analytics, and partner domains may have weaker security

### 🎯 Discovery Techniques
__SPF Include Chain Analysis__
```bash
# Extract all SPF includes recursively
dig TXT target.com +short | grep -oE 'include:[^ "]+' | sed 's/include://' | while read domain; do echo "[+] Third-party email service: $domain" ; dig TXT $domain +short | grep -oE 'include:[^ "]+' | sed 's/include://' ;done
```

__JavaScript Import Analysis__
```bash
# Find third-party JS libraries + CDNs
cat live_hosts.txt | httpx -silent -js-crawl | grep -oE 'https?://[^"]+\.(js|css)' | grep -v "target.com" | sort -u > third_party_assets.txt

# Extract domains from imports
cat third_party_assets.txt | grep -oE 'https?://[a-zA-Z0-9.-]+' | sed 's|https\?://||' | cut -d'/' -f1 | sort -u > third_party_domains.txt
```

__OAuth Consent Screen Enumeration__
```bash
# Check for registered OAuth apps (requires user context, but public metadata exists)
curl -s "https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000003-0000-0000-c000-000000000000&redirect_uri=https://target.com&response_type=code&scope=openid" | grep -i "target.com" && echo "[+] Target uses Microsoft OAuth"
```

### 🛠️ Tool: Maltego for Supply Chain Mapping
```bash
# Maltego transforms (commercial but powerful)
# Transform: "To Domain Names [from SPF]"
# Transform: "To DNS Name [from JS Import]"
# Transform: "To Organization [from WHOIS]"
```

> 💡 Pro Tip: Cross-reference third-party domains with Shodan/Censys to find exposed admin panels or misconfigured services.

# 🔌 API Discovery & Shadow API Enumeration
### 🔍 What Are Shadow APIs?
Undocumented, unmanaged, or forgotten API endpoints that bypass security controls 

### 🎯 Discovery Techniques
__Wayback + Parameter Mining__
```bash
# Extract API-like URLs from Wayback
cat wayback_all.txt | grep -iE "api|graphql|rest" | \
  grep -oE 'https?://[^"]+/api/[^"]*' | sort -u > shadow_apis.txt

# Extract parameters from API URLs
cat shadow_apis.txt | grep -oE '\?[^\s#]+' | tr '&' '\n' | sort -u > api_params.txt
```

__JS File Endpoint Correlation__
```bash
# Combine LinkFinder output with live host checking
cat endpoints_clean.txt | httpx -silent -status-code -mc 200,401,403 -o validated_apis.txt
```

__GraphQL Introspection Check__
```bash
# Test for GraphQL introspection (if endpoint found)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' | \
  grep -q "__schema" && echo "[+] GraphQL introspection enabled"
```

### 🛠️ Tool: Kiterunner for API Route Brute-Forcing
```bash
# GitHub: https://github.com/assetnote/kiterunner
go install github.com/assetnote/kiterunner/cmd/kr@latest

# Scan with bundled wordlists
kr scan target.com -w wordlists/api-routes.kw -o api_routes.json

# Filter for interesting responses
jq -r '.[] | select(.status == 200 or .status == 401) | .path' api_routes.json
```
> ⚠️ Correction: Not all 401/403 responses indicate a valid endpoint — some apps return these for any path. Always correlate with JS/Wayback data.

# 📄 Document & Metadata Harvesting
### 🔍 Why Documents Matter
Public PDFs, DOCX, XLSX files often contain: internal usernames, software versions, network paths, and email addresses

### 🎯 Document Discovery via Google Dorks
```bash
# Search for sensitive filetypes
site:target.com filetype:pdf "confidential" OR "internal"
site:target.com filetype:docx "password" OR "credential"
site:target.com filetype:xlsx "employee" OR "user"

# Search for config/backup files
site:target.com ext:bak OR ext:backup OR ext:old OR ext:config
```

### 🛠️ Metadata Extraction Tools
| 🛠️ Tool        | 🔍 Purpose                               | 💻 Command                                      |
|---------------|-------------------------------------------|------------------------------------------------|
| exiftool      | Extract metadata from images/docs         | exiftool document.pdf                          |
| Metagoofil    | Bulk download + metadata extract          | metagoofil -d target.com -t pdf,docx -l 20 -o output |
| pdf-parser.py | Analyze PDF internals                     | pdf-parser.py --search /URI document.pdf       |

### 🎯 exiftool Bulk Scan
```bash
# Download documents first (respect robots.txt)
wget -r -l 2 -A pdf,docx,xlsx -e robots=off https://target.com -P docs/

# Extract metadata from all files
find docs/ -type f -exec exiftool -FileName -Author -Company -Software {} \; > metadata_output.txt

# Parse for interesting fields
cat metadata_output.txt | grep -iE "author|company|software|creator" | sort -u
```

> 💡 Pro Tip: Look for `Creator Tool` or `Producer` fields — they often reveal internal software versions that may be vulnerable.


# 👥 Advanced User/Identity Enumeration
### 🔍 Beyond GetCredentialType: Cross-Platform Correlation
__LinkedIn + Hunter.io Combo__
```bash
# Extract employee names from LinkedIn (manual or with IceScraper [[GitHub]])
# Then generate email patterns:
# first.last@target.com, f.last@target.com, firstl@target.com

# Validate with Hunter.io API (free tier)
curl -s "https://api.hunter.io/v2/email-verifier?email=john.doe@target.com&api_key=YOUR_KEY" | \
  jq -r '.data.status'
```

### Breached Data Correlation
```bash
# Check HaveIBeenPwned API (requires API key)
curl -s -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" | \
  jq -r '.[].Name' && echo "[+] Email found in breach"

# Use DeHashed (paid) for broader breach coverage
```

### Microsoft Graph Unauthenticated Quirks
```bash
# Try autocomplete endpoint (rate-limited, but sometimes works)
curl -s "https://login.microsoftonline.com/common/autologon?username=user@target.com" | \
  grep -q "user_exists" && echo "[+] User exists"

# Note: Microsoft actively patches these; test with known valid/invalid accounts first
```

### 🛠️ Tool: o365spray (Multi-Module Enumeration)
```bash
# GitHub: https://github.com/0xZDH/o365spray
git clone https://github.com/0xZDH/o365spray
cd o365spray && pip install -r requirements.txt

# Enumerate users via multiple methods
python3 o365spray.py --enumerate -d target.com -U usernames.txt -t 5

# Modules: autologon, oauth2, onedrive, skypetoken
```

> ⚠️ Rate Limiting Tip: Add `--delay 2-5` to avoid IP bans. Rotate user-agents: `--user-agent random`.

# 🤖 Automation & Intelligence Correlation
### 🔍 Why Automate?
Manual recon doesn't scale. Automation ensures: deduplication, correlation, and prioritization of findings.

### 🎯 Simple Python Orchestrator Skeleton
```python
#!/usr/bin/env python3
# recon_orchestrator.py - Basic framework

import subprocess, json, re
from collections import defaultdict

TARGET = "target.com"
RESULTS = defaultdict(list)

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

# Phase 1: Domain discovery
domains = run_cmd(f"amass intel -org '{TARGET}' -max-dns-queries 25 | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}' | sort -u")
RESULTS['domains'] = domains.split('\n') if domains else []

# Phase 2: Azure tenant enum
for domain in RESULTS['domains']:
    tenant_id = run_cmd(f"curl -s 'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration' | jq -r '.token_endpoint' | grep -oE '[a-f0-9-]{{36}}'")
    if tenant_id:
        RESULTS['tenants'].append({'domain': domain, 'tenant_id': tenant_id})

# Phase 3: Subdomain enum + validation
subdomains = run_cmd(f"subfinder -d {','.join(RESULTS['domains'])} -silent | httpx -silent -status-code -mc 200,401,403")
RESULTS['live_subdomains'] = [line.split()[0] for line in subdomains.split('\n') if line]

# Output structured JSON
with open(f"{TARGET}_recon.json", "w") as f:
    json.dump(RESULTS, f, indent=2)

print(f"[+] Recon complete. Results in {TARGET}_recon.json")
```

### 🎯 Findings Prioritization Matrix
```bash
Score = (Exploitability × Exposure × Business Impact) / Effort

High Priority (Score ≥ 8):
├─ Exposed admin panel with default creds
├─ Public S3 bucket with sensitive data
├─ Valid user + weak password policy
├─ Unpatched internet-facing service (CVE)

Medium Priority (Score 4-7):
├─ Subdomain takeover opportunity
├─ Information disclosure in API response
├─ Weak SPF/DMARC configuration

Low Priority (Score ≤ 3):
├─ Outdated but non-critical software version
├─ Internal path disclosed in JS (no auth bypass)
```

# 🧰 Tool Summary & Quick Reference
```bash
┌────────────────────────────────────────────────────────────────┐
│  🎯 PHASE                │ 🔧 TOOL / COMMAND                  │
├────────────────────────────────────────────────────────────────┤
│  GitHub Recon            │ truffleHog, gitleaks, dorks         │
│  Wayback Mining          │ waymore, waybackurls + grep         │
│  JS File Analysis        │ LinkFinder, JShunter, httpx         │
│  Azure Post-Patch Enum   │ azmap.dev API, AADInternals         │
│  Multi-Cloud Discovery   │ cloud_enum, MicroBurst, Pacu        │
│  Supply Chain Mapping    │ SPF parsing, Maltego, JS imports    │
│  Shadow API Discovery    │ kiterunner, GraphQL introspection   │
│  Document Metadata       │ exiftool, Metagoofil, dorks         │
│  Advanced User Enum      │ o365spray, Hunter.io, breach DBs    │
│  Automation              │ Python orchestrator + jq            │
│  Prioritization          │ Scoring matrix + tagging            │
└────────────────────────────────────────────────────────────────┘
```

# ⚡ One-Liner Setup Script (Kali/Debian)
```bash
#!/bin/bash
# recon2_setup.sh - Install Recon 2.0 toolkit

echo "[+] Updating system..."
sudo apt update && sudo apt upgrade -y

echo "[+] Installing core dependencies..."
sudo apt install -y \
  jq dnsutils curl wget git python3-pip golang \
  exiftool libimage-exiftool-perl

echo "[+] Installing Python tools..."
pip3 install --user \
  truffleHog SecretFinder metagoofil \
  requests beautifulsoup4

echo "[+] Installing Go tools..."
go install -v github.com/zricethezav/gitleaks/v8@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[+] Cloning key repos..."
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/xnl-h4ck3r/waymore
git clone https://github.com/initstring/cloud_enum
git clone https://github.com/0xZDH/o365spray
git clone https://github.com/DrAzureAD/AADInternals

echo "[+] Adding to PATH (add to ~/.bashrc)..."
echo 'export PATH=$PATH:~/go/bin:~/tools/waymore:~/tools/cloud_enum' >> ~/.bashrc
source ~/.bashrc

echo "[+] ✅ Recon 2.0 toolkit installed!"
echo "[+] Run: ~/tools/recon2_setup.sh && source ~/.bashrc"
```
> 🚫 Unauthorized access is illegal in most jurisdictions and can result in criminal prosecution, fines, or imprisonment.
