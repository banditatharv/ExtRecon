# 🔍 External Reconnaissance Playbook
_Professional Guide | Azure AD Focus | 2025_

```bash
┌─────────────────────────────────────────────────────┐
│  SCOPE: Organization Name → Domains → Assets → Users│
└─────────────────────────────────────────────────────┘
```

# 📋 Table of Contents
- [Root Domain Discovery](#-1-root-domain-discovery)
- [Azure Tenant Enumeration](#️-2-azure-tenant-enumeration)
- [Authentication Model Analysis](#-3-authentication-model-deep-dive-phs-vs-pta-vs-adfs)
- [Tenant ID & OpenID Configuration](#-4-tenant-id--openid-configuration)
- [DNS Record Enumeration](#-5-dns-record-enumeration)
- [Cloud Asset Discovery](#️-6-cloud-asset-discovery)
- [User Enumeration](#-7-user-enumeration)
- [Subdomain Enumeration](#-8-subdomain-enumeration)
- [Technology Fingerprinting](#️-9-technology-fingerprinting)
- [Tool Summary & Quick Reference](#-tool-summary--quick-reference)

# 🎯 1. Root Domain Discovery

Objective: Given only an organization name, discover all associated root domains.

## 🔎 Methods & Tools
### A. Google Dorking Techniques

```bash
# Basic organization search
site:linkedin.com/company "Organization Name" "domain"
site:github.com "Organization Name" "@domain.com"

# Email pattern discovery
"Organization Name" "@*.com" -site:linkedin.com
intext:"@organization.com" OR "@org-domain.net"

# Certificate transparency hints
site:crt.sh "Organization Name"
```
---
### B. Passive DNS & OSINT Tools
```bash
# Using Amass (comprehensive)
amass intel -org "Organization Name" -max-dns-queries 50

# Using Hunter.io API (requires API key)
curl -s "https://api.hunter.io/v2/domain-search?company=Organization+Name&api_key=YOUR_KEY"

# Using Shodan
shodan search org:"Organization Name" --fields ipstr,port,hostnames
```
---

### C. Certificate Transparency Logs
```bash
# Quick crt.sh search for organization-related domains
curl -s "https://crt.sh/?q=%25Organization%25&output=json" | \
  jq -r '.[].name_value' | \
  grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
  sort -u | grep -v '\*'
```
---

### D. WHOIS & Registration Data
```bash
# Reverse WHOIS (via SecurityTrails, DomainTools, or free alternatives)
# Free option using whoisxmlapi (limited free tier)
curl -s "https://whois.whoisxmlapi.com/api/v1?apiKey=FREE_KEY&searchType=reverseWhois&mode=purchase&term=Organization+Name"
```

> 💡 Pro Tip: Combine multiple methods. No single source is 100% complete. Cross-reference results to build a master domain list.

---

# ☁️ 2. Azure Tenant Enumeration
🔑 Microsoft Unauthenticated API: `getuserrealm.srf`

__EndPoint:__
```bash
https://login.microsoftonline.com/getuserrealm.srf?login=anyuser@TARGET_DOMAIN&xml=1
```

__Example Response Breakdown:__
```bash
<RealmInfo Success="true">
  <State>4</State>                          <!-- Realm state code -->
  <UserState>1</UserState>                  <!-- User state code -->
  <Login>USERNAME@domain.com</Login>        <!-- Queried identifier -->
  <NameSpaceType>Managed</NameSpaceType>    <!-- 🔑 AUTH MODEL KEY -->
  <DomainName>domain.com</DomainName>       <!-- Verified domain -->
  <IsFederatedNS>false</IsFederatedNS>      <!-- 🔑 FEDERATION FLAG -->
  <FederationBrandName>domain</FederationBrandName>
  <CloudInstanceName>microsoftonline.com</CloudInstanceName>
</RealmInfo>
```

## 📊 Field Deep-Dive

| Field             | Value      | Meaning                                                                                                                                         | Red Team Implication                                                                                                      |
|------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| `<NameSpaceType>`  | Managed    | Authentication handled by Azure AD (cloud). May include: ☁️ Cloud-only identities, 🔁 Password Hash Sync (PHS), 🔄 Pass-Through Authentication (PTA) | Password spray attacks possible against Azure AD endpoints. On-prem credentials may work if PHS/PTA enabled.             |
| `<NameSpaceType>`  | Federated  | Authentication delegated to external Identity Provider (ADFS, Okta, Ping, etc.)                                                                 | Target the federation service (often on-prem, potentially less hardened). ADFS endpoints may be vulnerable to misconfigurations. |
| `<IsFederatedNS>`  | false      | Domain is not federated. Uses Azure AD-native auth (Managed).                                                                                    | Focus on Azure AD attack surface: password spray, token manipulation, OAuth abuse.                                        |
| `<IsFederatedNS>`  | true       | Domain is federated. Auth flows through external IdP.                                                                                            | Enumerate ADFS endpoints (/adfs/ls/, /adfs/services/trust). Test for ADFS vulnerabilities (e.g., CVE-2022-26923).         |

> ⚠️ Correction: NameSpaceType=Managed does NOT mean "no on-prem AD". Hybrid environments using PHS or PTA still show as Managed because Azure AD accepts the authentication decision, even if credentials are validated on-prem.

---
## 🔁 Authentication Model Flow Diagram
```bash
┌─────────────────────────────────────────┐
│         USER LOGIN ATTEMPT              │
└────────────────┬────────────────────────┘
                 ▼
┌─────────────────────────────────────────┐
│  IsFederatedNS = true?                  │
├───────────────┬─────────────────────────┤
│ YES           │ NO                      │
▼               ▼                         │
┌─────────────┐ ┌─────────────────────┐   │
│ FEDERATED   │ │ MANAGED             │   │
│ • ADFS      │ │ • Cloud-only        │   │
│ • Okta      │ │ • PHS (Password Hash│   │
│ • Ping      │ │   Sync)             │   │
│ • Custom IdP│ │ • PTA (Pass-Through │   │
└──────┬──────┘ │   Authentication)   │   │
       │        └──────────┬──────────┘   │
       ▼                   ▼              │
┌─────────────┐ ┌─────────────────────┐   │
│ Auth happens│ │ Auth decision in    │   │
│ on external │ │ Azure AD cloud      │   │
│ IdP         │ │ (creds may be       │   │
│             │ │ validated on-prem)  │   │
└─────────────┘ └─────────────────────┘   │
```
---

# 🔐 3. Authentication Model Deep Dive: PHS vs PTA vs ADFS

## 🔄 Password Hash Sync (PHS)
```bash
On-Prem AD ──[Hash Sync]──► Azure AD
                              │
                              ▼
                        Authentication in Cloud
```

- How it works: Password hashes (not plaintext) are synced from on-prem AD to Azure AD every 2 minutes - k21academy.com
- Red Team Impact: 
    - Compromised on-prem credentials may work in cloud if hash sync is active.
    - Password spray attacks can be launched directly against Azure AD endpoints.
    - No real-time password policy enforcement from on-prem.              
---

## 🔄 Pass-Through Authentication (PTA)
```bash
User Login ──► Azure AD ──[Secure Relay]──► On-Prem Agent ──► AD Validation
```
- How it works: Azure AD forwards authentication request to lightweight on-prem agents, which validate against local AD - unspoken103.rssing.com

- Red Team Impact:
    - Credentials must be valid on-prem to succeed.
    - Agents are outbound-only (no inbound ports), making them harder to target directly.
    - Password policies enforced on-prem.
---

## 🔗 Active Directory Federation Services (ADFS)
```bash
User Login ──► Azure AD ──[Redirect]──► ADFS Server ──► AD Validation ──► Token to Azure AD
```

- How it works: Azure AD trusts ADFS to authenticate users and issue tokens 
Microsoft

- Red Team Impact:
    - ADFS servers are often internet-facing and may have weaker patching cycles.
    - Vulnerable to token-signing certificate theft, SAML relay attacks, or misconfigured claim rules.
    - Enumeration endpoint: https://adfs.target.com/adfs/ls/IdpInitiatedSignon.aspx

> 📌 Key Takeaway: IsFederatedNS=false means you should focus on Azure AD-native attacks. IsFederatedNS=true means you should pivot to federation service enumeration.

---

# 🌐 4. Tenant ID & OpenID Configuration

## 🔍 Extract Tenant ID
```bash
# Using curl + jq (clean output)
curl -s "https://login.microsoftonline.com/TARGET_DOMAIN/.well-known/openid-configuration" | \
  jq -r '.token_endpoint' | \
  grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'

# Alternative: extract from any token endpoint field
curl -s "https://login.microsoftonline.com/TARGET_DOMAIN/.well-known/openid-configuration" | \
  jq -r '.issuer' | sed 's|.*/||'
```

## 🔎 Resolve Tenant ID to Organization Name
Tool: [TenantIDlookup](tenantidlookup.com) (free, no auth)
__Alternative Programmatic Method:__
```bash
# Using Microsoft Graph (requires token, but shows full tenant details)
# First get token via device code flow or app registration, then:
curl -s -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/domains" | jq
```
__What you'll learn:__
- Default domain name (e.g., domain.io)
- Organization display name
- Tenant region scope (critical for compliance targeting)
- MX record (confirms email infrastructure)

# 📧 5. DNS Record Enumeration
## 📬 MX Records (Mail Exchange)

```bash
# Using dig (most reliable)
dig +short MX target.com

# Using host (simpler)
host -t MX target.com

# Parse for mail server domains only
dig MX target.com +short | awk '{print $2}' | sort -u
```
> 💡 Why it matters: Confirms email infrastructure. Domains with valid MX records are higher-value targets for phishing simulations or credential harvesting.

## 🛡️ SPF Records (Sender Policy Framework)
```bash
# Query SPF (stored as TXT record)
dig +short TXT target.com | grep -i "v=spf1"

# Alternative with host
host -t TXT target.com | grep "spf"

# Parse includes to discover third-party email services
dig TXT target.com +short | grep -oE 'include:[^ "]+' | sed 's/include://'
```
__What SPF tells you:__
- Which IPs/services are authorized to send email for the domain
- Potential third-party services (e.g., include:spf.protection.outlook.com = Microsoft 365)
- Misconfigurations that could enable email spoofing

## 🔐 DMARC Records (Domain-based Message Authentication)
```bash
# DMARC is stored at _dmarc.target.com
dig +short TXT _dmarc.target.com

# Parse policy and reporting addresses
dig TXT _dmarc.target.com +short | grep -oE '(p=|rua=|ruf=)[^ ;"]+' 
```
__Key DMARC tags:__

| Tag | Example                    | Meaning                          |
|-----|----------------------------|----------------------------------|
| p=  | p=reject                   | Policy: none/quarantine/reject   |
| rua=| rua=mailto:d@target.com    | Aggregate report destination     |
| ruf=| ruf=mailto:f@target.com    | Forensic report destination      |
| sp= | sp=quarantine              | Subdomain policy override        |

> 🎯 Red Team Use: Weak DMARC (p=none) enables easier email spoofing for phishing campaigns. Reporting addresses may leak internal email addresses.
---

# ☁️ 6. Cloud Asset Discovery
__🛠️ Primary Tool:__ [cloud_enum](https://github.com/initstring/cloud_enum)

```bash
# GitHub: https://github.com/initstring/cloud_enum [[60]]
git clone https://github.com/initstring/cloud_enum
cd cloud_enum
python3 cloud_enum.py -k target -b aws,azure,gcp --disable-aws --disable-gcp  # Azure only
```

## 🔄 Alternative & Complementary Tools

| 🔧 Tool        | 🎯 Purpose                   | 💪 Strengths                                                                 |
|---------------|-----------------------------|------------------------------------------------------------------------------|
| MicroBurst    | Azure-specific enumeration  | PowerShell-native, integrates with Azure modules, brute-forces storage accounts |
| Azucar        | Azure security assessment   | Auto-discovers misconfigurations, RBAC issues                                |
| ScoutSuite    | Multi-cloud auditing        | Rule-based checks, HTML reports, supports Azure AD                           |
| Prowler       | Cloud security best practices | CIS benchmark compliance, Azure support growing                            |

## 🎯 MicroBurst Example (Azure Storage)
```bash
# Import module
Import-Module MicroBurst.psm1

# Enumerate storage accounts by keyword
Invoke-EnumerateAzureBlobs -Base "target" -Verbose

# Check for anonymous access on discovered containers
Invoke-EnumerateAzureStorage -StorageAccount "targetstorage" -Container "publicdata"
```

> 💡 Pro Tip: Cloud assets often have predictable naming patterns (target-dev, targetprod, target-backup). Combine keyword brute-forcing with OSINT-derived names.
---

# 👥 7. User Enumeration

__Endpoint:__ https://login.microsoftonline.com/common/GetCredentialType

__Request:__
```bash
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@target.com"}'
```
__Response Interpretation__
```bash
{
  "IfExistsResult": 0,    // ✅ Account EXISTS and uses this domain for auth
  "IfExistsResult": 1,    // ❌ Account does NOT exist
  "IfExistsResult": 2,    // ⚠️ Rate limited (slow down)
  "IfExistsResult": 4,    // ❗ Server error
  "IfExistsResult": 5,    // ℹ️ Account exists but uses different IdP (e.g., personal Microsoft account)
  "IfExistsResult": 6     // ℹ️ Account exists with multiple auth methods
}
```
> ⚠️ Correction: IfExistsResult: 0 = account exists (not the reverse). Always test with known valid/invalid accounts first to calibrate.

## Automated Enumeration Tools
| 🛠️ Tool              | ⚙️ Method                              | 📝 Notes                                                   |
|---------------------|----------------------------------------|------------------------------------------------------------|
| o365creeper         | danielchronlund.com, GetCredentialType API | Simple, reliable, outputs valid emails                    |
| o365spray           | Multiple modules (autologon, oauth2, onedrive) | Supports password spraying post-enumeration         |
| AADInternals        | aadinternals.com, PowerShell, multiple APIs | Most comprehensive; requires PowerShell               |
| onedrive_user_enum  | OneDrive API                           | Only works if user has accessed OneDrive                  |

__Example: o365creeper__
```bash
# Single email test
python3 o365creeper.py -e admin@target.com

# Bulk enumeration
python3 o365creeper.py -f potential_users.txt -o valid_users.txt -t 5  # 5 threads
```
> 🎯 Rate Limiting Tip: Add random delays (sleep $((RANDOM%5+2))) between requests to avoid IP bans. Rotate user-agents and source IPs if possible.

# 🌐 8. Subdomain Enumeration
## 🔍 Certificate Transparency Logs (Most Efficient)
```bash
# Optimized crt.sh query with filtering
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  grep -E '^.*\.target\.com$' | \
  sort -u | \
  tee -a subdomains.txt

# Alternative: use crtfinder for recursive discovery [[40]]
git clone https://github.com/yourpwnguy/crtfinder
cd crtfinder
python3 crtfinder.py -d target.com -o results.txt
```

## 🔄 Alternative CT Log Sources
```bash
# censys.io API (requires free API key)
curl -s -u "YOUR_UID:YOUR_SECRET" \
  "https://search.censys.io/api/v2/certificates/search?q=target.com&per_page=100" | \
  jq -r '.result.hits[].names[]' | grep target.com | sort -u

# Facebook CT Logs (via certspotter)
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | grep target.com | sort -u
```

## 🧱 Active Bruteforcing (Use Sparingly)

```bash
# Using puredns (fast, resolves in parallel)
puredns bruteforce wordlists/subdomains.txt target.com \
  --resolvers resolvers.txt \
  --wildcard-threads 50 \
  -o subdomains_brute.txt

# Using alterx for pattern-based generation [[44]]
alterx -p '{{word}}.target.com' -l wordlists/subdomains.txt | \
  dnsx -resp-only -silent -o subdomains_active.txt
```

## 🎯 Post-Enumeration: Validate & Filter

```bash
# Resolve all discovered subdomains and capture HTTP titles
cat subdomains_combined.txt | \
  httpx -silent -title -tech-detect -status-code -o httpx_results.txt

# Extract unique technologies for prioritization
cat httpx_results.txt | grep -oP 'tech:\[\K[^\]]+' | sort | uniq -c | sort -rn
```

# 🛠️ 9. Technology Fingerprinting
## 🔍 Primary Tool: [webanalyze](https://github.com/rverton/webanalyze)
```bash
# GitHub: https://github.com/rverton/webanalyze [[77]]
go install github.com/rverton/webanalyze/cmd/webanalyze@latest

# Single target
webanalyze -host https://sub.target.com -workers 10

# Bulk scan from file
cat subdomains_resolved.txt | webanalyze -hosts - -output json > tech_stack.json
```

## 🔄 Alternative Tools
| 🛠️ Tool                      | 💻 Language | 💪 Strengths                                           |
|-----------------------------|------------|--------------------------------------------------------|
| Wappalyzer CLI              | Node.js    | Largest detection database, frequent updates           |
| WhatWeb                     | Ruby       | Lightweight, good for quick scans                      |
| BuiltWith API               | API        | Commercial but extremely detailed (paid)               |
| projectdiscovery/nuclei     | Go         | Can fingerprint via custom templates                   |

## 🎯 Example: Extract High-Value Tech
```bash
# Parse webanalyze JSON for interesting technologies
jq -r '.[] | select(.matches != null) | 
  .matches[]? | select(.app | test("wordpress|joomla|drupal|jenkins|gitlab|jira|confluence")) | 
  "\(.host) - \(.app) \(.version? // "unknown")"' tech_stack.json

# Output example:
# admin.target.com - WordPress 6.4.2
# dev.target.com - Jenkins 2.401
```
> 💡 Red Team Priority: Focus on:
> - Admin panels (/admin, /wp-admin, /jenkins)
> - Known vulnerable versions (cross-reference with CVE databases)
> - Misconfigured cloud services (S3 buckets, Azure Blobs)

## 🧰 Tool Summary & Quick Reference
```bash
┌─────────────────────────────────────────────────────────┐
│  🎯 PHASE          │ 🔧 TOOL/COMMAND                   │
├─────────────────────────────────────────────────────────┤
│  Domain Discovery  │ amass intel, crt.sh, Google dorks  │
│  Azure Enum        │ getuserrealm.srf, openid-config    │
│  Auth Model Check  │ NameSpaceType, IsFederatedNS       │
│  DNS Records       │ dig MX/TXT, parse SPF/DMARC        │
│  Cloud Assets      │ cloud_enum, MicroBurst             │
│  User Enum         │ GetCredentialType, o365creeper     │
│  Subdomain Enum    │ crt.sh + jq, puredns, alterx       │
│  Tech Fingerprint  │ webanalyze, Wappalyzer, nuclei     │
└─────────────────────────────────────────────────────────┘
```

## 📦 One-Liner Setup (Kali/Debian)
```bash
# Install core tools
sudo apt update && sudo apt install -y \
  amass jq dnsutils curl httpx \
  python3-pip git golang

# Install Python tools
pip3 install cloud_enum o365creeper puredns

# Install Go tools
go install github.com/rverton/webanalyze/cmd/webanalyze@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Clone key repos
git clone https://github.com/initstring/cloud_enum ~/tools/cloud_enum
git clone https://github.com/rbsec/dnscan ~/tools/dnscan
```

_Document Version: 1.0 | Last Updated: 3 April 2026 | For Authorized Security Testing Only 🔐_
