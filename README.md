# 🔍 External Reconnaissance Playbook
> A professional, step-by-step guide for external reconnaissance in red team engagements — focused on Azure AD, domain enumeration, and cloud asset discovery.

```bash
Org Name → Domains → Azure Tenant → Assets → Users
```
# 📦 What's Inside
| 🧭 Phase                | 🔑 Key Techniques                                                |
|------------------------|-------------------------------------------------------------------|
| 🔎 Domain Discovery     | Google dorks, Amass, crt.sh, WHOIS                               |
| ☁️ Azure Enumeration   | getuserrealm.srf, OpenID config, Tenant ID lookup                 |
| 🔐 Auth Model Analysis | PHS vs PTA vs ADFS breakdown                                      |
| 📧 DNS Records         | MX, SPF, DMARC enumeration & parsing                              |
| ☁️ Cloud Assets        | cloud_enum, MicroBurst, Azure storage brute                       |
| 👥 User Enumeration    | GetCredentialType API, o365creeper                                |
| 🌐 Subdomain Enum      | CT logs, bruteforce, validation pipeline                          |
| 🛠️ Tech Fingerprinting| webanalyze, Wappalyzer, nuclei                                    |
