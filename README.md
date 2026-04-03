# Advanced External Reconnaissance Playbook
> A complete, step-by-step OSINT & external recon framework for authorized red team engagements. Combines Recon 1.0 (foundational) + Recon 2.0 (advanced) into a single, actionable workflow.

```bash
Org Name → Domains → Azure/Cloud → Assets → Users → APIs
```
# 📦 What's Inside
| 🧭 Phase                  | 🔑 Techniques (v1.0 + v2.0)                                                                 |
|--------------------------|----------------------------------------------------------------------------------------------|
| 🔎 Domain & Subdomain     | Google dorks, Amass, CRT logs, puredns, wildcard filtering                                  |
| ☁️ Azure/Entra ID        | getuserrealm.srf, OpenID config, PHS/PTA/ADFS detection, tenant mapping                     |
| 🌐 DNS & Email           | MX/SPF/DMARC parsing, third-party service discovery, include-chain tracing                  |
| 🗃️ Cloud Assets          | cloud_enum, MicroBurst, AWS/Azure/GCP bucket brute-forcing                                  |
| 👥 User Enumeration      | GetCredentialType API, o365spray, Hunter.io, breach correlation                             |
| 🐙 Advanced OSINT        | GitHub leak hunting, Wayback mining, JS endpoint extraction, Shadow APIs                    |
| 🤖 Automation            | Python orchestrator, deduplication pipeline, exploitability scoring matrix                  |


# 🚀 Quick Start
```bash
# 1. Clone the repo
git clone https://github.com/yourusername/recon-playbook.git && cd recon-playbook

# 2. Read the full guides
cat recon_v1.md                # Foundational methods
cat recon_2.0_playbook.md      # Advanced expansion

# 3. Install toolkit (Kali/Debian)
bash setup.sh
```

> "Recon is not a phase, it's a mindset. Depth beats breadth."
> Start with `ExternalRecon.md` → Expand with `ExternalRecon2.0.md`
