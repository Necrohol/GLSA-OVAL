# GLSA-OVAL 🛡️

​Automated Gentoo Security Intelligence for SecOps & Infosec Workflows
​🚀 The Goal: Scalable Security Automation
​In high-velocity environments (10k+ EPS), manual review of security advisories is a liability. GLSA-OVAL bridges the gap between Gentoo’s rolling-release flexibility and enterprise-grade compliance auditing.
​By converting Gentoo Linux Security Advisories (GLSA) into enriched OVAL (Open Vulnerability and Assessment Language) feeds, this tool enables automated vulnerability scanning, SIEM correlation, and risk prioritization across massive fleets.
​🛠️ Key Features for SecOps
​Codeberg Integration: Automatically syncs with the official Gentoo glsa-content mirror.
​NVD Enrichment: Injects CVSS 3.x and 2.x scores directly into the OVAL definitions using nvdlib.
​Risk Prioritization: Automatically prefixes vulnerability titles with their Max CVSS score for instant "at-a-glance" triage in SIEM dashboards.
​CPE Mapping: Includes Inventory definitions to ensure scanners correctly identify Gentoo Linux assets.
​Audit-Ready: Outputs timestamped XML files (gentoo-YYYYMMDD-HHMM-oval.xml) for strict compliance history.
​📦 Compatibility
​This feed is designed to be consumed by both open-source and commercial security tools:
​Open Source: Vuls.io, OpenSCAP (oscap), Wazuh, Greenbone (GVM/OpenVAS).
​Enterprise: Ready for ingestion into Splunk, ELK, Tenable, or Rapid7 via custom OVAL import.
​Web Scanning: Complements tools found in the Open Source Web Scanners list by providing host-level OS vulnerability context.
​🔧 Installation

'git clone https://github.com/Necrohol/GLSA-OVAL
cd GLSA-OVAL
pip install .' 

🖥️ Usage
​Standard Generation:

# Syncs GLSA data, fetches NVD scores, and outputs timestamped OVAL
glsa-oval

SecOps Automation (Cron/Systemd):
# Example cron job for daily 2 AM updates
0 2 * * * export NVD_API_KEY="your_key" && /usr/local/bin/glsa-oval >> /var/log/glsa-oval.log 2>&1


📊 Why This Matters
​For a Security Researcher or Infosec Specialist, the difference between "Manual Reading" and "Automated Scanning" is the difference between being breached and being patched.

Feature Manual (GLSA Web) GLSA-OVAL Automation
Detection Human-speed Wire-speed
Scoring Qualitative (Text) Quantitative (CVSS 3.1)
Fleet Scale 1-5 nodes 10,000+ nodes
Intelligence Advisory only Advisory + NVD + EPSS

