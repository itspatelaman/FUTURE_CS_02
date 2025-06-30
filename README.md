# 🛡️ SOC Security Alert Monitoring Report – Splunk SIEM

> 📊 A real-world Security Operations Center (SOC) simulation project created as part of the **Future Interns Cybersecurity Internship Program**, focused on log ingestion, query building, and security incident analysis using **Splunk Enterprise SIEM**.

---

## 📌 Project Overview

This report documents the detection, analysis, and classification of simulated security incidents using Splunk.  
The task simulates the role of a SOC Analyst by ingesting various Linux system logs, building search queries, and identifying indicators of attack, such as:

- 🔐 Brute-force SSH login attempts
- 🔎 Blocked unauthorized RDP connections
- ⚠️ Suspicious command execution
- 👀 Multiple successful logins from the same external IP
- 🌐 Unusual access attempts on non-standard ports

Each incident is analyzed for severity, threat indicators, and recommended mitigation steps — reflecting SOC best practices.

---

## 👨‍💻 Internship Program

**Future Interns – Cybersecurity Internship**  
Conducted by **Future Interns**  
**Intern:** Aman Patel – *Cybersecurity & Ethical Hacking Enthusiast*  
**Date:** 29th June 2025

---

## 🧰 Tools & Technologies Used

| Tool/Tech                | Description                            |
|--------------------------|----------------------------------------|
| 🖥️ Splunk Enterprise     | SIEM platform for log search & analysis |
| 🐧 Linux Log Files        | `auth.log`, `syslog.log`, `network_connections.log` |
| 📂 Manual Log Ingestion   | Via Splunk UI (local setup on Windows 11) |
| 📸 Screenshots            | From Splunk's Search & Reporting app   |
| 📝 Report Compilation     | Markdown + Microsoft Word              |

---

## 📂 Repository Structure
``` 
📁 SOC-Security-Incident-Analysis-Splunk/
├── README.md <-- This file
├── report.md <-- Full report in markdown format
├── screenshots/ <-- All referenced screenshots
│ ├── Screenshot1.png
│ ├── Screenshot2.png
│ └── ...
├── log_samples/ (optional) <-- Sample logs if allowed
├── queries.txt (optional) <-- Splunk queries used
└── report.pdf (optional) <-- Exported version of the report
```

---

## 🚨 Key Findings

| Incident # | Type                            | Severity |
|------------|----------------------------------|----------|
| 1          | SSH Brute-Force Attempt         | 🔴 High  |
| 2          | Blocked RDP Access              | 🔴 High  |
| 3          | Suspicious Command Execution    | 🟠 Medium|
| 4          | Multiple Logins (Same IP)       | 🟠 Medium|
| 5          | Unusual Port Access Attempts    | 🟠 Medium|

Each incident includes:
- Splunk query used
- Sample logs
- Screenshot reference
- Threat context + recommendations

---

## ✅ Recommendations Summary

- 🔐 **Strengthen Authentication:** Lockouts, 2FA, login monitoring  
- 🔥 **Network Hardening:** Block unused ports, strict firewall rules  
- 🛡️ **Least Privilege:** Restrict dangerous commands like `wget`, `curl`  
- 📈 **Alerting:** Set up alerts for login anomalies and command usage  
- 📋 **Response Readiness:** Maintain up-to-date playbooks and simulate attacks

---

## 📎 Appendix

- [x] All screenshots are saved in `/screenshots/`  
- [x] Splunk queries are listed in `queries.txt`  
- [x] Sample `.log` files excluded due to size or sensitivity (add your own)

---

## 🚀 Outcome

This internship simulation project helped build strong practical knowledge in:
- SOC workflows
- Splunk query writing
- Log file investigation
- Incident documentation and reporting

It reflects readiness to handle real-world SOC environments and contribute as a junior SOC analyst or cybersecurity intern.

---

## 📬 Contact

If you'd like to collaborate or know more about this project:

**Aman Patel**  
🔗 [LinkedIn Profile](https://www.linkedin.com/in/its-aman-patel)  
💻 [GitHub](https://github.com/itspatelaman)

---

