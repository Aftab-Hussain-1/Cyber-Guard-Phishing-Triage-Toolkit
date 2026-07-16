# 🎣 Cyber Guard — Phishing Triage Toolkit

**DecodeLabs Cyber Security Internship — Project 3: Phishing Awareness Analysis**

A stylish, hacker-themed **desktop application** (built with Python + CustomTkinter) that analyzes suspicious emails and messages, flags social-engineering red flags, and produces a triage verdict using the **Pause → Verify → Report** decision tree. Not a website — a native GUI app that runs locally on your machine.

![Status](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 🎯 Project Goal

Analyze sample emails or messages to identify phishing attempts by:
- Identifying suspicious links or keywords
- Listing red flags found in the message
- Explaining *why* the message is unsafe
- Producing a definitive triage outcome: **Safe → Close**, **Suspicious → Warn User**, or **Malicious → Block & Escalate**

---

## ✨ Features

- **Inbox Inspector** — enter sender display name, sender email, reply-to, subject, and body just like a real inbox
- **Built-in test samples** — one-click load of a Safe email, a Business-Email-Compromise (BEC) scam, and a credential-harvesting phishing email
- **12-point red flag scanner**, covering:
  - Display-name vs. domain spoofing
  - Reply-To domain mismatch
  - Lookalike / typosquatted domains (e.g. `amaz0n.com`)
  - Authority impersonation from free webmail
  - Urgency and time-pressure language
  - Authority / bypass-procedure pressure
  - Fear & greed manipulation
  - Requests for sensitive information (passwords, OTPs, card numbers)
  - Secrecy demands
  - Raw IP-address links
  - Shortened URLs
  - Dangerous attachment extensions (`.exe`, `.iso`, `.js`, `.scr`, etc.)
- **Threat score meter** (0–100) with color-coded verdict: 🟢 Safe → 🟡 Suspicious/Low Risk → 🔴 Malicious
- **Explainable results** — every red flag comes with a plain-language reason, not just a label
- **Golden Rule reminder** — reinforces Pause, Verify, Report on every screen

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9 or higher

### Installation

```bash
pip install customtkinter
```

> **Note:** On Linux you may also need Tkinter:
> ```bash
> sudo apt-get install python3-tk
> ```

### Run the App

```bash
python phishing_triage_toolkit.py
```

---

## 🧠 How the Triage Decision Tree Works

```
Incoming Message
      │
      ▼
Scan for red flags (sender, links, language, attachments)
      │
      ▼
 ┌─────────┬──────────────┬────────────┐
 │  SAFE   │  SUSPICIOUS  │ MALICIOUS  │
 │ (Close) │ (Warn User)  │(Block &    │
 │         │              │ Escalate)  │
 └─────────┴──────────────┴────────────┘
```

| Verdict | Trigger Condition | Action |
|---|---|---|
| **SAFE** | No red flags detected | Close |
| **LOW RISK** | Only minor/weak signals (e.g. one urgency word) | Monitor |
| **SUSPICIOUS** | At least one high-severity flag, or score ≥ 25 | Warn User / Verify Out-of-Band |
| **MALICIOUS** | At least one critical flag (sensitive-info request, malicious link, dangerous attachment, secrecy demand), or score ≥ 55 | Block Domain & Escalate |

---

## 🗂️ Project Structure

```
├── phishing_triage_toolkit.py   # Main application (GUI + analysis engine)
└── README.md                    # This file
```

---

## ⚠️ Disclaimer

This tool is for **educational purposes** as part of a cyber security internship project. It performs local, in-memory text analysis only — it does not send, fetch, or click any link, and does not scan real inboxes or live network traffic.

---

## 📄 License

MIT License — free to use, modify, and share for learning purposes.

---

*Built with 🐍 Python and 🖤 CustomTkinter as part of the DecodeLabs Cyber Security Internship — "Building the Human Firewall."*
