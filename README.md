# 🛡️ PhishGuard Enterprise v2.0
> **Advanced Zero-Trust URL Phishing Analysis & OSINT Platform**  
> 👨‍💻 Architected and Developed by **[GAURAV MEENA]**

![Python](https://img.shields.io/badge/Python-FastAPI-blue?style=for-the-badge&logo=python)
![React](https://img.shields.io/badge/React-Vite-blue?style=for-the-badge&logo=react)
![Tailwind](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css)
![Selenium](https://img.shields.io/badge/Selenium-Deep_Trace-43B02A?style=for-the-badge&logo=selenium)
![AI](https://img.shields.io/badge/AI-Google_Gemini-orange?style=for-the-badge)

---

## 📦 PART 1: WHAT IS PHISHGUARD?

PhishGuard is an enterprise-grade cybersecurity tool designed to detect malicious URLs, IP Loggers, Webhooks, and Phishing domains in real-time. It moves beyond traditional signature-based detection by utilizing a **Zero-Trust Multi-Layered Architecture**, bypassing JavaScript redirects, Cloudflare protections, and Cloaking techniques using Headless Browsers.

### 🔥 Core Capabilities:
*   **Zero-Trust Deep Tracing (Selenium):** Uses a headless Chrome browser to patiently follow multi-level redirect chains (up to 12 seconds) and find the *True Destination* of any masked link.
*   **5-Engine Threat Intelligence:** Cross-references URLs against **VirusTotal, Google Safe Browsing, URLhaus, and AbuseIPDB**.
*   **OSINT & Network Forensics:** Extracts Domain Registration (WHOIS), resolves IPs via NSLookup, and scans for open server ports using **Shodan API**.
*   **AI-Powered Prediction:** Utilizes **Google Gemini AI (gemini-pro)** to act as a virtual cybersecurity analyst. Includes an *"AI Overrule"* fail-safe to prevent false positives on legitimate websites.
*   **Smart Omnitool Dashboard:** A premium, dark-mode SOC-style UI built with React. Paste a single URL for a deep Bento-box report, or paste up to 10 URLs for a **Live Batch-Scanning Table**.

---

## ⚙️ PART 2: HOW TO INSTALL AND RUN (For Developers)

Follow these exact terminal commands to download and run PhishGuard on your local machine.

### Step 1: Prerequisites
Make sure you have these installed on your system:
*   **Python 3.9+** 
*   **Node.js & npm** 
*   **Google Chrome Browser** (Required for the Selenium Tracer)

### Step 2: Clone the Project
Open your terminal/Command Prompt and run:
```bash
git clone https://github.com/your-username/PhishGuard.git
cd PhishGuard

Install Dependencies
1. Install Backend (Python) Packages:
cd _backend_and_core
pip install -r ../requirements.txt


2. Install Frontend (React) Packages:
cd _frontend_web
npm install

Step : 🚀 Boot Up the System!

Run the master automation script from the main folder. This single command will start both the FastAPI backend and the React frontend.

python gaurav.py


PART 3: CHROME EXTENSION SETUP
Open Google Chrome and type chrome://extensions/ in the URL bar.
Toggle and Enable "Developer mode" in the top right corner.
Click the "Load unpacked" button on the top left.
Select the 2_browser_extension folder from this downloaded project directory.
Pin the 🛡️ PhishGuard extension to your browser toolbar.
Click on the extension icon on any website and press "SCAN CURRENT PAGE" for instant AI analysis.
(Note: The Python backend must be running locally python gaurav.py for the extension to fetch results)