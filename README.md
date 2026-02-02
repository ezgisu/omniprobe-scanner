# OmniProbe Scanner 🛡️

**OmniProbe Scanner** is a modern, all-in-one vulnerability assessment tool designed for security professionals and developers. It orchestrates powerful open-source security tools under a sleek, unified React interface to identify risks efficiently.

## 🚀 Features

- **Multi-Phase Scanning:**
  - **Port Scanning:** Nmap for fast and accurate port discovery.
  - **Service Discovery:** Httpx for identifying live web services.
  - **Deep Crawling:** Katana for exploring endpoints, JavaScript files, and APIs.
  - **Vulnerability Scanning:** Nuclei (Light/Deep modes) for detecting CVEs and misconfigurations.
  - **Fuzzing (Deep Mode):** Wapiti for advanced SQL Injection and XSS testing.
- **Modern Web UI:**
  - Real-time "Matrix Mode" logs.
  - Interactive reporting with finding aggregation.
  - Dark mode aesthetic with pink/orange neon accents.
- **Reporting:**
  - Professional PDF export with custom logo support (Whitelabeling).
  - Clean executive summaries.

## 📦 Installation

OmniProbe Scanner supports **macOS** and **Linux** (Debian/Ubuntu/Kali).

### Prerequisites
- **Git**
- **Sudo access** (for installing dependencies)

### Quick Start
1.  Clone the repository:
    ```bash
    git clone https://github.com/ezgisu/omniprobe-scanner.git
    cd omniprobe-scanner
    ```
2.  Run the installation script:
    ```bash
    chmod +x install.sh
    ./install.sh
    ```
    *This script automatically installs Nmap, Python3, Node.js, Go, Nuclei, Katana, and Wapiti.*

3.  Start the application:
    ```bash
    ./run_app.sh
    ```
4.  Open your browser at [http://localhost:5173](http://localhost:5173).

## 🛠️ Usage

1.  **Enter Target:** Input an IP address (e.g., `192.168.1.1`) or a URL (e.g., `example.com`).
2.  **Select Mode:**
    -   **Light Scan:** Fast. Checks for top ports, tech stack, and common CVEs.
    -   **Deep Scan:** Thorough. Includes full port range crawling, and detailed fuzzing (Wapiti).
3.  **Monitor:** Watch real-time logs in the "Matrix" view.
4.  **Export:** Use the "Export PDF" button to generate a report.

## 🧰 Powered By & Analyzed Tools

This project wraps several open-source security tools. Please ensure you comply with their respective licenses.

| Tool | Purpose | License | Source |
| :--- | :--- | :--- | :--- |
| **Nmap** | Network Discovery & Security Auditing | NPSL (Custom) | [nmap.org](https://nmap.org) |
| **Nuclei** | Template-based Vulnerability Scanner | MIT | [ProjectDiscovery](https://github.com/projectdiscovery/nuclei) |
| **Katana** | Next-generation Crawling & Spidering | MIT | [ProjectDiscovery](https://github.com/projectdiscovery/katana) |
| **Httpx** | Fast & multi-purpose HTTP toolkit | MIT | [ProjectDiscovery](https://github.com/projectdiscovery/httpx) |
| **Wapiti** | Web Application Vulnerability Scanner | GPLv2 | [Wapiti](https://wapiti.sourceforge.io/) |

## ⚠️ Disclaimer

**OmniProbe Scanner is for educational and authorized security testing purposes only.**
Scanning targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
*Created by Su.*
