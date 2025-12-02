# 🛡️ MalCommandGuard: Advanced Command & URL Detection System

**Author:** Jeniffer Su Kai Li

MalCommandGuard is an advanced security system prototype designed to detect malicious commands and URLs in real-time. It was developed to counter the challenge posed by attackers who "live off the land" by using normal system tools like PowerShell and CMD to hide malicious activities, which often bypasses traditional antivirus software.

The system emphasizes security by design and provides immediate alerts through multiple channels when threats are detected.

---

## ✨ Core Features

MalCommandGuard uses a lightweight, multi-layered approach to detection while maintaining good performance and user-friendly operation.

### 1. Multi-Layered Detection Engine

The system combines three different detection methods working together:

* **Rule-Based Detection:** Applies pattern recognition against **56 predefined detection rules** and heuristics that cover known malicious patterns.
* **Signature-Based Detection:**
    * **Local Database:** Uses an **Excel-based detection database** (Apache POI) containing **572+ detailed command entries** for fast local threat matching.
    * **Cloud (VirusTotal API):** Submits commands, URLs, and file hashes (MD5, SHA1, SHA256) to VirusTotal's multi-engine database for external verification and global threat intelligence.
* **Behavioral Pattern Analysis:** Implements a multi-factor **weighted scoring algorithm** to identify anomalous patterns and sequences.
    * The **Overall Risk Score** is calculated based on weighted parameters, with high emphasis on Content Score (0.40) and Frequency Score (0.20).
    * Commands are classified as **Malicious ($0.7 - 1.0$)**, **Suspicious ($0.4 - 0.69$)**, or **Legitimate ($0.0 - 0.39$)**.

### 2. Security Controls (Secure by Design)

The system incorporates advanced secure coding techniques to ensure a robust and resilient posture:

* **Advanced Password Hashing:** Implements **SHA-256 hashing with Salt** to strengthen password protection against rainbow table attacks.
* **Brute Force Protection:** Limits login attempts to a **maximum of 3 failures**, after which the system locks out and terminates for security reasons.
* **Role-Based Access Control (RBAC):** Restricts access to sensitive functions (like the Admin Panel) based on assigned roles (Admin vs. User).
* **Input Validation & Sanitization:** Filters and sanitizes user input to prevent injection attacks and enforces length and format checks.
* **Secure Logging:** Provides a **Comprehensive Logging System** for audit and forensic analysis, saving detection events with timestamps, commands, and classification scores.

### 3. Alert & Notification System

Alerts are provided through multiple channels for maximum visibility:

* **Console Output:** Real-time messages are displayed immediately in the terminal.
* **GUI Popups:** Visual dialog boxes notify users of suspicious or critical actions.
* **VirusTotal Reports:** Detailed external analysis results are automatically fetched and displayed for commands, URLs, and hashes.

---

## 💻 Technical Stack

| Component | Technology | Rationale / Key Feature |
| :--- | :--- | :--- |
| **Programming Language** | Java | Platform independence ("write once, run anywhere"), built-in security managers, and cryptographic libraries. |
| **User Interface** | CLI with GUI Components | Combines rapid interaction (CLI) with secure credential input (GUI password dialogs). |
| **Database** | Apache POI + Excel | Flexible format for non-technical users to update the threat intelligence. |
| **External Integration** | VirusTotal API | Leverages global threat intelligence to verify detections. |

---

## 🚀 Getting Started

### Prerequisites
* Java Development Kit (JDK) 11+ (or compatible version)

### Sample Commands (For Testing)
Use these examples to test the system's detection and classification capabilities:

| Classification | Example Command(s) |
| :--- | :--- |
| **Malicious** | `certutil -urlcache`, `http://www.eicar.org/download/eicar.com.txt` |
| **Suspicious** | `net user administrator`, `whoami /priv` |
| **Legitimate** | `ipconfig /all`, `ping google.com` |

---

## 📄 MalCommandGuard Handbook
https://github.com/JenifferSu/MalCommandGuard/blob/main/MalcommandGuard%20HandBook.pdf


