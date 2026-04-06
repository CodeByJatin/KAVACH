<div align="center">
  <img src="https://img.shields.io/badge/Security-Post--Quantum-9f1239?style=for-the-badge" alt="Security" />
  <img src="https://img.shields.io/badge/AI-Ollama%20%7C%20Phi3.5-facc15?style=for-the-badge" alt="AI Engine" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Framework-Flask-black?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  
  <h1>🛡️ KAVACH</h1>
  <p><strong>Enterprise Post-Quantum Security Audit & Mitigation Platform</strong></p>
</div>

---

## 📖 Overview

**KAVACH** (Sanskrit for "Shield") is a comprehensive, AI-powered cryptographic monitoring platform. Designed for large-scale enterprise infrastructures (like banks and financial institutions), KAVACH automates the discovery, scanning, and auditing of public-facing assets to assess their vulnerability against future quantum computing threats. 

It specifically combats **"Store Now, Decrypt Later" (SNDL)** attacks by tracking TLS versions, Cipher Suites, and Key Lengths against strict NIST Post-Quantum Cryptography standards.

## ✨ Core Features

- 🔒 **MFA-Enforced Access**: Mandatory Multi-Factor Authentication prevents unauthorized access to sensitive cryptographic telemetry.
- 📡 **Automated Asset Discovery**: Passively discovers subdomains using Certificate Transparency (CT) logs to map your entire attack surface.
- 🔍 **Deep Cryptographic Scanning**: Granular assessment of TLS protocols, underlying cipher suites, and public key exchanges.
- 📊 **Visual CBOM Mapping**: Generates a dynamic Cryptographic Bill of Materials (CBOM) to visualize your security posture.
- 🤖 **Context-Aware AI Assistant (RAG)**: Uses a local AI model grounded in NIST standards to generate instant, step-by-step remediation plans for vulnerable domains.
- 📑 **Enterprise Reporting**: Generates downloadable, presentation-ready PDF certificates detailing organizational risk posture.

---

## 🧠 Local AI Engine Setup (Crucial)

KAVACH takes data privacy very seriously. Instead of relying on cloud APIs (like OpenAI), KAVACH runs a localized, air-gapped language model to analyze your vulnerabilities without ever leaking secure infrastructure data to the internet.

To run the AI Mitigation engine, **you must have Ollama running in the background.**

### 1. Install the Local AI Server
Download and install [Ollama](https://ollama.com/) for your operating system (Windows/macOS/Linux).

### 2. Pull the Phi3.5 Model
Once installed, open your terminal/command prompt and pull the Microsoft Phi-3.5 model (the 'brain' of the KAVACH assistant):
```bash
ollama pull phi3.5
```

### 3. Keep it Running
Ensure the Ollama application is actively running in your system tray/background. It listens on port `11434`. KAVACH will automatically connect to it!

---

## 🚀 Installation & Setup

Follow these steps to deploy KAVACH on your machine or local server environment.

### Prerequisites
- Python 3.9+
- Git
- Ollama (See above)

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-organization/kavach.git
cd kavach
```

### Step 2: Install Dependencies
It is highly recommended to use a virtual environment (`venv`).
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### Step 3: Download Offline Geolocation Database
KAVACH uses an air-gapped database for secure IP tracking without leaking telemetry. Run the setup script to instantly download it:
```bash
python setup.py
```

### Step 4: Initialize & Run the Application
Start the Flask web server:
```bash
python app.py
```
> **Note:** The application will automatically initialize the local `database.db` file upon the first launch.

### Step 5: Access the Dashboard
Open your web browser and navigate to:
```text
http://localhost:5000
```

---

## 🧑‍💻 Usage Guide

1. **Register**: Create an admin account and register the generated generated OTP secret in your authenticator app (e.g., Google Authenticator).
2. **Add Context**: Navigate to the sidebar and click **"Add Domain"**. Enter your primary corporate domain (e.g., `pnb.in`).
3. **Discover**: Switch to the **Discovery CT Logs** tab. Select the discovered subdomains and hit **"Deep Scan"**.
4. **Audit**: Move to the **PQC Posture Assessment** page to view granular cryptographic evaluations.
5. **Mitigate**: Click **"Inspect"** on any highly vulnerable domain, and click **"Ask KAVACH AI"** to generate a step-by-step upgrade plan!

---

## 🤝 Contributing Guidelines

We welcome contributions from the community to make KAVACH stronger! Please follow standard GitHub flow:

1. **Fork the repository**
2. **Create a Feature Branch:** `git checkout -b feature/AmazingSecurityFeature`
3. **Commit your changes:** Ensure commit messages are descriptive. `git commit -m "feat: added quantum-resistant cipher tracking"`
4. **Push to the branch:** `git push origin feature/AmazingSecurityFeature`
5. **Open a Pull Request:** Describe the problem you are solving and your approach. Wait for core maintainers to review.

### Coding Standards
- Python backend follows PEP-8 formatting.
- Frontend uses TailwindCSS utility classes to maintain design consistency without external CSS clutter.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Built with 🛡️ for a Quantum-Safe Future.*
