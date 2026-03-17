# VaultScan — AI-Powered Cybersecurity Platform

> **Scan. Detect. Secure.**  
> Enterprise-grade AI vulnerability scanner with OWASP detection and intelligent remediation.

---

## PROJECT ARCHITECTURE

```
VaultScan/
├── frontend/                    # React.js Application
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── App.js               # Router & layout
│   │   ├── index.js             # Entry point
│   │   ├── index.css            # Global styles (cyber theme)
│   │   ├── components/
│   │   │   └── Navbar.js
│   │   └── pages/
│   │       ├── LandingPage.js   # Hero + animated radar scanner
│   │       ├── ScanDashboard.js # URL input + live scan progress
│   │       ├── ResultsPage.js   # Vulnerability table + filters
│   │       ├── AIDashboard.js   # Risk charts + AI insights
│   │       ├── FixPanel.js      # Step-by-step remediation
│   │       └── ReportPage.js    # PDF download + report preview
│   └── package.json
│
├── backend/                     # Python Flask API
│   ├── main.py                  # Flask routes + API endpoints
│   ├── scanner.py               # Vulnerability scanning engine
│   ├── ai_models.py             # AI risk analysis & summaries
│   ├── report.py                # PDF report generator
│   └── requirements.txt
│
├── reports/                     # Generated PDF reports (auto-created)
└── README.md
```

---

## STEP-BY-STEP SETUP GUIDE

### Prerequisites

- **Python 3.9+** — [python.org](https://www.python.org/downloads/)
- **Node.js 18+** — [nodejs.org](https://nodejs.org/)
- **npm** (comes with Node.js)

---

### 1. BACKEND SETUP

Open a terminal and navigate to the backend folder:

```bash
cd vulnscan/backend
```

Create and activate a Python virtual environment:

```bash
# Create venv
python -m venv venv

# Activate (macOS/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Start the Flask backend:

```bash
python main.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

**Keep this terminal open.** The backend runs on port 5000.

---

### 2. FRONTEND SETUP

Open a **new terminal** and navigate to the frontend folder:

```bash
cd vulnscan/frontend
```

Install Node.js dependencies:

```bash
npm install
```

Start the React development server:

```bash
npm start
```

The browser will automatically open **http://localhost:3000**

---

### 3. USING VAULTSCAN

1. Open **http://localhost:3000** in your browser
2. Enter a target URL (only scan sites you own or have permission to test)
3. Click **LAUNCH SCAN** — the scanner will:
   - Crawl the website
   - Test 25+ OWASP vulnerability categories  
   - Run AI risk analysis
4. View results in the **Vulnerability Results** page
5. Explore the **AI Dashboard** for risk scores and charts
6. Read remediation steps in the **Fix Panel**
7. Download a professional **PDF report**

---

### 4. API ENDPOINTS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | API health check |
| POST | `/api/scan/start` | Start a new scan |
| GET | `/api/scan/status/:id` | Poll scan progress |
| GET | `/api/scan/results/:id` | Get completed results |
| GET | `/api/scan/report/:id` | Download PDF report |

**Example — Start a scan:**
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

### 5. VULNERABILITIES DETECTED

VaultScan detects 25+ vulnerability types:

| # | Vulnerability | OWASP |
|---|--------------|-------|
| 1 | SQL Injection | A03 |
| 2 | XSS (Reflected/DOM) | A03 |
| 3 | Command Injection | A03 |
| 4 | Directory Traversal | A01 |
| 5 | CSRF | A01 |
| 6 | Open Redirect | A01 |
| 7 | SSRF | A10 |
| 8 | CORS Misconfiguration | A05 |
| 9 | Clickjacking | A05 |
| 10 | Missing Security Headers | A05 |
| 11 | SSL/TLS Issues | A02 |
| 12 | JWT Misconfiguration | A07 |
| 13 | Insecure Deserialization | A08 |
| 14 | XXE Injection | A03 |
| 15 | IDOR | A01 |
| 16 | Broken Authentication | A07 |
| 17 | Sensitive File Exposure | A05 |
| 18 | Default Credentials | A07 |
| 19 | Information Disclosure | A09 |
| 20 | Server Version Disclosure | A05 |
| 21 | Insecure Session Cookies | A07 |
| 22 | Missing Rate Limiting | A07 |
| 23 | HTML Comment Disclosure | A02 |
| 24 | Path Traversal | A01 |
| 25 | Potential API Exposures | A05 |

---

### 6. AI MODULES

| Module | Description |
|--------|-------------|
| **Risk Prediction** | Calculates 0-100 risk score using CVSS + OWASP weighting |
| **Vulnerability Summary** | Natural language explanations of findings |
| **Fix Suggestion Engine** | Step-by-step remediation with code examples |
| **Threat Prioritization** | Ranks by severity × exploitability × CVSS |
| **Security Insights** | AI-generated recommendations for security posture |
| **Threat Heatmap** | Category-based risk visualization |

---

### 7. DESIGN SYSTEM

**Colors:**
- Cyber Red: `#FB3640`
- Deep Black: `#000000`
- Pure White: `#FFFFFF`

**Typography:**
- Display: Syne (800 weight)
- Monospace: Space Mono

**UI Components:**
- Glassmorphism panels (backdrop-filter blur)
- Cyber grid background
- Radar scan animation (Canvas API)
- Terminal-style log viewer
- Animated progress bars with glow
- Severity badge system

---

### 8. TROUBLESHOOTING

**"Could not connect to VaultScan API"**
→ Make sure the backend Flask server is running on port 5000

**"PDF generation failed"**
→ Install reportlab: `pip install reportlab`

**CORS errors in browser**
→ The backend already includes flask-cors. Check it's installed.

**Scan takes too long**
→ Some sites have slow responses. The scanner has 8s timeouts per request.

**"Module not found" in frontend**
→ Run `npm install` again in the frontend directory.

---

### 9. LEGAL DISCLAIMER

VaultScan is for **authorized security testing only**.  
Only scan systems you own or have **explicit written permission** to test.  
Unauthorized scanning may violate computer fraud laws in your jurisdiction.

---

*VaultScan — AI-Powered Security Intelligence Platform*
