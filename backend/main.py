from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import uuid
import threading
import time
import json
import os
from scanner import VulnerabilityScanner
from ai_models import AIAnalyzer
from report import ReportGenerator

app = Flask(__name__)
CORS(app)

# In-memory sessions + file persistence
scan_sessions = {}
RESULTS_DIR = "scan_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── File Persistence Helpers ───────────────────────────────────────────────

def save_scan(scan_id, data):
    try:
        with open(f"{RESULTS_DIR}/{scan_id}.json", "w") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"[WARN] Could not save scan {scan_id}: {e}")

def load_scan(scan_id):
    path = f"{RESULTS_DIR}/{scan_id}.json"
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load scan {scan_id}: {e}")
    return None

def get_session(scan_id):
    # Check memory first
    if scan_id in scan_sessions:
        return scan_sessions[scan_id]
    # Fall back to file
    data = load_scan(scan_id)
    if data:
        scan_sessions[scan_id] = data
        return data
    return None

# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "online", "message": "VaultScan API is running"})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    target_url = data.get('url', '').strip()

    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    scan_id = str(uuid.uuid4())
    scan_sessions[scan_id] = {
        "id": scan_id,
        "url": target_url,
        "status": "initializing",
        "progress": 0,
        "logs": [],
        "vulnerabilities": [],
        "ai_analysis": None,
        "started_at": time.time()
    }

    # Save initial state to file immediately
    save_scan(scan_id, scan_sessions[scan_id])

    thread = threading.Thread(target=run_scan, args=(scan_id, target_url))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "started"})

def run_scan(scan_id, target_url):
    session = scan_sessions[scan_id]
    try:
        scanner = VulnerabilityScanner(scan_id, session)
        vulnerabilities = scanner.run_full_scan(target_url)

        session['vulnerabilities'] = vulnerabilities
        session['progress'] = 90
        session['status'] = 'analyzing'
        session['logs'].append("[AI] Running AI threat analysis...")
        save_scan(scan_id, session)

        analyzer = AIAnalyzer()
        session['ai_analysis'] = analyzer.analyze(vulnerabilities, target_url)
        session['progress'] = 100
        session['status'] = 'complete'
        session['logs'].append("[SYSTEM] Scan complete. Report ready.")

        # Save final completed results to file
        save_scan(scan_id, session)

    except Exception as e:
        session['status'] = 'error'
        session['logs'].append(f"[ERROR] Scan failed: {str(e)}")
        save_scan(scan_id, session)

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    session = get_session(scan_id)
    if not session:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "id": session['id'],
        "url": session['url'],
        "status": session['status'],
        "progress": session['progress'],
        "logs": session['logs'][-20:],
        "vulnerability_count": len(session['vulnerabilities'])
    })

@app.route('/api/scan/results/<scan_id>', methods=['GET'])
def scan_results(scan_id):
    session = get_session(scan_id)
    if not session:
        return jsonify({"error": "Scan not found"}), 404
    if session['status'] != 'complete':
        return jsonify({"error": "Scan not complete yet"}), 400
    return jsonify({
        "scan_id": scan_id,
        "url": session['url'],
        "vulnerabilities": session['vulnerabilities'],
        "ai_analysis": session['ai_analysis'],
        "summary": {
            "total": len(session['vulnerabilities']),
            "critical": sum(1 for v in session['vulnerabilities'] if v['severity'] == 'Critical'),
            "high": sum(1 for v in session['vulnerabilities'] if v['severity'] == 'High'),
            "medium": sum(1 for v in session['vulnerabilities'] if v['severity'] == 'Medium'),
            "low": sum(1 for v in session['vulnerabilities'] if v['severity'] == 'Low'),
            "info": sum(1 for v in session['vulnerabilities'] if v['severity'] == 'Info'),
        }
    })

@app.route('/api/scan/report/<scan_id>', methods=['GET'])
def download_report(scan_id):
    session = get_session(scan_id)
    if not session:
        return jsonify({"error": "Scan not found"}), 404
    if session['status'] != 'complete':
        return jsonify({"error": "Scan not complete"}), 400

    generator = ReportGenerator()
    pdf_path = generator.generate(session)
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"vaultscan_report_{scan_id[:8]}.pdf"
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)