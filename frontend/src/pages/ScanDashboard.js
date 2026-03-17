import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const API = "https://vaultscan-backend.onrender.com";

const SCAN_STAGES = [
  { label: 'Initializing Engine', icon: '⚙️', pct: 5 },
  { label: 'Crawling Website', icon: '🕷️', pct: 15 },
  { label: 'Security Headers', icon: '🔒', pct: 20 },
  { label: 'SSL/TLS Analysis', icon: '🔐', pct: 25 },
  { label: 'SQL Injection Tests', icon: '💉', pct: 35 },
  { label: 'XSS Detection', icon: '⚡', pct: 40 },
  { label: 'Command Injection', icon: '💻', pct: 45 },
  { label: 'Path Traversal', icon: '📁', pct: 50 },
  { label: 'CSRF Analysis', icon: '🔄', pct: 55 },
  { label: 'CORS Testing', icon: '🌐', pct: 60 },
  { label: 'SSRF Detection', icon: '🎯', pct: 70 },
  { label: 'JWT Analysis', icon: '🔑', pct: 78 },
  { label: 'Auth Testing', icon: '👤', pct: 85 },
  { label: 'AI Risk Analysis', icon: '🧠', pct: 92 },
  { label: 'Generating Report', icon: '📊', pct: 98 },
];

export default function ScanDashboard() {
  const navigate = useNavigate();
  const location = useLocation();
  const [url, setUrl] = useState(location.state?.url || '');
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState('idle');
  const [vulnCount, setVulnCount] = useState(0);
  const [currentStage, setCurrentStage] = useState(0);
  const logsRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const startScan = async () => {
    if (!url.trim()) return;
    setScanning(true);
    setProgress(0);
    setLogs([]);
    setVulnCount(0);
    setCurrentStage(0);
    setStatus('scanning');

    try {
      const res = await fetch(`${API}/api/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await res.json();
      if (data.scan_id) {
        setScanId(data.scan_id);
        pollRef.current = setInterval(() => poll(data.scan_id), 1200);
      }
    } catch (err) {
      setLogs(l => [...l, `[ERROR] Could not connect to VaultScan API. Is the backend running on port 5000?`]);
      setScanning(false);
      setStatus('error');
    }
  };

  const poll = async (id) => {
    try {
      const res = await fetch(`${API}/api/scan/status/${id}`);
      const data = await res.json();
      setProgress(data.progress || 0);
      setLogs(data.logs || []);
      setVulnCount(data.vulnerability_count || 0);
      const stage = SCAN_STAGES.findIndex(s => s.pct > (data.progress || 0));
      setCurrentStage(Math.max(0, stage - 1));

      if (data.status === 'complete') {
        clearInterval(pollRef.current);
        setStatus('complete');
        setScanning(false);
        setTimeout(() => navigate(`/results/${id}`), 1500);
      } else if (data.status === 'error') {
        clearInterval(pollRef.current);
        setStatus('error');
        setScanning(false);
      }
    } catch { }
  };

  const stage = SCAN_STAGES[Math.min(currentStage, SCAN_STAGES.length - 1)];

  return (
    <div style={{ paddingTop: '70px', minHeight: '100vh', padding: '80px 24px 40px' }}>
      <div style={{ maxWidth: '900px', margin: '0 auto' }}>

        {/* Header */}
        <div style={{ marginBottom: '40px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '8px' }}>
            ◆ SECURITY SCANNER
          </div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '36px', fontWeight: 800 }}>
            Vulnerability Scanner
          </h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>
            AI-powered OWASP vulnerability detection and risk analysis
          </p>
        </div>

        {/* URL Input Card */}
        <div className="glass" style={{ padding: '28px', marginBottom: '24px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '12px' }}>
            TARGET URL
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: '240px', position: 'relative' }}>
              <span style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>$</span>
              <input
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !scanning && startScan()}
                placeholder="https://target.example.com"
                disabled={scanning}
                style={{
                  width: '100%',
                  background: scanning ? 'rgba(8,8,8,0.8)' : 'rgba(8,8,8,0.9)',
                  border: '1px solid var(--border-bright)',
                  borderRadius: '8px',
                  padding: '13px 14px 13px 32px',
                  color: 'var(--text-primary)',
                  fontSize: '14px',
                  fontFamily: 'var(--font-mono)',
                  opacity: scanning ? 0.6 : 1,
                }}
              />
            </div>
            <button
              onClick={scanning ? undefined : startScan}
              disabled={scanning}
              style={{
                padding: '13px 28px',
                background: scanning ? 'rgba(251,54,64,0.3)' : 'var(--red)',
                border: 'none',
                borderRadius: '8px',
                color: 'white',
                fontWeight: 700,
                fontSize: '13px',
                letterSpacing: '0.1em',
                fontFamily: 'var(--font-display)',
                cursor: scanning ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', gap: '8px',
                transition: 'all 0.2s',
              }}
            >
              {scanning ? (
                <>
                  <span style={{ display: 'inline-block', width: '12px', height: '12px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                  SCANNING...
                </>
              ) : '⚡ START SCAN'}
            </button>
          </div>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>

        {/* Progress Section */}
        {scanning && (
          <div className="glass" style={{ padding: '28px', marginBottom: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '20px' }}>{stage.icon}</span>
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--red)' }}>SCANNING</div>
                  <div style={{ fontSize: '14px', fontWeight: 600 }}>{stage.label}</div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '24px', fontWeight: 700, color: 'var(--red)' }}>{progress}%</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{vulnCount} vulns found</div>
              </div>
            </div>
            {/* Progress bar */}
            <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden', marginBottom: '20px' }}>
              <div style={{
                height: '100%',
                width: `${progress}%`,
                background: 'linear-gradient(90deg, var(--red), #ff6b6b)',
                borderRadius: '3px',
                transition: 'width 0.8s ease',
                boxShadow: '0 0 10px var(--red-glow)',
              }} />
            </div>
            {/* Stage indicators */}
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {SCAN_STAGES.map((s, i) => (
                <div key={i} style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '10px',
                  padding: '3px 8px',
                  borderRadius: '3px',
                  background: i < currentStage ? 'rgba(251,54,64,0.15)' : i === currentStage ? 'rgba(251,54,64,0.25)' : 'rgba(255,255,255,0.03)',
                  color: i < currentStage ? 'var(--red)' : i === currentStage ? 'white' : 'var(--text-muted)',
                  border: i === currentStage ? '1px solid var(--red)' : '1px solid transparent',
                  transition: 'all 0.3s',
                }}>
                  {i < currentStage ? '✓' : i === currentStage ? '▶' : '○'} {s.label}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Status Complete */}
        {status === 'complete' && (
          <div className="glass" style={{ padding: '20px', marginBottom: '24px', borderColor: 'rgba(0,255,159,0.3)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', color: 'var(--green)' }}>
              <span style={{ fontSize: '20px' }}>✓</span>
              <div>
                <div style={{ fontWeight: 700 }}>Scan Complete</div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Redirecting to results...</div>
              </div>
            </div>
          </div>
        )}

        {/* Terminal Logs */}
        <div className="glass" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <div style={{ display: 'flex', gap: '6px' }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#FF5F57' }} />
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#FFBD2E' }} />
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#28CA41' }} />
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
              VAULTSCAN TERMINAL
            </span>
            {scanning && (
              <div style={{ display: 'flex', gap: '4px', marginLeft: 'auto' }}>
                {[0, 1, 2].map(i => (
                  <div key={i} style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: 'var(--red)',
                    animation: `loadingDot 1.4s ease-in-out ${i * 0.2}s infinite`,
                  }} />
                ))}
              </div>
            )}
          </div>
          <div
            ref={logsRef}
            style={{
              minHeight: '200px',
              maxHeight: '320px',
              overflowY: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              lineHeight: '1.8',
              color: 'var(--text-secondary)',
            }}
          >
            {logs.length === 0 ? (
              <div style={{ color: 'var(--text-muted)' }}>
                <span style={{ color: 'var(--red)' }}>vault@scan:~$</span>{' '}
                {scanning ? 'Initializing scan...' : 'Awaiting target URL...'}
                <span style={{ animation: 'blink 1s step-end infinite', color: 'var(--red)' }}>_</span>
              </div>
            ) : (
              logs.map((log, i) => {
                let col = 'var(--text-secondary)';
                if (log.includes('[ERROR]')) col = 'var(--red)';
                else if (log.includes('[WARN]')) col = 'var(--yellow)';
                else if (log.includes('[AI]')) col = 'var(--blue)';
                else if (log.includes('[DONE]') || log.includes('[SYSTEM]')) col = 'var(--green)';
                else if (log.includes('[INIT]') || log.includes('[TARGET]')) col = 'var(--red)';
                return (
                  <div key={i} style={{ color: col, animation: i === logs.length - 1 ? 'fadeIn 0.3s ease' : 'none' }}>
                    {log}
                  </div>
                );
              })
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
