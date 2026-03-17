import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

const API = '';

export default function ReportPage() {
  const { scanId } = useParams();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API}/api/scan/results/${scanId}`);
        const data = await res.json();
        setResults(data);
      } catch { } finally { setLoading(false); }
    };
    load();
  }, [scanId]);

  const downloadPDF = async () => {
    setDownloading(true);
    try {
      const res = await fetch(`${API}/api/scan/report/${scanId}`);
      if (!res.ok) throw new Error('PDF generation failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vaultscan_report_${scanId.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setDownloaded(true);
    } catch (e) {
      alert('PDF generation failed. Make sure the backend is running with reportlab installed.');
    } finally {
      setDownloading(false);
    }
  };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: '12px' }}>
      <div style={{ width: 20, height: 20, border: '2px solid var(--red)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  const ai = results?.ai_analysis || {};
  const vulns = results?.vulnerabilities || [];
  const summary = results?.summary || {};
  const exec = ai.executive_summary || {};
  const SEV_COLORS = { Critical: 'var(--red)', High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--green)', Info: 'var(--blue)' };
  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

  const topVulns = [...vulns].sort((a, b) => (SEV_ORDER[a.severity] || 5) - (SEV_ORDER[b.severity] || 5)).slice(0, 5);

  return (
    <div style={{ paddingTop: '80px', minHeight: '100vh', padding: '80px 24px 40px' }}>
      <div style={{ maxWidth: '900px', margin: '0 auto' }}>

        {/* Header */}
        <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '8px' }}>◆ SECURITY REPORT</div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '32px', fontWeight: 800 }}>Assessment Report</h1>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>{results?.url}</div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Link to={`/results/${scanId}`}><button style={{ padding: '10px 18px', background: 'transparent', border: '1px solid var(--border-bright)', borderRadius: '6px', color: 'var(--text-secondary)', fontFamily: 'var(--font-display)', fontSize: '13px', cursor: 'pointer' }}>← Results</button></Link>
            <Link to={`/ai/${scanId}`}><button style={{ padding: '10px 18px', background: 'transparent', border: '1px solid var(--border-bright)', borderRadius: '6px', color: 'var(--text-secondary)', fontFamily: 'var(--font-display)', fontSize: '13px', cursor: 'pointer' }}>AI Dashboard</button></Link>
          </div>
        </div>

        {/* PDF Download Hero */}
        <div className="glass" style={{
          padding: '40px',
          marginBottom: '24px',
          textAlign: 'center',
          background: 'linear-gradient(135deg, rgba(251,54,64,0.06), rgba(0,0,0,0.4))',
          borderColor: 'rgba(251,54,64,0.25)',
        }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>📄</div>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '24px', fontWeight: 800, marginBottom: '8px' }}>
            Security Assessment Report
          </h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '28px', maxWidth: '460px', margin: '0 auto 28px', lineHeight: 1.6, fontSize: '14px' }}>
            Professional PDF report with executive summary, all vulnerability findings, CVSS scores, and AI remediation guidance.
          </p>
          <button
            onClick={downloadPDF}
            disabled={downloading}
            style={{
              padding: '16px 48px',
              background: downloaded ? 'rgba(0,255,159,0.15)' : 'var(--red)',
              border: downloaded ? '1px solid var(--green)' : 'none',
              borderRadius: '8px',
              color: downloaded ? 'var(--green)' : 'white',
              fontSize: '16px',
              fontWeight: 700,
              letterSpacing: '0.1em',
              fontFamily: 'var(--font-display)',
              cursor: downloading ? 'wait' : 'pointer',
              transition: 'all 0.3s',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              margin: '0 auto',
              boxShadow: downloaded ? '0 0 20px rgba(0,255,159,0.2)' : '0 0 30px var(--red-glow)',
            }}
          >
            {downloading ? (
              <>
                <div style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                GENERATING PDF...
              </>
            ) : downloaded ? (
              <>✓ DOWNLOADED</>
            ) : (
              <>⬇ DOWNLOAD PDF REPORT</>
            )}
          </button>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          <div style={{ marginTop: '14px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
            Requires backend running with reportlab installed
          </div>
        </div>

        {/* Report Preview */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
          {/* Score */}
          <div className="glass" style={{ padding: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>SECURITY SCORE</div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: '16px' }}>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '64px',
                fontWeight: 800,
                color: (exec.risk_score || 0) >= 60 ? 'var(--red)' : 'var(--yellow)',
                lineHeight: 1,
              }}>{exec.grade || 'N/A'}</div>
              <div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '22px', fontWeight: 700 }}>{Math.round(exec.risk_score || 0)}<span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>/100</span></div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: (exec.risk_score || 0) >= 60 ? 'var(--red)' : 'var(--yellow)' }}>{exec.risk_level || 'N/A'}</div>
              </div>
            </div>
          </div>

          {/* Summary stats */}
          <div className="glass" style={{ padding: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>FINDINGS SUMMARY</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              {[
                { label: 'Critical', v: summary.critical || 0 },
                { label: 'High', v: summary.high || 0 },
                { label: 'Medium', v: summary.medium || 0 },
                { label: 'Low', v: summary.low || 0 },
              ].map(s => (
                <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: SEV_COLORS[s.label] }}>{s.label}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700, color: SEV_COLORS[s.label] }}>{s.v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Exec Narrative */}
        {exec.narrative && (
          <div className="glass" style={{ padding: '24px', marginBottom: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '12px' }}>EXECUTIVE NARRATIVE</div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7, fontSize: '14px' }}>{exec.narrative}</p>
          </div>
        )}

        {/* Top findings */}
        <div className="glass" style={{ padding: '24px', marginBottom: '24px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>TOP CRITICAL FINDINGS</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {topVulns.map(v => (
              <div key={v.id} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 16px',
                background: 'rgba(0,0,0,0.3)',
                borderRadius: '6px',
                borderLeft: `3px solid ${SEV_COLORS[v.severity] || 'white'}`,
                gap: '12px',
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '2px' }}>{v.name}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{v.owasp_category}</div>
                </div>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: SEV_COLORS[v.severity] }}>CVSS {v.cvss}</span>
                  <span className={`badge badge-${v.severity.toLowerCase()}`}>{v.severity}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Report includes */}
        <div className="glass" style={{ padding: '24px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>REPORT CONTENTS</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
            {[
              { icon: '📋', label: 'Executive Summary' },
              { icon: '🎯', label: 'Risk Score & Grade' },
              { icon: '📊', label: 'Vulnerability Table' },
              { icon: '🔍', label: 'Detailed Findings' },
              { icon: '🛠️', label: 'Remediation Steps' },
              { icon: '🧠', label: 'AI Security Insights' },
              { icon: '📈', label: 'Severity Distribution' },
              { icon: '🔐', label: 'OWASP Mapping' },
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 14px', background: 'rgba(251,54,64,0.04)', border: '1px solid var(--border)', borderRadius: '6px' }}>
                <span style={{ fontSize: '16px' }}>{item.icon}</span>
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{item.label}</span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
