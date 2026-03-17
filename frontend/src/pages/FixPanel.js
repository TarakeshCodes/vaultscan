import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

const API = "https://vaultscan-backend.onrender.com";

function CodeBlock({ code }) {
  return (
    <pre style={{
      background: '#0A0A0A',
      border: '1px solid rgba(251,54,64,0.15)',
      borderRadius: '6px',
      padding: '16px',
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      color: '#e0e0e0',
      overflowX: 'auto',
      lineHeight: 1.6,
      marginTop: '8px',
    }}>
      {code.split('\n').map((line, i) => {
        let color = '#e0e0e0';
        if (line.startsWith('# ✅') || line.startsWith('// ✅')) color = '#00FF9F';
        else if (line.startsWith('# ❌') || line.startsWith('// ❌')) color = '#FB3640';
        else if (line.startsWith('#') || line.startsWith('//')) color = '#888';
        else if (line.includes('SELECT') || line.includes('INSERT') || line.includes('DELETE')) color = '#00D4FF';
        return <span key={i} style={{ color, display: 'block' }}>{line}</span>;
      })}
    </pre>
  );
}

function FixCard({ fix, vuln }) {
  const [open, setOpen] = useState(false);
  const sevColors = {
    Critical: 'var(--red)',
    High: 'var(--orange)',
    Medium: 'var(--yellow)',
    Low: 'var(--green)',
    Info: 'var(--blue)',
  };
  const col = sevColors[fix.severity] || 'white';

  return (
    <div className="glass" style={{
      overflow: 'hidden',
      borderLeft: `3px solid ${col}`,
      marginBottom: '12px',
      transition: 'all 0.2s',
    }}>
      {/* Header */}
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          padding: '18px 24px',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '12px',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
              <span style={{ fontSize: '15px', fontWeight: 700 }}>{fix.vuln_name}</span>
              <span className={`badge badge-${fix.severity.toLowerCase()}`}>{fix.severity}</span>
              {fix.priority === 'Immediate' && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--red)', background: 'rgba(251,54,64,0.1)', padding: '2px 8px', borderRadius: '3px', border: '1px solid rgba(251,54,64,0.3)' }}>IMMEDIATE</span>
              )}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
              Effort: {fix.estimated_effort}
            </div>
          </div>
        </div>
        <span style={{ color: 'var(--text-muted)', fontSize: '18px', transition: 'transform 0.2s', transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}>▾</span>
      </div>

      {/* Content */}
      {open && (
        <div style={{ padding: '0 24px 24px', animation: 'fadeIn 0.2s ease', borderTop: '1px solid var(--border)' }}>
          <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            {/* Steps */}
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: col, letterSpacing: '0.1em', marginBottom: '12px' }}>
                REMEDIATION STEPS
              </div>
              <ol style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {fix.steps?.map((step, i) => (
                  <li key={i} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <span style={{
                      flexShrink: 0,
                      width: '22px', height: '22px',
                      background: col,
                      borderRadius: '50%',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '11px',
                      fontWeight: 700,
                      color: 'black',
                    }}>{i + 1}</span>
                    <span style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, paddingTop: '2px' }}>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
            {/* Code example */}
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: col, letterSpacing: '0.1em', marginBottom: '12px' }}>
                SECURE CODE EXAMPLE
              </div>
              {fix.code_example && <CodeBlock code={fix.code_example} />}
              {fix.references && (
                <div style={{ marginTop: '14px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '8px' }}>REFERENCES</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {fix.references.map((ref, i) => (
                      <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--blue)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ color: 'var(--text-muted)' }}>→</span> {ref}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Vuln details */}
          {vuln && (
            <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Endpoint: </span>
              <span style={{ color: 'var(--blue)' }}>{vuln.endpoint}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function FixPanel() {
  const { scanId } = useParams();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState('All');

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

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: '12px' }}>
      <div style={{ width: 20, height: 20, border: '2px solid var(--red)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  const fixes = results?.ai_analysis?.fix_suggestions || {};
  const vulns = results?.vulnerabilities || [];
  const vulnMap = Object.fromEntries(vulns.map(v => [v.id, v]));
  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

  const allFixes = Object.values(fixes)
    .filter(f => filterSev === 'All' || f.severity === filterSev)
    .sort((a, b) => (SEV_ORDER[a.severity] || 5) - (SEV_ORDER[b.severity] || 5));

  const criticalCount = Object.values(fixes).filter(f => f.severity === 'Critical').length;
  const immediateCount = Object.values(fixes).filter(f => f.priority === 'Immediate').length;

  return (
    <div style={{ paddingTop: '80px', minHeight: '100vh', padding: '80px 24px 40px' }}>
      <div style={{ maxWidth: '1000px', margin: '0 auto' }}>

        <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '8px' }}>◆ AI REMEDIATION</div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '32px', fontWeight: 800 }}>Fix Suggestion Panel</h1>
            <p style={{ color: 'var(--text-secondary)', marginTop: '6px', fontSize: '14px' }}>AI-generated step-by-step remediation for all vulnerabilities</p>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Link to={`/results/${scanId}`}><button style={{ padding: '10px 18px', background: 'transparent', border: '1px solid var(--border-bright)', borderRadius: '6px', color: 'var(--text-secondary)', fontFamily: 'var(--font-display)', fontSize: '13px', cursor: 'pointer' }}>← Results</button></Link>
            <Link to={`/report/${scanId}`}><button style={{ padding: '10px 18px', background: 'var(--red)', border: 'none', borderRadius: '6px', color: 'white', fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '13px', cursor: 'pointer' }}>📄 Report</button></Link>
          </div>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '24px' }}>
          {[
            { label: 'TOTAL FIXES', val: Object.keys(fixes).length, color: 'white' },
            { label: 'IMMEDIATE', val: immediateCount, color: 'var(--red)' },
            { label: 'CRITICAL', val: criticalCount, color: 'var(--red)' },
          ].map(s => (
            <div key={s.label} className="glass" style={{ padding: '16px', textAlign: 'center' }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '28px', fontWeight: 800, color: s.color }}>{s.val}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginTop: '4px' }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: '6px', marginBottom: '20px', flexWrap: 'wrap' }}>
          {['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(f => (
            <button key={f} onClick={() => setFilterSev(f)} style={{
              padding: '6px 16px',
              background: filterSev === f ? 'var(--red)' : 'transparent',
              border: `1px solid ${filterSev === f ? 'var(--red)' : 'var(--border)'}`,
              borderRadius: '4px',
              color: filterSev === f ? 'white' : 'var(--text-secondary)',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}>{f}</button>
          ))}
        </div>

        {allFixes.length === 0 ? (
          <div className="glass" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            No fixes for selected filter.
          </div>
        ) : (
          allFixes.map(fix => (
            <FixCard key={fix.vuln_id} fix={fix} vuln={vulnMap[fix.vuln_id]} />
          ))
        )}
      </div>
    </div>
  );
}
