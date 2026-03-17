import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';

const API = process.env.REACT_APP_API_URL || "http://localhost:5000";

function SevBadge({ sev }) {
  const map = {
    Critical: 'badge badge-critical',
    High: 'badge badge-high',
    Medium: 'badge badge-medium',
    Low: 'badge badge-low',
    Info: 'badge badge-info',
  };
  return <span className={map[sev] || 'badge'}>{sev}</span>;
}

export default function ResultsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState(null);
  const [sortBy, setSortBy] = useState('severity');

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API}/api/scan/results/${scanId}`);
        if (!res.ok) throw new Error('Results not available');
        const data = await res.json();
        setResults(data);
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [scanId]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: '12px' }}>
      <div style={{ width: 20, height: 20, border: '2px solid var(--red)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>Loading results...</span>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  if (error) return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: '16px' }}>
      <div style={{ color: 'var(--red)', fontSize: '48px' }}>⚠</div>
      <p style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{error}</p>
      <button onClick={() => navigate('/scan')} style={{ padding: '10px 24px', background: 'var(--red)', border: 'none', borderRadius: '6px', color: 'white', cursor: 'pointer' }}>
        New Scan
      </button>
    </div>
  );

  const { vulnerabilities = [], summary = {}, url } = results;
  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

  const filtered = vulnerabilities
    .filter(v => filter === 'All' || v.severity === filter)
    .filter(v => !search || v.name.toLowerCase().includes(search.toLowerCase()) || v.owasp_category?.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      if (sortBy === 'severity') return (SEV_ORDER[a.severity] || 5) - (SEV_ORDER[b.severity] || 5);
      if (sortBy === 'cvss') return (b.cvss || 0) - (a.cvss || 0);
      return a.name.localeCompare(b.name);
    });

  return (
    <div style={{ paddingTop: '80px', minHeight: '100vh', padding: '80px 24px 40px' }}>
      <div style={{ maxWidth: '1100px', margin: '0 auto' }}>

        {/* Header */}
        <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '8px' }}>◆ SCAN RESULTS</div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '32px', fontWeight: 800, marginBottom: '6px' }}>Vulnerability Report</h1>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{url}</div>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <Link to={`/ai/${scanId}`}>
              <button style={{ padding: '10px 20px', background: 'rgba(251,54,64,0.1)', border: '1px solid var(--border-bright)', borderRadius: '6px', color: 'var(--red)', fontFamily: 'var(--font-display)', fontWeight: 600, fontSize: '13px', cursor: 'pointer', transition: 'all 0.2s' }}>
                🧠 AI Dashboard
              </button>
            </Link>
            <Link to={`/fixes/${scanId}`}>
              <button style={{ padding: '10px 20px', background: 'rgba(251,54,64,0.1)', border: '1px solid var(--border-bright)', borderRadius: '6px', color: 'var(--red)', fontFamily: 'var(--font-display)', fontWeight: 600, fontSize: '13px', cursor: 'pointer', transition: 'all 0.2s' }}>
                🛠️ Fix Panel
              </button>
            </Link>
            <Link to={`/report/${scanId}`}>
              <button style={{ padding: '10px 20px', background: 'var(--red)', border: 'none', borderRadius: '6px', color: 'white', fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '13px', cursor: 'pointer' }}>
                📄 Report
              </button>
            </Link>
          </div>
        </div>

        {/* Summary Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '12px', marginBottom: '28px' }}>
          {[
            { label: 'Total', count: summary.total || 0, color: 'white' },
            { label: 'Critical', count: summary.critical || 0, color: 'var(--red)' },
            { label: 'High', count: summary.high || 0, color: 'var(--orange)' },
            { label: 'Medium', count: summary.medium || 0, color: 'var(--yellow)' },
            { label: 'Low', count: summary.low || 0, color: 'var(--green)' },
            { label: 'Info', count: summary.info || 0, color: 'var(--blue)' },
          ].map(s => (
            <div key={s.label} className="glass" style={{
              padding: '16px', textAlign: 'center',
              borderColor: s.count > 0 && s.label !== 'Total' ? `${s.color}30` : 'var(--border)',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
              onClick={() => setFilter(s.label === 'Total' ? 'All' : s.label)}
            >
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '28px', fontWeight: 800, color: s.color, textShadow: s.label !== 'Total' && s.count > 0 ? `0 0 12px ${s.color}50` : 'none' }}>
                {s.count}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginTop: '4px' }}>
                {s.label.toUpperCase()}
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="glass" style={{ padding: '16px', marginBottom: '16px', display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{
                padding: '5px 14px',
                background: filter === f ? 'var(--red)' : 'transparent',
                border: `1px solid ${filter === f ? 'var(--red)' : 'var(--border)'}`,
                borderRadius: '4px',
                color: filter === f ? 'white' : 'var(--text-secondary)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}>{f}</button>
            ))}
          </div>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search vulnerabilities..."
            style={{
              marginLeft: 'auto',
              background: 'rgba(0,0,0,0.4)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              padding: '6px 12px',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              width: '200px',
            }}
          />
          <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={{
            background: 'rgba(0,0,0,0.4)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '6px 10px',
            color: 'var(--text-secondary)',
            fontSize: '12px',
            fontFamily: 'var(--font-mono)',
          }}>
            <option value="severity">Sort: Severity</option>
            <option value="cvss">Sort: CVSS</option>
            <option value="name">Sort: Name</option>
          </select>
        </div>

        {/* Vuln Count */}
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
          Showing {filtered.length} of {vulnerabilities.length} vulnerabilities
        </div>

        {/* Vulnerability Table */}
        {filtered.length === 0 ? (
          <div className="glass" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            No vulnerabilities match your filters.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {filtered.map(v => (
              <div key={v.id} className="glass" style={{
                padding: '0',
                overflow: 'hidden',
                transition: 'border-color 0.2s',
                borderLeft: `3px solid ${v.severity === 'Critical' ? 'var(--red)' : v.severity === 'High' ? 'var(--orange)' : v.severity === 'Medium' ? 'var(--yellow)' : v.severity === 'Low' ? 'var(--green)' : 'var(--blue)'}`,
              }}>
                {/* Row */}
                <div
                  onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                  style={{
                    padding: '14px 20px',
                    display: 'grid',
                    gridTemplateColumns: '70px 1fr 100px 70px 1fr',
                    gap: '12px',
                    alignItems: 'center',
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{v.id}</span>
                  <span style={{ fontSize: '14px', fontWeight: 600 }}>{v.name}</span>
                  <SevBadge sev={v.severity} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: v.severity === 'Critical' ? 'var(--red)' : 'var(--text-secondary)' }}>
                    {v.cvss}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {v.owasp_category?.split(' - ')[1] || v.owasp_category}
                  </span>
                </div>
                {/* Expanded */}
                {expanded === v.id && (
                  <div style={{
                    padding: '0 20px 20px',
                    borderTop: '1px solid var(--border)',
                    animation: 'fadeIn 0.2s ease',
                  }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '16px', flexWrap: 'wrap' }}>
                      <div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '6px' }}>DESCRIPTION</div>
                        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{v.description}</p>
                      </div>
                      <div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '6px' }}>ENDPOINT</div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--blue)', wordBreak: 'break-all', marginBottom: '12px' }}>{v.endpoint}</div>
                        {v.evidence && (
                          <>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '6px' }}>EVIDENCE</div>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--yellow)', background: 'rgba(255,184,0,0.06)', padding: '8px 12px', borderRadius: '4px', wordBreak: 'break-all' }}>
                              {v.evidence}
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                    <div style={{ marginTop: '16px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                      <Link to={`/fixes/${scanId}`}>
                        <button style={{ padding: '7px 16px', background: 'transparent', border: '1px solid var(--border-bright)', borderRadius: '5px', color: 'var(--red)', fontSize: '12px', fontFamily: 'var(--font-mono)', cursor: 'pointer' }}>
                          View Fix →
                        </button>
                      </Link>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ color: 'var(--text-muted)' }}>OWASP:</span>
                        <span style={{ color: 'var(--red)' }}>{v.owasp_category}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
