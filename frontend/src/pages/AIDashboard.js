import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis } from 'recharts';

const API = "https://vaultscan-backend.onrender.com";

const SEV_COLORS = {
  Critical: '#FB3640',
  High: '#FF6B35',
  Medium: '#FFB800',
  Low: '#00FF9F',
  Info: '#00D4FF',
};

function RiskMeter({ score }) {
  const angle = -135 + (score / 100) * 270;
  const color = score >= 80 ? '#FB3640' : score >= 60 ? '#FF6B35' : score >= 40 ? '#FFB800' : '#00FF9F';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width="200" height="120" viewBox="0 0 200 120">
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="16" strokeLinecap="round" />
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke={color} strokeWidth="16" strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 251.2} 251.2`} style={{ transition: 'all 1.5s ease', filter: `drop-shadow(0 0 8px ${color})` }} />
        <g transform={`translate(100, 100) rotate(${angle})`}>
          <line x1="0" y1="0" x2="70" y2="0" stroke={color} strokeWidth="2.5" strokeLinecap="round" />
          <circle cx="0" cy="0" r="5" fill={color} />
        </g>
        <circle cx="100" cy="100" r="8" fill="var(--bg-card2)" stroke={color} strokeWidth="2" />
        <text x="100" y="90" textAnchor="middle" fill="white" fontSize="22" fontWeight="800" fontFamily="Syne">{score}</text>
        <text x="100" y="105" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="9" fontFamily="Space Mono">/100</text>
      </svg>
      <div style={{
        fontFamily: 'var(--font-display)',
        fontSize: '18px',
        fontWeight: 800,
        color: color,
        textShadow: `0 0 16px ${color}50`,
        letterSpacing: '0.05em',
        marginTop: '-8px',
      }}>
        {score >= 80 ? 'CRITICAL RISK' : score >= 60 ? 'HIGH RISK' : score >= 40 ? 'MODERATE RISK' : 'LOW RISK'}
      </div>
    </div>
  );
}

function ThreatHeatmap({ data }) {
  if (!data || data.length === 0) return null;
  const maxScore = Math.max(...data.map(d => d.score));
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '8px' }}>
      {data.map((item, i) => {
        const intensity = item.score / maxScore;
        const sevColor = SEV_COLORS[item.max_severity] || '#888';
        return (
          <div key={i} style={{
            padding: '14px',
            borderRadius: '8px',
            background: `rgba(${item.max_severity === 'Critical' ? '251,54,64' : item.max_severity === 'High' ? '255,107,53' : '255,184,0'}, ${intensity * 0.18})`,
            border: `1px solid ${sevColor}30`,
            transition: 'all 0.2s',
          }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = `${sevColor}60`; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = `${sevColor}30`; }}
          >
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: sevColor, marginBottom: '6px' }}>{item.max_severity?.toUpperCase()}</div>
            <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '4px', lineHeight: 1.3 }}>{item.name}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{item.count} vulns</div>
            <div style={{ marginTop: '8px', height: '3px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px' }}>
              <div style={{ height: '100%', width: `${intensity * 100}%`, background: sevColor, borderRadius: '2px' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '6px', padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
        <div style={{ color: 'white', marginBottom: '4px' }}>{label || payload[0].name}</div>
        <div style={{ color: 'var(--red)' }}>{payload[0].value} {payload[0].name === 'Count' ? 'vulnerabilities' : ''}</div>
      </div>
    );
  }
  return null;
};

export default function AIDashboard() {
  const { scanId } = useParams();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API}/api/scan/results/${scanId}`);
        const data = await res.json();
        setResults(data);
      } catch (e) { } finally { setLoading(false); }
    };
    load();
  }, [scanId]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: '12px' }}>
      <div style={{ width: 20, height: 20, border: '2px solid var(--red)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>Loading AI analysis...</span>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  const ai = results?.ai_analysis || {};
  const summary = results?.summary || {};
  const sevDist = ai.severity_distribution || {};
  const pieData = Object.entries(sevDist).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  const barData = ai.prioritized_threats?.slice(0, 8).map(v => ({
    name: v.name.length > 20 ? v.name.slice(0, 18) + '...' : v.name,
    Score: Math.round(v.priority_score * 10) / 10,
  })) || [];
  const radarData = ai.threat_heatmap?.slice(0, 6).map(d => ({
    subject: d.name.length > 18 ? d.name.slice(0, 16) + '...' : d.name,
    value: Math.round(d.score),
  })) || [];

  const riskScore = ai.risk_score || 0;
  const grade = ai.scan_grade || 'N/A';

  return (
    <div style={{ paddingTop: '80px', minHeight: '100vh', padding: '80px 24px 40px' }}>
      <div style={{ maxWidth: '1100px', margin: '0 auto' }}>

        {/* Header */}
        <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '8px' }}>◆ AI ANALYSIS</div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '32px', fontWeight: 800 }}>AI Risk Dashboard</h1>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Link to={`/results/${scanId}`}><button style={{ padding: '10px 18px', background: 'transparent', border: '1px solid var(--border-bright)', borderRadius: '6px', color: 'var(--text-secondary)', fontFamily: 'var(--font-display)', fontSize: '13px', cursor: 'pointer' }}>← Results</button></Link>
            <Link to={`/fixes/${scanId}`}><button style={{ padding: '10px 18px', background: 'var(--red)', border: 'none', borderRadius: '6px', color: 'white', fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '13px', cursor: 'pointer' }}>Fix Panel →</button></Link>
          </div>
        </div>

        {/* Executive Summary */}
        {ai.executive_summary && (
          <div className="glass" style={{ padding: '24px', marginBottom: '24px', borderColor: 'rgba(251,54,64,0.2)' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.15em', marginBottom: '12px' }}>AI EXECUTIVE SUMMARY</div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7, fontSize: '14px' }}>{ai.executive_summary.narrative}</p>
          </div>
        )}

        {/* Top row: Risk meter + Grade + Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '24px' }}>
          <div className="glass" style={{ padding: '28px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>RISK SCORE</div>
            <RiskMeter score={Math.round(riskScore)} />
          </div>
          <div className="glass" style={{ padding: '28px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>SECURITY GRADE</div>
            <div style={{
              fontFamily: 'var(--font-display)',
              fontSize: '72px',
              fontWeight: 800,
              color: grade === 'F' ? 'var(--red)' : grade === 'D' ? 'var(--orange)' : grade === 'C' ? 'var(--yellow)' : 'var(--green)',
              textShadow: `0 0 40px ${grade === 'F' ? 'var(--red-glow-strong)' : grade === 'D' ? 'rgba(255,107,53,0.5)' : 'rgba(0,255,159,0.3)'}`,
              lineHeight: 1,
            }}>{grade}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px' }}>
              {grade === 'F' ? 'NEEDS IMMEDIATE ATTENTION' : grade === 'D' ? 'POOR SECURITY POSTURE' : grade === 'C' ? 'ACCEPTABLE, IMPROVE' : grade === 'B' || grade === 'B+' ? 'GOOD POSTURE' : 'EXCELLENT SECURITY'}
            </div>
          </div>
          <div className="glass" style={{ padding: '28px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>FINDINGS OVERVIEW</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { label: 'CRITICAL', count: summary.critical || sevDist.Critical || 0, color: 'var(--red)' },
                { label: 'HIGH', count: summary.high || sevDist.High || 0, color: 'var(--orange)' },
                { label: 'MEDIUM', count: summary.medium || sevDist.Medium || 0, color: 'var(--yellow)' },
                { label: 'LOW', count: summary.low || sevDist.Low || 0, color: 'var(--green)' },
              ].map(item => (
                <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: item.color, width: '60px' }}>{item.label}</span>
                  <div style={{ flex: 1, height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${Math.min((item.count / (summary.total || 1)) * 100, 100)}%`,
                      background: item.color,
                      borderRadius: '3px',
                      transition: 'width 1s ease',
                    }} />
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: item.color, width: '24px', textAlign: 'right' }}>{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '16px', marginBottom: '24px' }}>
          {/* Pie Chart */}
          <div className="glass" style={{ padding: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>SEVERITY DISTRIBUTION</div>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={SEV_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center' }}>
              {pieData.map((d, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-secondary)' }}>
                  <div style={{ width: 8, height: 8, borderRadius: '2px', background: SEV_COLORS[d.name] }} />
                  {d.name}: {d.value}
                </div>
              ))}
            </div>
          </div>

          {/* Threat Priority Bar */}
          <div className="glass" style={{ padding: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>AI THREAT PRIORITIZATION</div>
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={barData} layout="vertical" margin={{ left: 0, right: 20 }}>
                  <XAxis type="number" stroke="rgba(255,255,255,0.1)" tick={{ fontFamily: 'Space Mono', fontSize: 10, fill: 'rgba(255,255,255,0.4)' }} />
                  <YAxis type="category" dataKey="name" width={130} tick={{ fontFamily: 'Space Mono', fontSize: 9, fill: 'rgba(255,255,255,0.6)' }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="Score" fill="var(--red)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>No threat data</div>}
          </div>
        </div>

        {/* Threat Heatmap */}
        {ai.threat_heatmap && ai.threat_heatmap.length > 0 && (
          <div className="glass" style={{ padding: '24px', marginBottom: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>THREAT CATEGORY HEATMAP</div>
            <ThreatHeatmap data={ai.threat_heatmap} />
          </div>
        )}

        {/* AI Security Insights */}
        {ai.security_insights && ai.security_insights.length > 0 && (
          <div className="glass" style={{ padding: '24px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>AI SECURITY INSIGHTS</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
              {ai.security_insights.map((insight, i) => (
                <div key={i} style={{
                  padding: '16px',
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  animation: `fadeIn 0.4s ease ${i * 0.1}s forwards`,
                  opacity: 0,
                }}>
                  <div style={{ fontSize: '20px', marginBottom: '8px' }}>{insight.icon}</div>
                  <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '6px', color: 'white' }}>{insight.title}</div>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{insight.message}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
