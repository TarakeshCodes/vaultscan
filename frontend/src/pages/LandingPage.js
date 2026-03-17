import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

const FEATURES = [
  { icon: '⚡', title: 'OWASP Top 10 Scanner', desc: 'Detects all major OWASP vulnerability classes including injection, XSS, CSRF, and more.' },
  { icon: '🧠', title: 'AI Risk Analysis', desc: 'Machine learning models calculate real-time risk scores and prioritize threats by exploitability.' },
  { icon: '🔍', title: 'Deep Crawl Engine', desc: 'Intelligent web crawler discovers all endpoints, forms, and attack surfaces automatically.' },
  { icon: '🛡️', title: 'Fix Suggestion AI', desc: 'AI generates step-by-step remediation guides with secure code examples for every vulnerability.' },
  { icon: '📊', title: 'Visual Dashboards', desc: 'Interactive heatmaps, risk meters, and vulnerability distribution charts for instant insights.' },
  { icon: '📄', title: 'PDF Report Export', desc: 'Professional executive security reports with findings, CVSS scores, and remediation plans.' },
];

const VULN_TYPES = [
  'SQL INJECTION', 'XSS', 'CSRF', 'SSRF', 'XXE', 'IDOR', 'PATH TRAVERSAL',
  'BROKEN AUTH', 'CORS', 'CLICKJACKING', 'OPEN REDIRECT', 'JWT FLAW',
  'CMD INJECTION', 'DESERIALIZATION', 'SENSITIVE EXPOSURE'
];

function RadarAnimation() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const size = 280;
    canvas.width = size;
    canvas.height = size;
    const cx = size / 2, cy = size / 2;
    let angle = 0;
    let dots = Array.from({ length: 8 }, () => ({
      r: Math.random() * 100 + 20,
      a: Math.random() * Math.PI * 2,
      age: Math.random() * 100,
      size: Math.random() * 3 + 1,
      severity: Math.random() > 0.7 ? 'critical' : Math.random() > 0.5 ? 'high' : 'medium'
    }));

    const draw = () => {
      ctx.clearRect(0, 0, size, size);
      // Rings
      [80, 100, 120, 140].forEach(r => {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(251,54,64,0.12)';
        ctx.lineWidth = 1;
        ctx.stroke();
      });
      // Cross hairs
      ctx.beginPath();
      ctx.moveTo(0, cy); ctx.lineTo(size, cy);
      ctx.moveTo(cx, 0); ctx.lineTo(cx, size);
      ctx.strokeStyle = 'rgba(251,54,64,0.08)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Sweep gradient
      const grad = ctx.createConicalGradient ? undefined : null;
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);
      const sweep = ctx.createLinearGradient(0, 0, 150, 0);
      sweep.addColorStop(0, 'rgba(251,54,64,0.5)');
      sweep.addColorStop(1, 'rgba(251,54,64,0)');
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, 145, -0.3, 0.3);
      ctx.closePath();
      ctx.fillStyle = sweep;
      ctx.fill();
      ctx.restore();

      // Dots
      dots.forEach(dot => {
        dot.age++;
        const dotAngle = dot.a;
        const sweepAngle = angle % (Math.PI * 2);
        let diff = ((dotAngle - sweepAngle) + Math.PI * 2) % (Math.PI * 2);
        if (diff < 0.4) dot.age = 0;
        const opacity = Math.max(0, 1 - dot.age / 80);
        if (opacity > 0) {
          const x = cx + Math.cos(dot.a) * dot.r;
          const y = cy + Math.sin(dot.a) * dot.r;
          const colors = { critical: '#FB3640', high: '#FF6B35', medium: '#FFB800' };
          const col = colors[dot.severity];
          ctx.beginPath();
          ctx.arc(x, y, dot.size + 2, 0, Math.PI * 2);
          ctx.fillStyle = col.replace(')', `,${opacity * 0.2})`).replace('rgb', 'rgba').replace('#FB3640', `rgba(251,54,64,${opacity * 0.15})`);
          ctx.fill();
          ctx.beginPath();
          ctx.arc(x, y, dot.size, 0, Math.PI * 2);
          ctx.fillStyle = `${col}${Math.floor(opacity * 255).toString(16).padStart(2, '0')}`;
          ctx.fill();
        }
      });

      // Center dot
      ctx.beginPath();
      ctx.arc(cx, cy, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#FB3640';
      ctx.fill();
      ctx.beginPath();
      ctx.arc(cx, cy, 8, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(251,54,64,0.2)';
      ctx.fill();

      angle += 0.025;
      requestAnimationFrame(draw);
    };
    const raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <div style={{
      position: 'relative',
      width: 280, height: 280,
      borderRadius: '50%',
      border: '1px solid rgba(251,54,64,0.3)',
      boxShadow: '0 0 60px rgba(251,54,64,0.15), inset 0 0 60px rgba(251,54,64,0.05)',
      overflow: 'hidden',
    }}>
      <canvas ref={canvasRef} style={{ display: 'block' }} />
    </div>
  );
}

function FloatingVulnTag({ label, style }) {
  return (
    <div style={{
      position: 'absolute',
      fontFamily: 'var(--font-mono)',
      fontSize: '10px',
      color: 'var(--red)',
      padding: '4px 10px',
      border: '1px solid rgba(251,54,64,0.3)',
      borderRadius: '4px',
      background: 'rgba(251,54,64,0.05)',
      backdropFilter: 'blur(8px)',
      whiteSpace: 'nowrap',
      animation: 'pulse 3s ease-in-out infinite',
      animationDelay: style.animationDelay || '0s',
      ...style,
    }}>
      {label}
    </div>
  );
}

export default function LandingPage() {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [typedText, setTypedText] = useState('');

  const heroText = 'SCAN. DETECT. SECURE.';
  useEffect(() => {
    let i = 0;
    const t = setInterval(() => {
      setTypedText(heroText.slice(0, i + 1));
      i++;
      if (i >= heroText.length) clearInterval(t);
    }, 60);
    return () => clearInterval(t);
  }, []);

  const handleScan = () => {
    const u = url.trim();
    if (u) {
      navigate('/scan', { state: { url: u } });
    } else {
      navigate('/scan');
    }
  };

  return (
    <div style={{ minHeight: '100vh', position: 'relative', overflow: 'hidden' }}>
      {/* Top accent */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0, height: '2px',
        background: 'linear-gradient(90deg, transparent, var(--red), transparent)',
        zIndex: 100,
      }} />

      {/* HERO */}
      <section style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '80px 24px 60px',
        position: 'relative',
      }}>
        {/* Top badge */}
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          letterSpacing: '0.2em',
          color: 'var(--red)',
          padding: '6px 18px',
          border: '1px solid var(--border-bright)',
          borderRadius: '20px',
          background: 'rgba(251,54,64,0.06)',
          marginBottom: '32px',
          animation: 'flicker 4s ease-in-out infinite',
        }}>
          ◆ AI-POWERED VULNERABILITY SCANNER ◆
        </div>

        {/* Logo */}
        <div style={{
          fontFamily: 'var(--font-display)',
          fontSize: 'clamp(52px, 10vw, 100px)',
          fontWeight: 800,
          letterSpacing: '0.1em',
          color: 'white',
          lineHeight: 1,
          marginBottom: '8px',
          textAlign: 'center',
        }}>
          VAULT<span style={{ color: 'var(--red)', textShadow: '0 0 30px var(--red-glow-strong)' }}>SCAN</span>
        </div>

        {/* Typed tagline */}
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'clamp(14px, 3vw, 20px)',
          color: 'var(--text-secondary)',
          letterSpacing: '0.25em',
          marginBottom: '20px',
          minHeight: '30px',
          textAlign: 'center',
        }}>
          {typedText}
          <span style={{ animation: 'blink 1s step-end infinite', color: 'var(--red)' }}>_</span>
        </div>

        <p style={{
          color: 'var(--text-muted)',
          fontSize: '15px',
          maxWidth: '480px',
          textAlign: 'center',
          lineHeight: 1.7,
          marginBottom: '48px',
        }}>
          Enterprise-grade AI security platform that detects OWASP vulnerabilities,
          generates risk scores, and provides remediation guidance.
        </p>

        {/* Radar + floating tags */}
        <div style={{ position: 'relative', marginBottom: '56px' }}>
          <RadarAnimation />
          <FloatingVulnTag label="SQL INJECTION" style={{ top: '-20px', left: '-80px', animationDelay: '0s' }} />
          <FloatingVulnTag label="XSS DETECTED" style={{ top: '30px', right: '-100px', animationDelay: '0.5s' }} />
          <FloatingVulnTag label="CSRF RISK" style={{ bottom: '20px', left: '-70px', animationDelay: '1s' }} />
          <FloatingVulnTag label="SSRF ALERT" style={{ bottom: '-20px', right: '-80px', animationDelay: '1.5s' }} />
          <FloatingVulnTag label="JWT FLAW" style={{ top: '130px', left: '-100px', animationDelay: '2s' }} />
        </div>

        {/* URL Input */}
        <div style={{
          display: 'flex',
          gap: '12px',
          width: '100%',
          maxWidth: '580px',
          flexWrap: 'wrap',
          justifyContent: 'center',
        }}>
          <div style={{
            flex: 1,
            minWidth: '260px',
            position: 'relative',
          }}>
            <span style={{
              position: 'absolute',
              left: '14px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--red)',
              fontFamily: 'var(--font-mono)',
              fontSize: '13px',
            }}>$</span>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
              placeholder="https://target.example.com"
              style={{
                width: '100%',
                background: 'rgba(17,17,17,0.9)',
                border: '1px solid var(--border-bright)',
                borderRadius: '8px',
                padding: '14px 14px 14px 32px',
                color: 'var(--text-primary)',
                fontSize: '14px',
                fontFamily: 'var(--font-mono)',
                transition: 'border-color 0.2s, box-shadow 0.2s',
              }}
              onFocus={e => { e.target.style.borderColor = 'var(--red)'; e.target.style.boxShadow = '0 0 16px var(--red-glow)'; }}
              onBlur={e => { e.target.style.borderColor = 'var(--border-bright)'; e.target.style.boxShadow = 'none'; }}
            />
          </div>
          <button
            onClick={handleScan}
            style={{
              padding: '14px 32px',
              background: 'var(--red)',
              border: 'none',
              borderRadius: '8px',
              color: 'white',
              fontSize: '14px',
              fontWeight: 700,
              letterSpacing: '0.1em',
              fontFamily: 'var(--font-display)',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
              boxShadow: '0 0 24px var(--red-glow)',
            }}
            onMouseEnter={e => { e.target.style.background = 'var(--red-dark)'; e.target.style.boxShadow = '0 0 40px var(--red-glow-strong)'; }}
            onMouseLeave={e => { e.target.style.background = 'var(--red)'; e.target.style.boxShadow = '0 0 24px var(--red-glow)'; }}
          >
            LAUNCH SCAN →
          </button>
        </div>

        <div style={{
          marginTop: '16px',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          color: 'var(--text-muted)',
          textAlign: 'center',
        }}>
          Only scan systems you own or have explicit permission to test.
        </div>

        {/* Scroll indicator */}
        <div style={{
          position: 'absolute',
          bottom: '32px',
          left: '50%',
          transform: 'translateX(-50%)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '8px',
          color: 'var(--text-muted)',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)',
        }}>
          <div style={{ width: '1px', height: '40px', background: 'linear-gradient(to bottom, transparent, var(--red))' }} />
          SCROLL
        </div>
      </section>

      {/* STATS BAR */}
      <section style={{
        borderTop: '1px solid var(--border)',
        borderBottom: '1px solid var(--border)',
        padding: '28px 40px',
        display: 'flex',
        justifyContent: 'center',
        gap: '60px',
        flexWrap: 'wrap',
        background: 'rgba(251,54,64,0.02)',
      }}>
        {[
          { num: '25+', label: 'VULN TYPES' },
          { num: 'OWASP', label: 'TOP 10 MAPPED' },
          { num: 'AI', label: 'RISK ENGINE' },
          { num: 'PDF', label: 'REPORT EXPORT' },
        ].map(s => (
          <div key={s.label} style={{ textAlign: 'center' }}>
            <div style={{
              fontFamily: 'var(--font-display)',
              fontSize: '28px',
              fontWeight: 800,
              color: 'var(--red)',
              textShadow: '0 0 16px var(--red-glow)',
            }}>{s.num}</div>
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              color: 'var(--text-muted)',
              letterSpacing: '0.15em',
              marginTop: '4px',
            }}>{s.label}</div>
          </div>
        ))}
      </section>

      {/* FEATURES */}
      <section style={{ padding: '80px 40px', maxWidth: '1100px', margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: '56px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '12px' }}>CAPABILITIES</div>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(28px, 5vw, 42px)', fontWeight: 800 }}>
            Security Intelligence Platform
          </h2>
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '20px',
        }}>
          {FEATURES.map((f, i) => (
            <div key={i} className="glass" style={{
              padding: '28px',
              transition: 'all 0.3s ease',
              cursor: 'default',
              animation: `fadeIn 0.5s ease forwards`,
              animationDelay: `${i * 0.1}s`,
              opacity: 0,
            }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'var(--border-bright)';
                e.currentTarget.style.boxShadow = '0 0 30px var(--red-glow)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <div style={{ fontSize: '28px', marginBottom: '12px' }}>{f.icon}</div>
              <h3 style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '15px', marginBottom: '8px', color: 'white' }}>{f.title}</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: 1.6 }}>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* VULN TYPES MARQUEE */}
      <section style={{
        borderTop: '1px solid var(--border)',
        padding: '20px 0',
        overflow: 'hidden',
        background: 'rgba(251,54,64,0.02)',
      }}>
        <div style={{
          display: 'flex',
          gap: '40px',
          animation: 'marqueeScroll 20s linear infinite',
          whiteSpace: 'nowrap',
        }}>
          {[...VULN_TYPES, ...VULN_TYPES].map((v, i) => (
            <span key={i} style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--text-muted)',
              letterSpacing: '0.15em',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
            }}>
              <span style={{ color: 'var(--red)' }}>◆</span> {v}
            </span>
          ))}
        </div>
        <style>{`
          @keyframes marqueeScroll {
            from { transform: translateX(0); }
            to { transform: translateX(-50%); }
          }
        `}</style>
      </section>

      {/* CTA */}
      <section style={{
        padding: '100px 40px',
        textAlign: 'center',
        background: 'linear-gradient(to bottom, transparent, rgba(251,54,64,0.04), transparent)',
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--red)', letterSpacing: '0.2em', marginBottom: '20px' }}>GET STARTED</div>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(28px, 5vw, 48px)', fontWeight: 800, marginBottom: '20px' }}>
          Start Your Security Scan Now
        </h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '480px', margin: '0 auto 36px', lineHeight: 1.7 }}>
          Identify vulnerabilities before attackers do. Get an AI-powered security assessment in minutes.
        </p>
        <button
          onClick={() => navigate('/scan')}
          style={{
            padding: '16px 48px',
            background: 'var(--red)',
            border: 'none',
            borderRadius: '8px',
            color: 'white',
            fontSize: '16px',
            fontWeight: 700,
            letterSpacing: '0.1em',
            fontFamily: 'var(--font-display)',
            boxShadow: '0 0 40px var(--red-glow)',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={e => { e.target.style.transform = 'scale(1.05)'; e.target.style.boxShadow = '0 0 60px var(--red-glow-strong)'; }}
          onMouseLeave={e => { e.target.style.transform = 'scale(1)'; e.target.style.boxShadow = '0 0 40px var(--red-glow)'; }}
        >
          LAUNCH FREE SCAN
        </button>
      </section>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid var(--border)',
        padding: '24px 40px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <span style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: '14px', letterSpacing: '0.1em' }}>
          VAULT<span style={{ color: 'var(--red)' }}>SCAN</span>
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
          AI-Powered Security Intelligence Platform
        </span>
      </footer>
    </div>
  );
}
