import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';

const NavLink = ({ to, children }) => {
  const location = useLocation();
  const active = location.pathname === to;
  return (
    <Link to={to} style={{
      color: active ? 'var(--red)' : 'var(--text-secondary)',
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      letterSpacing: '0.1em',
      textTransform: 'uppercase',
      padding: '6px 14px',
      borderRadius: '4px',
      border: active ? '1px solid var(--border-bright)' : '1px solid transparent',
      background: active ? 'rgba(251,54,64,0.08)' : 'transparent',
      transition: 'all 0.2s ease',
      whiteSpace: 'nowrap',
    }}>
      {children}
    </Link>
  );
};

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const location = useLocation();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  if (location.pathname === '/') return null;

  return (
    <nav style={{
      position: 'fixed',
      top: 0, left: 0, right: 0,
      zIndex: 1000,
      background: scrolled ? 'rgba(8,8,8,0.95)' : 'rgba(8,8,8,0.7)',
      backdropFilter: 'blur(20px)',
      borderBottom: '1px solid var(--border)',
      padding: '12px 32px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      transition: 'background 0.3s ease',
    }}>
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{
          width: 28, height: 28,
          background: 'var(--red)',
          borderRadius: '6px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '14px', fontWeight: 800,
          fontFamily: 'var(--font-display)',
          boxShadow: '0 0 12px var(--red-glow)',
        }}>V</div>
        <span style={{
          fontFamily: 'var(--font-display)',
          fontWeight: 800,
          fontSize: '16px',
          letterSpacing: '0.15em',
          color: 'white',
        }}>VAULTSCAN</span>
      </Link>
      <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
        <NavLink to="/scan">Scanner</NavLink>
        <div style={{ width: '1px', height: '16px', background: 'var(--border-bright)', margin: '0 4px' }} />
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          color: 'var(--text-muted)',
        }}>AI-POWERED</span>
      </div>
    </nav>
  );
}
