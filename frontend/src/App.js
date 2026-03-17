import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import ScanDashboard from './pages/ScanDashboard';
import ResultsPage from './pages/ResultsPage';
import AIDashboard from './pages/AIDashboard';
import FixPanel from './pages/FixPanel';
import ReportPage from './pages/ReportPage';
import Navbar from './components/Navbar';

function App() {
  return (
    <Router>
      <div style={{ position: 'relative', minHeight: '100vh' }}>
        <div className="cyber-grid" />
        <Navbar />
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/scan" element={<ScanDashboard />} />
          <Route path="/results/:scanId" element={<ResultsPage />} />
          <Route path="/ai/:scanId" element={<AIDashboard />} />
          <Route path="/fixes/:scanId" element={<FixPanel />} />
          <Route path="/report/:scanId" element={<ReportPage />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
