import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Activity } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import ReportView from './pages/ReportView';
import History from './pages/History';

function App() {
  return (
    <Router>
      <div className="min-h-screen font-sans text-white">
        {/* SOC Navbar */}
        <nav className="p-4 bg-[#0a0a0a]/90 backdrop-blur-md border-b border-cyan-900/50 sticky top-0 z-50 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <div className="max-w-6xl mx-auto flex justify-between items-center">
                <Link to="/" className="text-2xl font-black tracking-widest text-white flex items-center gap-2">
                    <Activity className="text-cyan-400 w-6 h-6 animate-pulse" />
                    PHISH<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600">GUARD</span>
                </Link>
                <div className="flex items-center space-x-8 text-sm font-bold tracking-widest text-gray-400">
                    <Link to="/" className="hover:text-cyan-400 transition-colors">SMART SCANNER</Link>
                    <Link to="/history" className="hover:text-cyan-400 transition-colors">THREAT LOGS</Link>
                    {/* Live System Status */}
                    <div className="flex items-center gap-2 px-3 py-1 bg-green-950/30 border border-green-900/50 rounded-full">
                        <span className="w-2 h-2 rounded-full bg-green-500 animate-ping"></span>
                        <span className="text-green-500 text-xs">SYSTEM ONLINE</span>
                    </div>
                </div>
            </div>
        </nav>

        {/* Page Content */}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/report" element={<ReportView />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;