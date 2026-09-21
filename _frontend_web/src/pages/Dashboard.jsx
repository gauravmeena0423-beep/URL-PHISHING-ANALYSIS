import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Radar, Terminal, ShieldAlert, CheckCircle2, Globe, Hash, Smartphone, Link, ChevronRight, Zap } from 'lucide-react';
import { scanUrl, scanIp, scanHash } from '../services/api';

// =====================================================================
// TAB CONFIGURATION
// =====================================================================
const SCAN_TABS = [
    {
        id: 'url',
        label: 'URL',
        icon: Link,
        color: 'cyan',
        placeholder: 'Paste URL to scan...\nOr paste multiple URLs (one per line) for Batch Scan.',
        hint: 'e.g., https://suspicious-site.com',
        inputType: 'url',
        description: 'Deep phishing & malware analysis',
        multiline: true,
    },
    {
        id: 'ip',
        label: 'IP Address',
        icon: Globe,
        color: 'violet',
        placeholder: 'Enter an IP address...',
        hint: 'e.g., 192.168.1.1 or 8.8.8.8',
        inputType: 'ip',
        description: 'Geolocation, abuse score & port scan',
        multiline: false,
    },
    {
        id: 'apk',
        label: 'APK Hash',
        icon: Smartphone,
        color: 'emerald',
        placeholder: 'Enter APK file hash (MD5 / SHA256)...',
        hint: 'e.g., d41d8cd98f00b204e9800998ecf8427e',
        inputType: 'hash',
        description: 'Android app malware detection',
        multiline: false,
    },
    {
        id: 'hash',
        label: 'File Hash',
        icon: Hash,
        color: 'amber',
        placeholder: 'Enter file hash (MD5 / SHA1 / SHA256)...',
        hint: 'e.g., a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
        inputType: 'hash',
        description: 'VirusTotal multi-engine hash scan',
        multiline: false,
    },
];

const TAB_COLORS = {
    cyan:    { border: 'border-cyan-500',    glow: 'shadow-cyan-500/30',   text: 'text-cyan-400',   bg: 'bg-cyan-500',   activeBg: 'bg-cyan-900/30',   ring: 'ring-cyan-500/50'   },
    violet:  { border: 'border-violet-500',  glow: 'shadow-violet-500/30', text: 'text-violet-400', bg: 'bg-violet-500', activeBg: 'bg-violet-900/30', ring: 'ring-violet-500/50' },
    emerald: { border: 'border-emerald-500', glow: 'shadow-emerald-500/30',text: 'text-emerald-400',bg: 'bg-emerald-500',activeBg: 'bg-emerald-900/30',ring: 'ring-emerald-500/50'},
    amber:   { border: 'border-amber-500',   glow: 'shadow-amber-500/30',  text: 'text-amber-400',  bg: 'bg-amber-500',  activeBg: 'bg-amber-900/30',  ring: 'ring-amber-500/50'  },
};

// =====================================================================
// MAIN DASHBOARD COMPONENT
// =====================================================================
export default function Dashboard() {
    const [activeTab, setActiveTab] = useState('url');
    const [inputData, setInputData] = useState('');
    const [loading, setLoading] = useState(false);
    
    // Bulk Scan States (URL tab only)
    const [isBulkMode, setIsBulkMode] = useState(false);
    const [bulkResults, setBulkResults] = useState([]);
    const [progress, setProgress] = useState({ current: 0, total: 0 });
    
    const navigate = useNavigate();
    const currentTab = SCAN_TABS.find(t => t.id === activeTab);
    const colors = TAB_COLORS[currentTab.color];

    // Tab switch karte waqt input clear karo
    const handleTabChange = (tabId) => {
        setActiveTab(tabId);
        setInputData('');
        setIsBulkMode(false);
        setBulkResults([]);
    };

    // ===== SMART AUTO-DETECT: Input dekh ke tab suggest karna =====
    const handleInputChange = (value) => {
        setInputData(value);
        const trimmed = value.trim();
        if (!trimmed) return;
        
        // Auto-detect
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        const hashPattern = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
        const urlPattern = /^https?:\/\//i;
        
        if (activeTab === 'url' && ipPattern.test(trimmed)) {
            setActiveTab('ip');
        } else if (activeTab === 'url' && hashPattern.test(trimmed)) {
            setActiveTab('hash');
        } else if ((activeTab === 'ip' || activeTab === 'hash') && urlPattern.test(trimmed)) {
            setActiveTab('url');
        }
    };

    // ===== MAIN EXECUTE FUNCTION =====
    const handleExecute = async (e) => {
        e.preventDefault();
        if (!inputData.trim()) return;
        
        setLoading(true);
        setIsBulkMode(false);
        setBulkResults([]);
        
        try {
            // --- URL TAB ---
            if (activeTab === 'url') {
                const urls = inputData.split('\n').map(u => u.trim()).filter(u => u !== '');
                if (urls.length === 0) { setLoading(false); return; }
                if (urls.length > 10) { alert("System Safety: Maximum 10 URLs allowed at once!"); setLoading(false); return; }
                
                if (urls.length === 1) {
                    const result = await scanUrl(urls[0]);
                    navigate('/report', { state: { reportData: result, scanType: 'url' } });
                } else {
                    // Bulk mode
                    setIsBulkMode(true);
                    setBulkResults([]);
                    setProgress({ current: 0, total: urls.length });
                    let tempResults = [];
                    for (let i = 0; i < urls.length; i++) {
                        setProgress({ current: i + 1, total: urls.length });
                        try {
                            const data = await scanUrl(urls[i]);
                            tempResults.push(data);
                            setBulkResults([...tempResults]);
                        } catch (error) {
                            tempResults.push({
                                target: { url_scanned: urls[i], real_destination: 'Failed' },
                                threat_intelligence: { verdict: 'Error', risk_score_percentage: 0 }
                            });
                            setBulkResults([...tempResults]);
                        }
                    }
                    setLoading(false);
                }
                return;
            }
            
            // --- IP TAB ---
            if (activeTab === 'ip') {
                const result = await scanIp(inputData.trim());
                navigate('/report', { state: { reportData: result, scanType: 'ip' } });
                return;
            }
            
            // --- APK HASH TAB ---
            if (activeTab === 'apk') {
                const result = await scanHash(inputData.trim(), 'apk');
                navigate('/report', { state: { reportData: result, scanType: 'apk' } });
                return;
            }
            
            // --- FILE HASH TAB ---
            if (activeTab === 'hash') {
                const result = await scanHash(inputData.trim(), 'file');
                navigate('/report', { state: { reportData: result, scanType: 'hash' } });
                return;
            }
            
        } catch (error) {
            alert(`Scan Failed: ${error.response?.data?.detail || error.message || 'Connection to AI Core Failed!'}`);
        } finally {
            if (activeTab !== 'url' || !isBulkMode) {
                setLoading(false);
            }
        }
    };

    const getButtonText = () => {
        if (loading && activeTab === 'url' && !isBulkMode) return 'INITIALIZING DEEP TRACE...';
        if (loading && isBulkMode) return `SCANNING BATCH (${progress.current}/${progress.total})`;
        if (loading && activeTab === 'ip') return 'TRACING IP...';
        if (loading && (activeTab === 'apk' || activeTab === 'hash')) return 'ANALYZING HASH...';
        return 'EXECUTE SCAN';
    };

    return (
        <div className="flex flex-col items-center min-h-[85vh] pt-12 px-4">
            
            {/* Holographic Radar */}
            {!isBulkMode && (
                <div className="relative mb-6">
                    <Radar className={`w-20 h-20 transition-all duration-300 ${loading ? 'animate-spin' : ''} ${colors.text}`} />
                    <div className={`absolute inset-0 blur-2xl rounded-full opacity-20 ${colors.bg}`}></div>
                </div>
            )}
            
            <h1 className="mb-1 text-4xl md:text-5xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-600 drop-shadow-lg text-center">
                THREAT ANALYSIS ENGINE
            </h1>
            <p className="mb-8 text-base font-mono text-cyan-700/80 flex items-center gap-2">
                <Terminal className="w-4 h-4" /> root@phishguard:~# awaiting_scan_target
            </p>
            
            {/* ===== 4-TAB SELECTOR ===== */}
            <div className="w-full max-w-4xl mb-4">
                <div className="grid grid-cols-4 gap-2 p-1.5 bg-[#0a0a0a] rounded-2xl border border-slate-800">
                    {SCAN_TABS.map((tab) => {
                        const isActive = activeTab === tab.id;
                        const tabColors = TAB_COLORS[tab.color];
                        const Icon = tab.icon;
                        return (
                            <button
                                key={tab.id}
                                type="button"
                                onClick={() => handleTabChange(tab.id)}
                                className={`
                                    relative flex flex-col items-center gap-1.5 py-3 px-2 rounded-xl
                                    font-bold text-sm transition-all duration-300 group
                                    ${isActive 
                                        ? `${tabColors.activeBg} ${tabColors.text} border ${tabColors.border} shadow-lg ${tabColors.glow}` 
                                        : 'text-slate-600 hover:text-slate-300 hover:bg-slate-900/50 border border-transparent'}
                                `}
                            >
                                <Icon className={`w-5 h-5 transition-all duration-300 ${isActive ? '' : 'group-hover:scale-110'}`} />
                                <span className="tracking-wider text-xs font-black">{tab.label}</span>
                                {isActive && (
                                    <span className={`text-[10px] font-normal opacity-70 text-center leading-tight ${tabColors.text}`}>
                                        {tab.description}
                                    </span>
                                )}
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* ===== SMART INPUT BOX ===== */}
            <form onSubmit={handleExecute} className="w-full max-w-4xl relative group mb-8">
                <div className={`absolute -inset-0.5 bg-gradient-to-r from-${currentTab.color === 'cyan' ? 'cyan' : currentTab.color}-500 to-blue-600 rounded-xl blur opacity-20 group-hover:opacity-40 transition duration-700`}></div>
                
                <div className={`relative flex flex-col bg-[#0a0a0a] rounded-xl border overflow-hidden transition-all duration-300 ${colors.border}`}>
                    
                    {/* Input Hint Bar */}
                    <div className={`flex items-center gap-2 px-5 py-2 border-b border-slate-900 ${colors.text} opacity-60`}>
                        <Zap className="w-3.5 h-3.5" />
                        <span className="text-xs font-mono">{currentTab.hint}</span>
                        <span className="ml-auto text-[10px] uppercase tracking-widest opacity-60">
                            {activeTab === 'url' ? 'Multi-line for batch scan' : `${currentTab.label} Mode`}
                        </span>
                    </div>
                    
                    {currentTab.multiline ? (
                        <textarea
                            rows={inputData.split('\n').length > 1 ? "5" : "2"}
                            value={inputData}
                            onChange={(e) => handleInputChange(e.target.value)}
                            disabled={loading && isBulkMode}
                            placeholder={currentTab.placeholder}
                            required
                            className={`w-full p-5 text-lg font-mono bg-transparent focus:outline-none resize-none transition-all duration-300 placeholder-slate-800 ${colors.text}`}
                        />
                    ) : (
                        <input
                            type="text"
                            value={inputData}
                            onChange={(e) => handleInputChange(e.target.value)}
                            disabled={loading}
                            placeholder={currentTab.placeholder}
                            required
                            className={`w-full p-5 text-lg font-mono bg-transparent focus:outline-none transition-all duration-300 placeholder-slate-800 ${colors.text}`}
                        />
                    )}
                    
                    <button
                        type="submit"
                        disabled={loading}
                        className={`
                            w-full px-10 py-4 text-base font-black tracking-widest
                            text-[#0a0a0a] transition-all duration-300 border-t
                            flex items-center justify-center gap-3
                            ${colors.bg} hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed
                            border-t-slate-800
                        `}
                    >
                        {loading ? (
                            <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"/>
                            </svg>
                        ) : (
                            <ChevronRight className="w-5 h-5" />
                        )}
                        {getButtonText()}
                    </button>
                </div>
            </form>

            {/* ===== SCAN MODE BADGES ===== */}
            {!isBulkMode && (
                <div className="flex flex-wrap justify-center gap-3 mb-6 w-full max-w-4xl">
                    {[
                        { icon: '🔗', label: 'URL Phishing Scan', tab: 'url', color: 'border-cyan-900/50 text-cyan-700' },
                        { icon: '🌐', label: 'IP Reputation & Geo', tab: 'ip', color: 'border-violet-900/50 text-violet-700' },
                        { icon: '📱', label: 'APK Malware Check', tab: 'apk', color: 'border-emerald-900/50 text-emerald-700' },
                        { icon: '#️⃣', label: 'File Hash Analysis', tab: 'hash', color: 'border-amber-900/50 text-amber-700' },
                    ].map(badge => (
                        <button
                            key={badge.tab}
                            type="button"
                            onClick={() => handleTabChange(badge.tab)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-full border text-xs font-mono font-bold transition-all duration-200 hover:brightness-150 ${badge.color} ${activeTab === badge.tab ? 'brightness-200' : ''}`}
                        >
                            <span>{badge.icon}</span> {badge.label}
                        </button>
                    ))}
                </div>
            )}

            {/* ===== LIVE BULK RESULTS TABLE (URL Tab Only) ===== */}
            {isBulkMode && (
                <div className="w-full max-w-5xl">
                    {loading && (
                        <div className="mb-6 bg-black rounded-full h-1.5 border border-cyan-900 overflow-hidden shadow-[0_0_15px_rgba(6,182,212,0.2)]">
                            <div
                                className="bg-cyan-500 h-full transition-all duration-500"
                                style={{ width: `${(progress.current / progress.total) * 100}%` }}
                            ></div>
                        </div>
                    )}
                    
                    {bulkResults.length > 0 && (
                        <div className="bg-[#0a0a0a] rounded-xl border border-slate-800 shadow-xl overflow-hidden">
                            <table className="w-full text-left font-mono text-sm">
                                <thead className="bg-slate-900 text-cyan-500 border-b border-slate-800">
                                    <tr>
                                        <th className="p-4">#</th>
                                        <th className="p-4">Original URL</th>
                                        <th className="p-4">Resolved Destination</th>
                                        <th className="p-4">Risk Score</th>
                                        <th className="p-4">Verdict</th>
                                    </tr>
                                </thead>
                                <tbody className="text-gray-300">
                                    {bulkResults.map((res, index) => {
                                        const isSafe = res.threat_intelligence.verdict === 'Safe';
                                        const isError = res.threat_intelligence.verdict === 'Error';
                                        const isMalicious = res.threat_intelligence.verdict === 'Malicious';
                                        const isSuspicious = res.threat_intelligence.verdict === 'Suspicious';
                                        return (
                                            <tr key={index} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                                                <td className="p-4 text-slate-600">{index + 1}</td>
                                                <td className="p-4 truncate max-w-[180px] text-cyan-300" title={res.target?.url_scanned}>{res.target?.url_scanned}</td>
                                                <td className="p-4 truncate max-w-[200px] text-slate-500" title={res.target?.real_destination}>{res.target?.real_destination}</td>
                                                <td className="p-4">
                                                    {isError ? 'N/A' : (
                                                        <span className={`font-bold ${isSafe ? 'text-emerald-500' : isSuspicious ? 'text-amber-500' : 'text-rose-500'}`}>
                                                            {res.threat_intelligence.risk_score_percentage}%
                                                        </span>
                                                    )}
                                                </td>
                                                <td className="p-4">
                                                    {isError ? (
                                                        <span className="text-gray-500">FAILED</span>
                                                    ) : (
                                                        <span className={`flex items-center gap-2 px-3 py-1 rounded-full w-max text-xs font-bold
                                                            ${isSafe ? 'bg-emerald-900/30 text-emerald-500 border border-emerald-500/30' 
                                                            : isSuspicious ? 'bg-amber-900/30 text-amber-500 border border-amber-500/30'
                                                            : 'bg-rose-900/30 text-rose-500 border border-rose-500/30'}`}>
                                                            {isSafe ? <CheckCircle2 className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3 animate-pulse" />}
                                                            {res.threat_intelligence.verdict.toUpperCase()}
                                                        </span>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

        </div>
    );
}