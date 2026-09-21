import { useLocation, useNavigate } from 'react-router-dom';
import { 
    ArrowLeft, ShieldAlert, ShieldCheck, Globe, Cpu, AlertTriangle, 
    Fingerprint, Server, Link as LinkIcon, Hash, Smartphone, 
    MapPin, Wifi, Activity, Eye, Database, Clock
} from 'lucide-react';
import ThreatMeter from '../components/ThreatMeter';

// =====================================================================
// HELPER: Verdict Theme Config
// =====================================================================
function getTheme(verdict) {
    if (verdict === 'Safe') return { 
        gradient: 'from-emerald-900/40 to-slate-900 border-emerald-500/30', 
        text: 'text-emerald-400', badge: 'bg-emerald-900/30 text-emerald-400 border-emerald-500/30'
    };
    if (verdict === 'Suspicious') return { 
        gradient: 'from-amber-900/40 to-slate-900 border-amber-500/30', 
        text: 'text-amber-400', badge: 'bg-amber-900/30 text-amber-400 border-amber-500/30'
    };
    if (verdict === 'Malicious') return { 
        gradient: 'from-rose-900/40 to-slate-900 border-rose-500/30', 
        text: 'text-rose-400', badge: 'bg-rose-900/30 text-rose-400 border-rose-500/30'
    };
    return { 
        gradient: 'from-slate-900/40 to-slate-900 border-slate-500/30', 
        text: 'text-slate-400', badge: 'bg-slate-900/30 text-slate-400 border-slate-500/30'
    };
}

// =====================================================================
// HELPER: Info Cell Component
// =====================================================================
function InfoCell({ label, value, highlight, className = '' }) {
    return (
        <div className={`bg-slate-800/50 p-4 rounded-lg border border-slate-700/50 ${className}`}>
            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">{label}</span>
            <span className={`text-sm font-mono font-bold break-all ${highlight || 'text-cyan-300'}`}>{value || 'N/A'}</span>
        </div>
    );
}

// =====================================================================
// HELPER: Alert Card
// =====================================================================
function AlertCard({ icon, text, type = 'danger' }) {
    const styles = {
        danger: 'bg-rose-900/20 border-rose-500/30 text-rose-400',
        warning: 'bg-amber-900/20 border-amber-500/30 text-amber-400',
        safe: 'bg-emerald-900/20 border-emerald-500/30 text-emerald-400',
        info: 'bg-cyan-900/20 border-cyan-500/30 text-cyan-400',
    };
    return (
        <div className={`flex items-center gap-3 p-3 border rounded-lg ${styles[type]}`}>
            {icon} <span className="text-sm font-bold">{text}</span>
        </div>
    );
}

// =====================================================================
// SECTION: URL Report (Original)
// =====================================================================
function URLReportSection({ detailed_analysis }) {
    const lex = detailed_analysis?.lexical_analysis || {};
    const net = detailed_analysis?.network_analysis || {};
    const shodan = detailed_analysis?.shodan || {};
    const isWebhook = lex.is_webhook === 1 || lex.is_webhook_or_tunnel === 1;

    return (
        <>
            {/* Intelligence Engines + Lexical */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                {/* Intelligence Engines */}
                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <Cpu className="w-5 h-5 text-cyan-400" /> Intelligence Engines
                    </h3>
                    <div className="space-y-3">
                        {[
                            { label: 'Google Safe Browsing', value: detailed_analysis.google_safe_browsing?.toUpperCase() || 'CLEAN', isClean: detailed_analysis.google_safe_browsing === 'Clean' },
                            { label: 'VirusTotal Detection', value: `${detailed_analysis.virustotal?.malicious || 0} ENGINES FLAGGED`, isClean: (detailed_analysis.virustotal?.malicious || 0) === 0, alwaysCyan: true },
                            { label: 'URLhaus Database', value: detailed_analysis.urlhaus?.toUpperCase() || 'CLEAN', isClean: detailed_analysis.urlhaus === 'Clean' },
                            { label: 'AbuseIPDB (IP Rep)', value: `${detailed_analysis.abuseipdb?.score || 0}% ABUSE SCORE`, isClean: (detailed_analysis.abuseipdb?.score || 0) === 0 },
                            { label: 'Gemini AI Engine', value: `${detailed_analysis.ml_ai_score || 0}% CONFIDENCE`, isClean: null, alwaysPurple: true },
                        ].map((item, i) => (
                            <div key={i} className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                <span className="text-slate-400 font-medium text-sm">{item.label}</span>
                                <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                                    item.alwaysPurple ? 'bg-purple-900/30 text-purple-400' :
                                    item.alwaysCyan ? 'bg-cyan-900/30 text-cyan-400' :
                                    item.isClean ? 'bg-emerald-900/30 text-emerald-400' : 'bg-rose-900/30 text-rose-400'
                                }`}>{item.value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Deep Link Extraction */}
                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <Fingerprint className="w-5 h-5 text-cyan-400" /> Deep Link Extraction
                    </h3>
                    <div className="grid grid-cols-2 gap-3 mb-4">
                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50 flex flex-col">
                            <span className="text-xs text-slate-500 uppercase tracking-wider">URL Length</span>
                            <span className="text-lg font-mono text-cyan-300">{lex.url_length} Chars</span>
                        </div>
                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50 flex flex-col">
                            <span className="text-xs text-slate-500 uppercase tracking-wider">Security</span>
                            <span className={`text-lg font-mono ${lex.is_https ? 'text-emerald-400' : 'text-rose-400'}`}>
                                {lex.is_https ? 'HTTPS SECURED' : 'UNSECURED HTTP'}
                            </span>
                        </div>
                    </div>
                    <div className="space-y-2">
                        {lex.is_logger === 1 && <AlertCard icon={<Server className="w-4 h-4"/>} text="IP Logger Detected" />}
                        {lex.is_shortener === 1 && <AlertCard icon={<LinkIcon className="w-4 h-4"/>} text="URL Shortener/Masking Detected" />}
                        {isWebhook && <AlertCard icon={<AlertTriangle className="w-4 h-4"/>} text="Credential Stealing Webhook / Tunnel Detected" />}
                        {lex.is_evasion === 1 && <AlertCard icon={<AlertTriangle className="w-4 h-4"/>} text="Evasion Wall (Click-Wall) Detected" />}
                        {lex.has_ip === 1 && <AlertCard icon={<Globe className="w-4 h-4"/>} text="Direct IP Address Used (Highly Suspicious)" />}
                        {lex.is_logger === 0 && lex.is_shortener === 0 && !isWebhook && lex.has_ip === 0 && lex.is_evasion === 0 && (
                            <AlertCard icon={<ShieldCheck className="w-4 h-4"/>} text="No critical lexical threats found in URL structure." type="safe" />
                        )}
                    </div>
                </div>
            </div>

            {/* OSINT Network Forensics */}
            <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                    <Server className="w-5 h-5 text-cyan-400" /> OSINT: Network & Domain Forensics
                </h3>
                {net.error && !net.resolved_ip ? (
                    <div className="p-4 bg-slate-800/50 rounded-lg text-slate-400 border border-slate-700/50">
                        {net.error} (Domain details protected or invalid)
                    </div>
                ) : (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <InfoCell label="Resolved IP (Host)" value={net.resolved_ip || "Unknown"} />
                        <InfoCell label="Registrar" value={net.registrar || "Hidden"} />
                        <InfoCell label="Organization" value={net.registrant_org || "Hidden"} highlight="text-emerald-400" />
                        <InfoCell label="Country" value={net.registrant_country || "Unknown"} highlight="text-amber-400" />
                        <InfoCell 
                            label="Domain Age" 
                            value={net.days_old !== -1 ? `${net.days_old} Days Old` : "Unknown"}
                            highlight={net.days_old < 30 && net.days_old !== -1 ? 'text-rose-500' : 'text-cyan-300'}
                        />
                        <div className="col-span-2 md:col-span-3 bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Shodan Open Ports Scan</span>
                            <span className={`text-sm font-mono font-bold truncate block ${shodan?.ports?.length > 3 ? 'text-rose-500 animate-pulse' : 'text-emerald-400'}`}>
                                {shodan?.ports?.length > 0 ? shodan.ports.join(", ") : "None Detected / Hidden"}
                            </span>
                        </div>
                    </div>
                )}
            </div>
        </>
    );
}

// =====================================================================
// SECTION: IP Report (NEW)
// =====================================================================
function IPReportSection({ detailed_analysis, target }) {
    const geo = detailed_analysis?.geolocation || {};
    const openPorts = detailed_analysis?.open_ports || [];
    const dangerousPorts = detailed_analysis?.dangerous_ports || {};
    
    const DANGEROUS_PORT_COLORS = {
        22: 'text-amber-400', 23: 'text-rose-400', 3389: 'text-rose-500',
        4444: 'text-rose-600', 8080: 'text-amber-400', 1080: 'text-amber-400',
    };

    return (
        <>
            {/* Geolocation + Org Info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <MapPin className="w-5 h-5 text-violet-400" /> Geolocation Intelligence
                    </h3>
                    <div className="grid grid-cols-2 gap-3">
                        <InfoCell label="IP Address" value={target?.ip_scanned || 'N/A'} highlight="text-violet-400" className="col-span-2" />
                        <InfoCell label="Country" value={geo.country || 'Unknown'} highlight="text-amber-400" />
                        <InfoCell label="Region" value={geo.region || 'Unknown'} />
                        <InfoCell label="City" value={geo.city || 'Unknown'} />
                        <InfoCell label="Reverse DNS" value={target?.reverse_dns || 'N/A'} />
                    </div>
                </div>

                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <Wifi className="w-5 h-5 text-violet-400" /> Network Identity
                    </h3>
                    <div className="space-y-3">
                        {[
                            { label: 'ISP', value: detailed_analysis?.isp || 'Unknown', color: 'text-cyan-400' },
                            { label: 'Organization', value: detailed_analysis?.org || 'Unknown', color: 'text-emerald-400' },
                            { label: 'ASN', value: detailed_analysis?.asn || 'Unknown', color: 'text-slate-300' },
                            { label: 'Usage Type', value: detailed_analysis?.usage_type || 'Unknown', color: 'text-slate-400' },
                            { label: 'Whitelisted', value: detailed_analysis?.is_whitelisted ? 'YES ✓' : 'NO', color: detailed_analysis?.is_whitelisted ? 'text-emerald-400' : 'text-slate-500' },
                        ].map((item, i) => (
                            <div key={i} className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                <span className="text-slate-400 font-medium text-sm">{item.label}</span>
                                <span className={`text-sm font-mono font-bold ${item.color}`}>{item.value}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* AbuseIPDB + Open Ports */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <Activity className="w-5 h-5 text-rose-400" /> AbuseIPDB Intelligence
                    </h3>
                    <div className="flex items-center justify-center mb-4">
                        <div className="relative w-32 h-32">
                            <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                                <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" strokeWidth="10"/>
                                <circle 
                                    cx="50" cy="50" r="40" fill="none" 
                                    stroke={detailed_analysis?.abuse_score > 50 ? '#ef4444' : detailed_analysis?.abuse_score > 20 ? '#f59e0b' : '#10b981'} 
                                    strokeWidth="10"
                                    strokeDasharray={`${(detailed_analysis?.abuse_score || 0) * 2.51} 251`}
                                    strokeLinecap="round"
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className={`text-3xl font-black ${detailed_analysis?.abuse_score > 50 ? 'text-rose-400' : detailed_analysis?.abuse_score > 20 ? 'text-amber-400' : 'text-emerald-400'}`}>
                                    {detailed_analysis?.abuse_score || 0}%
                                </span>
                                <span className="text-xs text-slate-500">Abuse Score</span>
                            </div>
                        </div>
                    </div>
                    <div className="text-center">
                        <span className="text-sm text-slate-500">Total Abuse Reports: </span>
                        <span className="text-sm font-bold text-slate-300">{detailed_analysis?.total_reports || 0}</span>
                    </div>
                </div>

                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <Database className="w-5 h-5 text-violet-400" /> Shodan: Open Ports
                    </h3>
                    {openPorts.length === 0 ? (
                        <AlertCard icon={<ShieldCheck className="w-4 h-4"/>} text="No open ports detected (or Shodan key not configured)" type="safe" />
                    ) : (
                        <div className="space-y-2">
                            <div className="flex flex-wrap gap-2 mb-3">
                                {openPorts.map(port => (
                                    <span key={port} className={`px-3 py-1 rounded-full text-xs font-mono font-bold border ${dangerousPorts[port] ? 'bg-rose-900/30 text-rose-400 border-rose-500/40 animate-pulse' : 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                                        :{port}
                                        {dangerousPorts[port] && <span className="ml-1 text-rose-300">({dangerousPorts[port]})</span>}
                                    </span>
                                ))}
                            </div>
                            {Object.keys(dangerousPorts).length > 0 && (
                                <AlertCard icon={<AlertTriangle className="w-4 h-4"/>} text={`${Object.keys(dangerousPorts).length} dangerous port(s) open!`} type="warning" />
                            )}
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}

// =====================================================================
// SECTION: Hash / APK Report (NEW)
// =====================================================================
function HashReportSection({ detailed_analysis, target, metadata }) {
    const isApk = target?.is_apk || metadata?.scan_type === 'APK_HASH';
    const detectionCount = detailed_analysis?.detection_count || 0;
    const totalEngines = detailed_analysis?.total_engines || 0;
    const malwareFamilies = detailed_analysis?.malware_families || [];
    const threatLabels = detailed_analysis?.threat_labels || [];
    const stats = detailed_analysis?.detection_stats || {};
    
    const detectionPct = totalEngines > 0 ? Math.round((detectionCount / totalEngines) * 100) : 0;

    return (
        <>
            {/* Hash Info + Detection Ratio */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        {isApk ? <Smartphone className="w-5 h-5 text-emerald-400" /> : <Hash className="w-5 h-5 text-amber-400" />}
                        {isApk ? 'APK File Details' : 'File Details'}
                    </h3>
                    <div className="space-y-3">
                        {[
                            { label: 'Hash Value', value: target?.hash_scanned, color: isApk ? 'text-emerald-400' : 'text-amber-400' },
                            { label: 'Hash Type', value: target?.hash_type || 'Unknown', color: 'text-cyan-400' },
                            { label: 'File Type', value: target?.file_type || 'Unknown', color: 'text-slate-300' },
                            { label: 'File Size', value: target?.file_size ? `${target.file_size} bytes` : 'Unknown', color: 'text-slate-400' },
                            { label: 'First Seen', value: detailed_analysis?.first_seen || 'Unknown', color: 'text-slate-400' },
                            { label: 'Last Scanned', value: detailed_analysis?.last_seen || 'Unknown', color: 'text-slate-400' },
                        ].map((item, i) => (
                            <div key={i} className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 gap-3">
                                <span className="text-slate-400 font-medium text-sm shrink-0">{item.label}</span>
                                <span className={`text-xs font-mono font-bold break-all text-right ${item.color}`}>{item.value || 'N/A'}</span>
                            </div>
                        ))}
                    </div>
                    {isApk && (
                        <div className="mt-4 p-3 bg-emerald-900/20 border border-emerald-500/30 rounded-lg flex items-center gap-2">
                            <Smartphone className="w-4 h-4 text-emerald-400" />
                            <span className="text-sm text-emerald-400 font-bold">Android APK Detected</span>
                        </div>
                    )}
                </div>

                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <Eye className="w-5 h-5 text-amber-400" /> VirusTotal Detection
                    </h3>
                    {/* Detection Circle */}
                    <div className="flex items-center justify-center mb-4">
                        <div className="relative w-32 h-32">
                            <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                                <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" strokeWidth="10"/>
                                <circle 
                                    cx="50" cy="50" r="40" fill="none" 
                                    stroke={detectionPct > 25 ? '#ef4444' : detectionPct > 5 ? '#f59e0b' : '#10b981'} 
                                    strokeWidth="10"
                                    strokeDasharray={`${detectionPct * 2.51} 251`}
                                    strokeLinecap="round"
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className={`text-2xl font-black ${detectionPct > 25 ? 'text-rose-400' : detectionPct > 5 ? 'text-amber-400' : 'text-emerald-400'}`}>
                                    {detectionCount}/{totalEngines}
                                </span>
                                <span className="text-xs text-slate-500">Detected</span>
                            </div>
                        </div>
                    </div>
                    {/* Stats Breakdown */}
                    <div className="grid grid-cols-2 gap-2 text-xs">
                        {Object.entries(stats).map(([key, val]) => (
                            <div key={key} className="flex justify-between p-2 bg-slate-800/50 rounded border border-slate-700/30">
                                <span className="text-slate-500 capitalize">{key}</span>
                                <span className={`font-bold ${key === 'malicious' ? 'text-rose-400' : key === 'suspicious' ? 'text-amber-400' : key === 'undetected' ? 'text-emerald-400' : 'text-slate-400'}`}>{val}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Malware Families + Threat Labels */}
            {(malwareFamilies.length > 0 || threatLabels.length > 0) && (
                <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-700/50 shadow-xl">
                    <h3 className="text-lg font-bold text-slate-300 mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-rose-400" /> Malware Intelligence
                    </h3>
                    {malwareFamilies.length > 0 && (
                        <div className="mb-4">
                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-2">Detected Malware Families</span>
                            <div className="flex flex-wrap gap-2">
                                {malwareFamilies.map((family, i) => (
                                    <span key={i} className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-rose-900/30 text-rose-400 border border-rose-500/30">
                                        ⚠ {family}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                    {threatLabels.length > 0 && (
                        <div>
                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-2">Engine Threat Labels</span>
                            <div className="flex flex-wrap gap-2">
                                {threatLabels.map((label, i) => (
                                    <span key={i} className="px-2 py-1 rounded text-xs font-mono bg-slate-800 text-amber-400 border border-slate-700">
                                        {label}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Not Found state */}
            {detailed_analysis?.detection_count === 0 && totalEngines === 0 && (
                <AlertCard icon={<Database className="w-4 h-4"/>} text="This hash was not found in VirusTotal database. It may be clean or never previously scanned." type="info" />
            )}
        </>
    );
}

// =====================================================================
// MAIN REPORT VIEW
// =====================================================================
export default function ReportView() {
    const location = useLocation();
    const navigate = useNavigate();
    const data = location.state?.reportData;
    const scanType = location.state?.scanType || 'url'; // 'url' | 'ip' | 'apk' | 'hash'

    if (!data) return <div className="p-10 text-center text-red-500 font-bold">ERROR: No Report Data Found.</div>;

    const { target = {}, threat_intelligence = {}, detailed_analysis = {}, recommendation = "", metadata = {} } = data;
    const verdict = threat_intelligence?.verdict || 'Unknown';
    const isSafe = verdict === 'Safe';
    const theme = getTheme(verdict);
    
    const effectiveReason = data.threat_reason || threat_intelligence?.threat_reason || (isSafe ? "No immediate threats detected." : "Suspicious patterns detected.");
    
    // Scan type badge config
    const scanBadges = {
        url: { label: '🔗 URL SCAN', color: 'bg-cyan-900/30 text-cyan-400 border-cyan-500/30' },
        ip:  { label: '🌐 IP SCAN', color: 'bg-violet-900/30 text-violet-400 border-violet-500/30' },
        apk: { label: '📱 APK HASH', color: 'bg-emerald-900/30 text-emerald-400 border-emerald-500/30' },
        hash:{ label: '#️⃣ FILE HASH', color: 'bg-amber-900/30 text-amber-400 border-amber-500/30' },
    };
    const badge = scanBadges[scanType] || scanBadges['url'];

    // Target display string
    const targetDisplay = 
        scanType === 'ip' ? (target.ip_scanned || 'N/A') :
        scanType === 'apk' || scanType === 'hash' ? (target.hash_scanned || 'N/A') :
        (target.url_scanned || 'N/A');

    return (
        <div className="max-w-6xl mx-auto mt-6 p-4 pb-16">
            <button onClick={() => navigate('/')} className="flex items-center text-cyan-500 hover:text-cyan-300 font-bold mb-6 transition-colors">
                <ArrowLeft className="w-5 h-5 mr-2" /> BACK TO SCANNER
            </button>

            {/* Top Section: Verdict & Threat Meter */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                
                {/* Main Verdict Card */}
                <div className={`md:col-span-2 p-8 rounded-2xl bg-gradient-to-br ${theme.gradient} border backdrop-blur-sm shadow-2xl flex flex-col justify-center`}>
                    <div className="flex items-start gap-4">
                        {isSafe ? <ShieldCheck className={`w-16 h-16 drop-shadow-lg ${theme.text}`} /> : <ShieldAlert className={`w-16 h-16 drop-shadow-lg animate-pulse ${theme.text}`} />}
                        <div className="flex-1 min-w-0">
                            {/* Scan Type Badge */}
                            <span className={`inline-block px-3 py-1 rounded-full text-[11px] font-mono font-bold border mb-2 ${badge.color}`}>
                                {badge.label}
                            </span>
                            <h2 className={`text-4xl font-black tracking-widest uppercase ${theme.text}`}>{verdict}</h2>
                            <p className={`mt-2 font-bold text-base ${isSafe ? 'text-emerald-300' : 'text-rose-300'}`}>
                                REASON: {effectiveReason}
                            </p>
                            <p className="text-slate-400 mt-3 flex items-center gap-2 flex-wrap">
                                <Globe className="w-4 h-4 text-cyan-500 shrink-0" />
                                <span className="font-mono bg-black/30 px-3 py-1 rounded border border-white/10 break-all text-sm">
                                    {targetDisplay}
                                </span>
                            </p>
                            {/* URL: Show redirect destination */}
                            {scanType === 'url' && target.real_destination && target.real_destination !== target.url_scanned && (
                                <p className="text-slate-400 mt-2 text-sm flex items-center gap-2">
                                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                                    Resolved: <span className="text-rose-400 font-mono break-all">{target.real_destination}</span>
                                </p>
                            )}
                        </div>
                    </div>
                    <div className="mt-6 p-4 bg-black/40 rounded-xl border border-white/5 text-slate-200 font-medium">
                        <span className="text-white/50 uppercase text-xs tracking-widest block mb-1">AI Recommendation</span>
                        {recommendation}
                    </div>
                </div>

                {/* Threat Meter */}
                <div className="bg-slate-900/80 rounded-2xl border border-slate-700/50 shadow-xl flex items-center justify-center">
                    <ThreatMeter score={threat_intelligence.risk_score_percentage} />
                </div>
            </div>

            {/* Scan-type specific sections */}
            {scanType === 'url' && <URLReportSection detailed_analysis={detailed_analysis} />}
            {scanType === 'ip' && <IPReportSection detailed_analysis={detailed_analysis} target={target} />}
            {(scanType === 'apk' || scanType === 'hash') && <HashReportSection detailed_analysis={detailed_analysis} target={target} metadata={metadata} />}

        </div>
    );
}