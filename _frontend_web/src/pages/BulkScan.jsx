import { useState } from 'react';
import { scanUrl } from '../services/api';
import { Layers, Play, CheckCircle2, ShieldAlert, Loader2 } from 'lucide-react';

export default function BulkScan() {
    const [urlList, setUrlList] = useState('');
    const [results, setResults] = useState([]);
    const [isScanning, setIsScanning] = useState(false);
    const [progress, setProgress] = useState({ current: 0, total: 0 });

    const handleBulkScan = async () => {
        // Text area se links nikalo (Enter / Nayi line ke hisaab se)
        const urls = urlList.split('\n').map(u => u.trim()).filter(u => u !== '');
        
        if (urls.length === 0) return alert("Please enter at least one URL!");
        if (urls.length > 10) return alert("For system safety, max 10 URLs allowed at once!");

        setIsScanning(true);
        setResults([]); // Purane results clear karo
        setProgress({ current: 0, total: urls.length });

        let tempResults = [];

        // Ek-ek karke backend ko bhejo taaki server crash na ho
        for (let i = 0; i < urls.length; i++) {
            setProgress({ current: i + 1, total: urls.length });
            try {
                const data = await scanUrl(urls[i]);
                tempResults.push(data);
                // Live table update karne ke liye state update karo
                setResults([...tempResults]); 
            } catch (error) {
                // Agar koi link fail ho jaye toh error daal do
                tempResults.push({
                    target: { url_scanned: urls[i], real_destination: 'Failed' },
                    threat_intelligence: { verdict: 'Error', risk_score_percentage: 0 }
                });
                setResults([...tempResults]);
            }
        }
        setIsScanning(false);
    };

    return (
        <div className="max-w-6xl mx-auto mt-8 p-6 font-sans">
            <h2 className="text-4xl font-black tracking-widest text-cyan-500 mb-6 flex items-center gap-3">
                <Layers className="w-10 h-10" /> BATCH ANALYSIS ENGINE
            </h2>

            {/* Input Area */}
            <div className="bg-[#0a0a0a] p-6 rounded-xl border border-cyan-900/50 shadow-[0_0_20px_rgba(6,182,212,0.1)] mb-8">
                <p className="text-gray-400 mb-2 font-mono text-sm">Paste multiple URLs (One URL per line). Max 10 URLs per batch.</p>
                <textarea
                    rows="6"
                    value={urlList}
                    onChange={(e) => setUrlList(e.target.value)}
                    placeholder="http://example.com&#10;https://iplogger.com/xyz&#10;http://tiny.cc/123"
                    disabled={isScanning}
                    className="w-full bg-black border border-cyan-900/50 rounded-lg p-4 text-cyan-300 font-mono focus:outline-none focus:border-cyan-500 mb-4"
                ></textarea>

                <button
                    onClick={handleBulkScan}
                    disabled={isScanning || urlList.trim() === ''}
                    className="flex items-center gap-2 px-8 py-3 bg-cyan-600 text-black font-bold tracking-widest rounded hover:bg-cyan-500 disabled:bg-cyan-900 disabled:text-cyan-700 transition-colors"
                >
                    {isScanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
                    {isScanning ? `SCANNING (${progress.current}/${progress.total})` : 'START BULK SCAN'}
                </button>
            </div>

            {/* Live Progress Bar */}
            {isScanning && (
                <div className="mb-8 bg-black rounded-full h-2 border border-cyan-900 overflow-hidden">
                    <div 
                        className="bg-cyan-500 h-full shadow-[0_0_10px_#06b6d4] transition-all duration-500"
                        style={{ width: `${(progress.current / progress.total) * 100}%` }}
                    ></div>
                </div>
            )}

            {/* Live Results Table */}
            {results.length > 0 && (
                <div className="bg-[#0a0a0a] rounded-xl border border-slate-800 shadow-xl overflow-hidden">
                    <table className="w-full text-left font-mono text-sm">
                        <thead className="bg-slate-900 text-cyan-500 border-b border-slate-800">
                            <tr>
                                <th className="p-4">Original URL</th>
                                <th className="p-4">Resolved Destination</th>
                                <th className="p-4">Risk Score</th>
                                <th className="p-4">Verdict</th>
                            </tr>
                        </thead>
                        <tbody className="text-gray-300">
                            {results.map((res, index) => {
                                const isSafe = res.threat_intelligence.verdict === 'Safe';
                                const isError = res.threat_intelligence.verdict === 'Error';
                                return (
                                    <tr key={index} className="border-b border-slate-800/50 hover:bg-slate-800/20">
                                        <td className="p-4 truncate max-w-[200px]" title={res.target?.url_scanned}>
                                            {res.target?.url_scanned}
                                        </td>
                                        <td className="p-4 truncate max-w-[250px] text-gray-500" title={res.target?.real_destination}>
                                            {res.target?.real_destination}
                                        </td>
                                        <td className="p-4">
                                            {isError ? 'N/A' : (
                                                <span className={`font-bold ${isSafe ? 'text-green-500' : 'text-red-500'}`}>
                                                    {res.threat_intelligence.risk_score_percentage}%
                                                </span>
                                            )}
                                        </td>
                                        <td className="p-4">
                                            {isError ? <span className="text-gray-500">FAILED</span> : (
                                                <span className={`flex items-center gap-2 px-3 py-1 rounded-full w-max text-xs font-bold ${isSafe ? 'bg-green-900/30 text-green-500 border border-green-500/30' : 'bg-red-900/30 text-red-500 border border-red-500/30'}`}>
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
    );
}