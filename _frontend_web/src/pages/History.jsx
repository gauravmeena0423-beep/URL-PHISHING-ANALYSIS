import { useState, useEffect } from 'react';
import { getHistory } from '../services/api';
import { ShieldAlert, ShieldCheck, Clock } from 'lucide-react';

export default function History() {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function fetchHistory() {
            const data = await getHistory();
            setHistory(data);
            setLoading(false);
        }
        fetchHistory();
    }, []);

    return (
        <div className="max-w-5xl mx-auto mt-10 p-6">
            <h2 className="text-3xl font-bold mb-6 text-blue-400 flex items-center gap-2">
                <Clock className="w-8 h-8" /> Recent Scan History
            </h2>

            {loading ? (
                <div className="text-gray-400 text-center mt-10 text-xl font-bold animate-pulse">Loading Database...</div>
            ) : history.length === 0 ? (
                <div className="text-gray-400 text-center mt-10 text-lg">No scans found. Start by scanning a URL!</div>
            ) : (
                <div className="overflow-x-auto bg-slate-800 rounded-xl border border-slate-700 shadow-xl">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-900 text-gray-300">
                                <th className="p-4 border-b border-slate-700 font-bold tracking-wider">URL Scanned</th>
                                <th className="p-4 border-b border-slate-700 font-bold tracking-wider">Verdict</th>
                                <th className="p-4 border-b border-slate-700 font-bold tracking-wider">Risk Score</th>
                                <th className="p-4 border-b border-slate-700 font-bold tracking-wider">Time (UTC)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {history.map((item, index) => (
                                <tr key={index} className="hover:bg-slate-700/50 transition-colors border-b border-slate-700/50">
                                    <td className="p-4 text-gray-200 truncate max-w-xs" title={item.url}>{item.url}</td>
                                    <td className="p-4">
                                        <span className={`px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1 w-max ${
                                            item.verdict === 'Safe' ? 'bg-green-900/50 text-green-400 border border-green-500/50' : 
                                            item.verdict === 'Suspicious' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-500/50' : 
                                            'bg-red-900/50 text-red-400 border border-red-500/50'
                                        }`}>
                                            {item.verdict === 'Safe' ? <ShieldCheck className="w-3 h-3"/> : <ShieldAlert className="w-3 h-3"/>}
                                            {item.verdict.toUpperCase()}
                                        </span>
                                    </td>
                                    <td className="p-4 font-bold text-gray-300">{item.risk_score}%</td>
                                    <td className="p-4 text-sm text-gray-400">{new Date(item.timestamp).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}