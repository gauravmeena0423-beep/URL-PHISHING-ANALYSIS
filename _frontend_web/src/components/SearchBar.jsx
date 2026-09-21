import { Search } from 'lucide-react';

export default function SearchBar({ onScan, loading }) {
    const handleSubmit = (e) => {
        e.preventDefault();
        const url = e.target.url.value;
        if (url) onScan(url);
    };

    return (
        <form onSubmit={handleSubmit} className="flex w-full shadow-2xl">
            <div className="relative flex-grow">
                <div className="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none">
                    <Search className="w-5 h-5 text-gray-400" />
                </div>
                <input
                    type="url"
                    name="url"
                    placeholder="Enter URL to scan (e.g., http://suspicious-link.com)"
                    required
                    className="w-full p-4 pl-12 text-lg text-white bg-slate-800 border-2 border-slate-700 rounded-l-xl focus:outline-none focus:border-blue-500 placeholder-gray-500"
                />
            </div>
            <button
                type="submit"
                disabled={loading}
                className="px-8 py-4 text-lg font-bold text-white transition-colors bg-blue-600 rounded-r-xl hover:bg-blue-700 disabled:bg-slate-600"
            >
                {loading ? 'Scanning...' : 'SCAN NOW'}
            </button>
        </form>
    );
}