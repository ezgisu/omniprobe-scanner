import React, { useState } from 'react';
import { Search } from 'lucide-react';
import axios from 'axios';

const InputForm = ({ onScanStart }) => {
    const [target, setTarget] = useState('');
    const [scanMode, setScanMode] = useState('light'); // 'light' or 'deep'
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!target) return;

        setLoading(true);
        try {
            const response = await axios.post('http://localhost:8000/scan', {
                target,
                scan_mode: scanMode
            });
            onScanStart(response.data.scan_id);
        } catch (error) {
            console.error("Scan failed to start", error);
            alert("Failed to start scan. Is the backend running?");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="w-full max-w-md mx-auto space-y-6">
            <form onSubmit={handleSubmit} className="relative flex items-center">
                <input
                    type="text"
                    placeholder="Enter IP or URL (e.g. 192.168.1.1 or scanme.nmap.org)"
                    className="w-full bg-slate-800 text-white rounded-lg py-4 px-6 pr-12 border border-slate-700 focus:border-accent focus:ring-1 focus:ring-accent outline-none transition-all shadow-lg text-base placeholder:text-sm"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={loading}
                />
                <button
                    type="submit"
                    className="absolute right-2 bg-accent hover:bg-blue-600 text-white p-2.5 rounded-md transition-colors disabled:opacity-50"
                    disabled={loading}
                >
                    {loading ? (
                        <div className="animate-spin h-5 w-5 border-2 border-white border-t-transparent rounded-full" />
                    ) : (
                        <Search className="h-5 w-5" />
                    )}
                </button>
            </form>

            {/* Scan Mode Selection */}
            {/* Scan Mode Selection */}
            <div className="space-y-3">
                {/* Top: Enumeration Mode (Full Width) */}
                <button
                    type="button"
                    onClick={() => setScanMode('enumeration')}
                    className={`w-full py-3 px-4 rounded-lg border-2 transition-all flex flex-col items-center justify-center gap-1 ${scanMode === 'enumeration'
                            ? 'bg-purple-500/10 border-purple-500 text-purple-400 shadow-lg shadow-purple-900/20'
                            : 'bg-slate-900 border-slate-800 text-slate-500 hover:border-slate-700 hover:text-slate-400'
                        }`}
                >
                    <span className="font-bold text-lg">Enumeration Mode</span>
                    <span className="text-xs opacity-70">Recon • UUID Extraction • Subdomains</span>
                </button>

                {/* Bottom: Light & Deep (Side by Side) */}
                <div className="grid grid-cols-2 gap-3">
                    <button
                        type="button"
                        onClick={() => setScanMode('light')}
                        className={`py-3 px-4 rounded-lg border-2 transition-all flex flex-col items-center justify-center gap-1 ${scanMode === 'light'
                                ? 'bg-blue-500/10 border-blue-500 text-blue-400 shadow-lg shadow-blue-900/20'
                                : 'bg-slate-900 border-slate-800 text-slate-500 hover:border-slate-700 hover:text-slate-400'
                            }`}
                    >
                        <span className="font-bold">Light Scan</span>
                        <span className="text-[10px] opacity-70">Fast • Standard Checks</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setScanMode('deep')}
                        className={`py-3 px-4 rounded-lg border-2 transition-all flex flex-col items-center justify-center gap-1 ${scanMode === 'deep'
                                ? 'bg-orange-500/10 border-orange-500 text-orange-400 shadow-lg shadow-orange-900/20'
                                : 'bg-slate-900 border-slate-800 text-slate-500 hover:border-slate-700 hover:text-slate-400'
                            }`}
                    >
                        <span className="font-bold">Deep Scan</span>
                        <span className="text-[10px] opacity-70">Wapiti Fuzzing • Full Nuclei</span>
                    </button>
                </div>
            </div>
        </div>
    );
};

export default InputForm;
