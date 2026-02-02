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
            <div className="bg-slate-900 p-1 rounded-lg flex items-center justify-between border border-slate-800">
                <button
                    type="button"
                    onClick={() => setScanMode('light')}
                    className={`flex-1 py-2 text-sm font-medium rounded-md transition-all ${scanMode === 'light'
                        ? 'bg-slate-700 text-white shadow'
                        : 'text-slate-500 hover:text-slate-300'
                        }`}
                >
                    Light Scan
                    <span className="block text-[10px] opacity-60 font-normal">Fast • Standard Checks</span>
                </button>
                <button
                    type="button"
                    onClick={() => setScanMode('deep')}
                    className={`flex-1 py-2 text-sm font-medium rounded-md transition-all ${scanMode === 'deep'
                        ? 'bg-accent text-white shadow'
                        : 'text-slate-500 hover:text-slate-300'
                        }`}
                >
                    Deep Scan
                    <span className="block text-[10px] opacity-80 font-normal text-slate-200">Wapiti Fuzzing • Full Nuclei</span>
                </button>
            </div>
        </div>
    );
};

export default InputForm;
