import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Shield, ShieldCheck, ShieldAlert, AlertTriangle, RefreshCw, Home } from 'lucide-react';

const ProgressBar = ({ scanId, onComplete, onScanStart, onReset }) => {
    const [progress, setProgress] = useState(0);
    const [statusText, setStatusText] = useState("Initializing...");
    const [showLogs, setShowLogs] = useState(false);
    const [logs, setLogs] = useState([]);
    const [error, setError] = useState(null);
    const [scanConfig, setScanConfig] = useState(null); // For retry {target, mode}
    const [lastLogTime, setLastLogTime] = useState(Date.now());
    const [isLongRunning, setIsLongRunning] = useState(false);

    // Auto-scroll ref
    const logsEndRef = React.useRef(null);

    const scrollToBottom = () => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }

    const handleRetry = async () => {
        if (!scanConfig) return;
        try {
            setError(null);
            setStatusText("Restarting scan...");
            const response = await axios.post('http://localhost:8000/scan', {
                target: scanConfig.target,
                scan_mode: scanConfig.mode || 'light'
            });
            onScanStart(response.data.scan_id);
        } catch (err) {
            setError("Failed to restart scan: " + err.message);
        }
    };

    const handleStop = async () => {
        try {
            await axios.post(`http://localhost:8000/stop/${scanId}`);
            // Polling will pick up the STOPPED status
        } catch (err) {
            console.error("Stop failed", err);
        }
    };

    useEffect(() => {
        setLastLogTime(Date.now());
        setIsLongRunning(false);
        setError(null);

        const interval = setInterval(async () => {
            try {
                // Poll with summary=true to avoid huge payloads (findings list)
                const response = await axios.get(`http://localhost:8000/scan/${scanId}?summary=true`);
                const data = response.data;

                // Error Handling
                if (data.status === 'FAILED') {
                    clearInterval(interval);
                    setError(data.error || "Unknown backend error occurred.");
                    setScanConfig({ target: data.target, mode: data.mode });
                    return;
                }

                // Stop Handling
                if (data.status === 'STOPPED') {
                    clearInterval(interval);
                    setError("Scan was manually terminated by the user.");
                    setScanConfig({ target: data.target, mode: data.mode });
                    return;
                }

                setProgress(data.progress);
                setStatusText(data.current_stage);

                // Log Activity Tracking
                if (data.logs && data.logs.length > logs.length) {
                    setLogs(data.logs);
                    setLastLogTime(Date.now());
                    setIsLongRunning(false);
                } else {
                    // Check silence duration (15s)
                    if (Date.now() - lastLogTime > 5000) {
                        setIsLongRunning(true);
                    }
                }

                if (data.status === 'COMPLETED') {
                    clearInterval(interval);
                    // Fetch FULL data (with findings) for the report
                    const fullResponse = await axios.get(`http://localhost:8000/scan/${scanId}`);
                    onComplete(fullResponse.data);
                }
            } catch (error) {
                console.error("Polling error", error);
                // Don't fail immediately on network glitch, maybe retry?
                // For now, let's just log it. If backend is down, user sees nothing updating.
            }
        }, 2000);

        return () => clearInterval(interval);
    }, [scanId, onComplete, logs.length, lastLogTime]);

    // Scroll to bottom when logs update
    useEffect(() => {
        if (showLogs) {
            scrollToBottom();
        }
    }, [logs, showLogs]);

    return (
        <div className="w-full max-w-2xl mx-auto space-y-8">
            {error ? (
                <div className="text-center space-y-6 animate-in fade-in zoom-in duration-300">
                    <div className="mx-auto bg-red-500/10 p-6 rounded-full w-24 h-24 flex items-center justify-center border border-red-500/20">
                        <AlertTriangle className="w-12 h-12 text-red-500" />
                    </div>

                    <div className="space-y-2">
                        <h3 className="text-2xl font-bold text-white">Scan Failed</h3>
                        <div className="bg-slate-900 border border-slate-800 rounded p-4 max-w-lg mx-auto text-left overflow-auto max-h-32">
                            <code className="text-red-400 font-mono text-sm break-all">
                                {error}
                            </code>
                        </div>
                    </div>

                    <div className="flex justify-center gap-4 pt-4">
                        <button
                            onClick={handleRetry}
                            className="flex items-center gap-2 px-6 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded font-bold transition-colors"
                        >
                            <RefreshCw size={18} />
                            Try Again
                        </button>
                        <button
                            onClick={onReset}
                            className="flex items-center gap-2 px-6 py-2 border border-slate-700 hover:bg-slate-800 text-slate-300 rounded font-bold transition-colors"
                        >
                            <Home size={18} />
                            New Scan
                        </button>
                    </div>
                </div>
            ) : (
                <div className="text-center space-y-6">
                    <div className="relative w-32 h-32 mx-auto flex items-center justify-center">
                        {/* Ring Animation */}
                        <div className="absolute inset-0 border-4 border-slate-800 rounded-full" />
                        <svg className="absolute inset-0 transform -rotate-90 w-full h-full" viewBox="0 0 100 100">
                            <circle cx="50" cy="50" r="45" fill="none" stroke="#1e293b" strokeWidth="8" />
                            <circle
                                cx="50" cy="50" r="45"
                                fill="none"
                                stroke="#3b82f6"
                                strokeWidth="8"
                                strokeDasharray="283"
                                strokeDashoffset={283 - (283 * progress / 100)}
                                strokeLinecap="round"
                                className="transition-all duration-1000 ease-out"
                            />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center text-xl font-bold text-white">
                            {progress}%
                        </div>
                    </div>

                    <div className="space-y-2">
                        <h3 className="text-xl font-semibold text-white animate-pulse">{statusText}</h3>
                        <p className="text-sm text-slate-400">Please wait while we check your target.</p>

                        {/* Still Working Indicator */}
                        <div className={`h-6 transition-opacity duration-700 ${isLongRunning ? 'opacity-100' : 'opacity-0'}`}>
                            <p className="text-xs text-yellow-500 font-mono flex items-center justify-center gap-1">
                                <span className="w-1.5 h-1.5 bg-yellow-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                                <span className="w-1.5 h-1.5 bg-yellow-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                                <span className="w-1.5 h-1.5 bg-yellow-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                                <span className="ml-2">Still working... (Heavy Task)</span>
                            </p>
                        </div>

                        {/* Stop Button */}
                        <div className="pt-4">
                            <button
                                onClick={handleStop}
                                className="inline-flex items-center gap-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/20 rounded transition-colors text-xs font-semibold uppercase tracking-wider"
                            >
                                <div className="w-2 h-2 bg-red-500 rounded-sm" />
                                Stop Scan
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Logs Section */}
            <div className="border-t border-slate-800 pt-6">
                <button
                    onClick={() => setShowLogs(!showLogs)}
                    className="flex items-center gap-2 mx-auto text-sm text-slate-400 hover:text-white transition-colors"
                >
                    {showLogs ? (
                        <>
                            <span>Hide Logs</span>
                            <ShieldAlert size={14} />
                        </>
                    ) : (
                        <>
                            <span>Show Live Logs</span>
                            <ShieldCheck size={14} />
                        </>
                    )}
                </button>

                {showLogs && (
                    <div className="mt-4 bg-black rounded-lg p-4 font-mono text-xs h-64 overflow-y-auto border border-slate-700 shadow-inner">
                        {logs.length > 0 ? (
                            logs.map((log, i) => (
                                <div key={i} className="mb-1 break-words">
                                    <span className="text-slate-500 mr-2">{log.split(']')[0]}]</span>
                                    <span className={
                                        log.includes("[ERROR]") ? "text-red-400" :
                                            log.includes("EXEC:") ? "text-blue-400" :
                                                log.includes("FOUND") ? "text-yellow-400" :
                                                    "text-green-400"
                                    }>
                                        {log.split(']').slice(1).join(']')}
                                    </span>
                                </div>
                            ))
                        ) : (
                            <div className="text-slate-600 italic">Waiting for logs...</div>
                        )}
                        <div ref={logsEndRef} />
                    </div>
                )}
            </div>
        </div>
    );
};

export default ProgressBar;
