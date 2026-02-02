import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Shield, ShieldCheck, ShieldAlert } from 'lucide-react';

const ProgressBar = ({ scanId, onComplete }) => {
    const [progress, setProgress] = useState(0);
    const [statusText, setStatusText] = useState("Initializing...");
    const [showLogs, setShowLogs] = useState(false);
    const [logs, setLogs] = useState([]);

    // Auto-scroll ref
    const logsEndRef = React.useRef(null);

    const scrollToBottom = () => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }

    useEffect(() => {
        const interval = setInterval(async () => {
            try {
                const response = await axios.get(`http://localhost:8000/scan/${scanId}`);
                const data = response.data;

                setProgress(data.progress);
                setStatusText(data.current_stage);

                if (data.logs) {
                    setLogs(data.logs);
                }

                if (data.status === 'COMPLETED') {
                    clearInterval(interval);
                    onComplete(data);
                }
            } catch (error) {
                console.error("Polling error", error);
            }
        }, 2000);

        return () => clearInterval(interval);
    }, [scanId, onComplete]);

    // Scroll to bottom when logs update
    useEffect(() => {
        if (showLogs) {
            scrollToBottom();
        }
    }, [logs, showLogs]);

    return (
        <div className="w-full max-w-2xl mx-auto space-y-8">
            <div className="text-center space-y-6">
                <div className="relative w-32 h-32 mx-auto flex items-center justify-center">
                    {/* Ring Animation */}
                    <div className="absolute inset-0 border-4 border-slate-700 rounded-full" />
                    <svg className="absolute inset-0 transform -rotate-90 w-full h-full" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="45" fill="none" stroke="#334155" strokeWidth="8" />
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
                    <div className="absolute inset-0 flex items-center justify-center text-xl font-bold">
                        {progress}%
                    </div>
                </div>

                <div>
                    <h3 className="text-xl font-semibold mb-2">{statusText}</h3>
                    <p className="text-sm text-gray-400">Please wait while we check your target.</p>
                </div>
            </div>

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
