import React, { useState } from 'react';
import { Radar } from 'lucide-react';
import InputForm from './components/InputForm';
import ProgressBar from './components/ProgressBar';
import ReportView from './components/ReportView';

function App() {
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState("IDLE"); // IDLE, RUNNING, COMPLETED
  const [scanData, setScanData] = useState(null);

  const handleScanStart = (id) => {
    setScanId(id);
    setStatus("RUNNING");
  };

  const handleScanComplete = (data) => {
    setScanData(data);
    setStatus("COMPLETED");
  };

  const handleReset = () => {
    setStatus("IDLE");
    setScanId(null);
    setScanData(null);
  };

  return (
    <div className="min-h-screen bg-primary text-white p-6 font-sans selection:bg-accent selection:text-white print:bg-white print:text-black print:p-0">
      <div className="max-w-6xl mx-auto print:max-w-none print:mx-0">
        {/* Header */}
        <header className="flex items-center gap-3 mb-12 border-b border-slate-800 pb-6 print:hidden">
          <div className="bg-accent p-2 rounded-lg shadow-lg shadow-blue-500/20">
            <Radar className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">OmniProbe Scanner</h1>
            <p className="text-slate-400 text-sm">Advanced Vulnerability Assessment</p>
          </div>
        </header>

        {/* Content Area */}
        <main className="transition-all duration-500 ease-in-out print:w-full">
          {status === "IDLE" && (
            <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-8 animate-in fade-in zoom-in duration-500 print:hidden">
              <div className="text-center space-y-4 max-w-2xl">
                <h2 className="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-pink-500 to-orange-400 pb-2">
                  Let's Scan!
                </h2>
                <p className="text-slate-400 text-lg">
                  Enter a target IP or URL to launch a comprehensive vulnerability scan
                </p>
              </div>
              <InputForm onScanStart={handleScanStart} />
            </div>
          )}

          {status === "RUNNING" && (
            <div className="min-h-[50vh] flex flex-col items-center justify-center animate-in fade-in slide-in-from-bottom-4 duration-500 print:hidden">
              <ProgressBar scanId={scanId} onComplete={handleScanComplete} />
            </div>
          )}

          {status === "COMPLETED" && scanData && (
            <div className="animate-in fade-in slide-in-from-bottom-8 duration-700">
              <ReportView scanData={scanData} onNewScan={handleReset} />

              <div className="mt-12 text-center print:hidden">
                <button
                  onClick={handleReset}
                  className="text-slate-500 hover:text-white underline transition-colors"
                >
                  Start New Scan
                </button>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
