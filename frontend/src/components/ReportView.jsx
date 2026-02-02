import React, { useState, useMemo } from 'react';
import { Download, Upload, Filter, AlertTriangle, CheckCircle, Info, Code, Eye, EyeOff, Server, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Helper to merge classes
function cn(...inputs) {
    return twMerge(clsx(inputs));
}

const SeverityBadge = ({ severity }) => {
    const colors = {
        critical: "bg-red-500/10 text-red-500 border-red-500/20",
        high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
        medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
        low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
        info: "bg-slate-500/10 text-slate-500 border-slate-500/20",
    };

    return (
        <span className={cn("px-2 py-0.5 rounded text-xs font-bold uppercase border", colors[severity?.toLowerCase()] || colors.info)}>
            {severity}
        </span>
    );
};

const FindingCard = ({ group, isExpanded, onToggle, excluded, onExcludeToggle }) => {
    const representative = group.findings[0];
    const { name, severity, description, references, tool } = representative;
    const count = group.findings.length;

    // Impact generation (Generic based on severity as fallback)
    const getPossibleImpact = (sev) => {
        switch (sev?.toLowerCase()) {
            case 'critical': return "Immediate system compromise is likely. Attackers can execute arbitrary code or access full database.";
            case 'high': return "Attackers can access sensitive data or modify application state. Significant business impact.";
            case 'medium': return "Partial disclosure of information or manipulation of some data. Requires user interaction or specific conditions.";
            case 'low': return "Minimal impact. May act as a stepping stone for complex attacks.";
            default: return "Information disclosure useful for reconnaissance.";
        }
    };

    return (
        <div className={cn("bg-slate-900 rounded-lg border transition-all break-inside-avoid print:bg-white print:border-slate-200 print:shadow-none print:rounded-none print:break-inside-avoid",
            excluded ? "border-slate-800 opacity-60 print:hidden" : "border-slate-800 hover:border-slate-700 shadow-sm"
        )}>
            {/* Header */}
            <div className="p-4 flex items-start gap-4 cursor-pointer group print:p-2 print:gap-2" onClick={onToggle}>
                <div className={cn("mt-1 p-2 rounded-lg print:hidden", excluded ? "bg-slate-800" : "bg-slate-800/50")}>
                    <AlertTriangle className={cn("w-5 h-5",
                        severity?.toLowerCase() === 'critical' ? 'text-red-500' :
                            severity?.toLowerCase() === 'high' ? 'text-orange-500' :
                                'text-slate-400'
                    )} />
                </div>

                <div className="flex-1 space-y-1">
                    <div className="flex items-center gap-3 flex-wrap print:gap-2">
                        <h3 className={cn("font-bold text-lg print:text-base print:text-black", excluded && "line-through text-slate-500")}>
                            {name}
                        </h3>
                        <SeverityBadge severity={severity} />
                        <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded uppercase print:hidden">{tool}</span>
                        {count > 1 && (
                            <span className="text-xs bg-accent/20 text-accent px-2 py-0.5 rounded font-mono print:bg-slate-100 print:text-slate-700">
                                x{count} Instances
                            </span>
                        )}
                    </div>
                </div>

                <div className="flex items-center gap-4 print:hidden">
                    {/* Expansion Indicator - Hidden in Print */}
                    <span className="text-xs text-slate-500 hidden sm:block group-hover:text-accent font-medium">
                        {isExpanded ? "Collapse" : "View Details"}
                    </span>
                    <ChevronDown className={cn("text-slate-500 transition-transform", isExpanded && "rotate-180")} size={20} />

                    <div className="border-l border-slate-700 pl-4" onClick={(e) => e.stopPropagation()}>
                        <input
                            type="checkbox"
                            checked={!excluded}
                            onChange={(e) => { onExcludeToggle(group.id); }}
                            className="w-4 h-4 rounded border-slate-600 bg-slate-800 checked:bg-accent cursor-pointer"
                            title="Include in Report"
                        />
                    </div>
                </div>
            </div>

            {/* Expanded Content (Details) - Always rendered for Print, toggled via CSS for Screen */}
            {!excluded && (
                <div className={cn("border-t border-slate-800 p-6 bg-slate-900/50 space-y-6 print:bg-white print:border-slate-100 print:p-4 print:space-y-4",
                    !isExpanded && "hidden print:block"
                )}>
                    {/* Description & Impact */}
                    <div className="grid md:grid-cols-2 gap-6 print:gap-4 break-inside-avoid">
                        <div className="space-y-2">
                            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider print:text-black print:text-xs">Description</h4>
                            <p className="text-sm text-slate-400 leading-relaxed print:text-slate-700 print:text-xs">
                                {description || "No specific description provided by tool."}
                            </p>
                        </div>
                        <div className="space-y-2">
                            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider print:text-black print:text-xs">Possible Impact</h4>
                            <p className="text-sm text-slate-400 leading-relaxed print:text-slate-700 print:text-xs">
                                {getPossibleImpact(severity)}
                            </p>
                        </div>
                    </div>

                    {/* Affected URLs / Assets */}
                    <div className="space-y-2 break-inside-avoid">
                        <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2 print:text-black print:text-xs">
                            <Server size={14} /> Affected Assets ({count})
                        </h4>
                        <div className="bg-slate-950 rounded border border-slate-800 max-h-40 overflow-y-auto font-mono text-xs p-2 space-y-1 print:bg-slate-50 print:border-slate-200 print:text-black print:max-h-none">
                            {group.findings.map((f, i) => (
                                <div key={i} className="flex items-start gap-2 text-slate-400 break-all border-b border-slate-900 last:border-0 pb-1 last:pb-0 print:border-slate-200 print:text-slate-800">
                                    <span className="text-slate-600 select-none w-6 text-right print:text-slate-500">{i + 1}.</span>
                                    <span className="text-green-400 print:text-blue-700">{f.matched_at || f.host || f.id}</span>
                                    {f.ip && <span className="text-slate-600 print:text-slate-500">({f.ip})</span>}
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Evidence (Grouped or First) */}
                    <div className="space-y-2 break-inside-avoid">
                        {/* Always open details in print to ensure content is visible */}
                        <details className="group print:open" open={severity === 'critical' || severity === 'high'}>
                            <summary className="flex items-center gap-2 text-sm font-semibold text-accent cursor-pointer select-none print:text-black">
                                <Code size={16} /> Technical Evidence
                                <ChevronDown className="group-open:rotate-180 transition-transform print:hidden" size={14} />
                            </summary>
                            <div className="pt-3">
                                <div className="bg-black rounded-lg border border-slate-800 p-4 font-mono text-xs overflow-x-auto text-green-400/90 whitespace-pre-wrap print:bg-slate-50 print:text-slate-800 print:border-slate-200 print:whitespace-pre-wrap print:break-all">
                                    {representative.evidence || "No raw evidence output captured for this item (check Affected Assets above)."}
                                </div>
                                {count > 1 && (
                                    <p className="text-xs text-slate-500 mt-2 italic">
                                        * Evidence shown for first instance.
                                    </p>
                                )}
                            </div>
                        </details>
                    </div>

                    {/* References */}
                    {references && references.length > 0 && (
                        <div className="space-y-2 break-inside-avoid">
                            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider print:text-black print:text-xs">References</h4>
                            <ul className="list-disc list-inside space-y-1">
                                {references.map((ref, i) => (
                                    <li key={i} className="text-sm text-accent truncate print:text-blue-600">
                                        <a href={ref} target="_blank" rel="noopener noreferrer" className="hover:underline flex items-inline gap-1">
                                            {ref} <ExternalLink size={10} className="inline" />
                                        </a>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

const ReportView = ({ scanData }) => {
    const [excludedGroups, setExcludedGroups] = useState(new Set());
    const [logo, setLogo] = useState(null);
    const [expandedGroups, setExpandedGroups] = useState(new Set()); // Which cards are open

    // 1. Group Findings
    const groupedFindings = useMemo(() => {
        if (!scanData || !scanData.findings) return [];

        // Group by Name + Tool
        const groups = {};
        scanData.findings.forEach(finding => {
            const key = `${finding.tool}-${finding.name}`;
            if (!groups[key]) {
                groups[key] = {
                    id: key,
                    name: finding.name,
                    tool: finding.tool,
                    severity: finding.severity || 'info',
                    findings: [] // List of specific instances
                };
            }
            groups[key].findings.push(finding);
        });

        // Sort groups by severity
        const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
        return Object.values(groups).sort((a, b) => {
            const sevA = severityOrder[a.severity?.toLowerCase()] || 0;
            const sevB = severityOrder[b.severity?.toLowerCase()] || 0;
            return sevB - sevA; // Descending
        });
    }, [scanData]);

    // 2. Stats Calculation (Filtered)
    const stats = useMemo(() => {
        const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        groupedFindings.forEach(group => {
            if (!excludedGroups.has(group.id)) {
                const sev = group.severity?.toLowerCase();
                const count = group.findings.length;
                if (s[sev] !== undefined) s[sev] += count; // Count instances or groups? Usually instances for Exec Summary
                s.total += count;
            }
        });
        return s;
    }, [groupedFindings, excludedGroups]);

    const handlePrint = () => {
        window.print();
    };

    const toggleGroup = (id) => {
        const next = new Set(expandedGroups);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        setExpandedGroups(next);
    };

    const toggleExclude = (id) => {
        const next = new Set(excludedGroups);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        setExcludedGroups(next);
    }

    const handleLogoUpload = (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => setLogo(reader.result);
            reader.readAsDataURL(file);
        }
    };

    if (!scanData) return null;

    return (
        <div className="w-full max-w-5xl mx-auto space-y-8 print:w-full print:max-w-none print:space-y-4">

            {/* HEADER Actions (No Print) */}
            <div className="bg-slate-800 p-4 rounded-lg flex flex-col md:flex-row justify-between items-center gap-4 shadow-lg border border-slate-700 print:hidden">
                <label className="flex items-center gap-2 cursor-pointer bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded transition-colors">
                    <Upload size={18} />
                    <span className="text-sm font-bold">Upload Logo</span>
                    <input type="file" className="hidden" accept="image/*" onChange={handleLogoUpload} />
                </label>

                <button
                    onClick={handlePrint}
                    className="flex items-center gap-2 px-4 py-2 bg-accent hover:bg-blue-600 text-white rounded font-bold shadow-lg transition-all active:scale-95"
                >
                    <Download size={18} />
                    Export PDF
                </button>
            </div>

            {/* REPORT HEADER */}
            <div className="border border-slate-700 bg-slate-900 rounded-lg p-8 shadow-xl print:shadow-none print:border-none print:bg-white print:text-black print:p-0">
                <div className="flex justify-between items-start mb-8 border-b border-slate-700 pb-6 print:border-slate-300 print:pb-4 print:mb-6">
                    <div>
                        <h1 className="text-3xl font-bold text-white mb-2 print:text-black print:text-2xl">Security Assessment Report</h1>
                        <div className="text-slate-400 space-y-1 print:text-slate-600 print:text-sm">
                            <p>Target: <span className="text-accent font-mono print:text-black print:font-bold">{scanData.target}</span></p>
                            <p>Date: {new Date().toLocaleDateString()} {new Date().toLocaleTimeString()}</p>
                            <p>Scan ID: <span className="font-mono text-xs">{scanData.id}</span></p>
                        </div>
                    </div>
                    {logo ? (
                        <div className="flex justify-end w-64 h-20">
                            <img src={logo} alt="Company Logo" className="h-full w-full object-contain object-right" />
                        </div>
                    ) : (
                        <div className="text-right h-20 flex flex-col justify-center">
                            <h2 className="text-2xl font-bold text-slate-700">OmniProbe Scanner</h2>
                            <p className="text-xs text-slate-500">CONFIDENTIAL</p>
                        </div>
                    )}
                </div>

                {/* EXECUTIVE SUMMARY */}
                <div className="mb-8 print:mb-6">
                    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2 print:text-black print:text-lg print:mb-2">
                        <span className="w-1 h-6 bg-accent rounded-full print:bg-black print:h-5" /> Executive Summary
                    </h2>

                    {/* Screen Layout: Grid of Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4 print:hidden">
                        {[
                            { l: 'Critical', c: stats.critical, color: 'text-red-500' },
                            { l: 'High', c: stats.high, color: 'text-orange-500' },
                            { l: 'Medium', c: stats.medium, color: 'text-yellow-500' },
                            { l: 'Low', c: stats.low, color: 'text-blue-500' },
                            { l: 'Info', c: stats.info, color: 'text-slate-400' },
                        ].map((stat) => (
                            <div key={stat.l} className="bg-slate-950 p-4 rounded border border-slate-800 text-center">
                                <div className={cn("text-3xl font-bold mb-1", stat.color)}>{stat.c}</div>
                                <div className="text-xs text-slate-500 uppercase font-semibold tracking-wider">{stat.l} Issues</div>
                            </div>
                        ))}
                    </div>

                    {/* Print Layout: Single Row of Solid Rectangles */}
                    <div className="hidden print:grid print:grid-cols-5 print:gap-1">
                        {[
                            { l: 'Critical', c: stats.critical, bg: 'bg-red-600' },
                            { l: 'High', c: stats.high, bg: 'bg-orange-500' },
                            { l: 'Medium', c: stats.medium, bg: 'bg-yellow-500' },
                            { l: 'Low', c: stats.low, bg: 'bg-blue-500' },
                            { l: 'Info', c: stats.info, bg: 'bg-slate-500' },
                        ].map((stat) => (
                            <div key={stat.l} className={cn("text-center py-2 px-1 text-white border border-white", stat.bg)}>
                                <div className="text-sm font-bold leading-none">{stat.c}</div>
                                <div className="text-[10px] uppercase font-bold opacity-90">{stat.l}</div>
                            </div>
                        ))}
                    </div>

                    <p className="mt-6 text-slate-400 leading-relaxed print:text-slate-700 print:text-sm print:mt-4">
                        A total of <strong className="text-white print:text-black">{stats.total}</strong> issues were identified during the assessment.
                        {stats.critical > 0 ? " Critical vulnerabilities requiring immediate attention were found." :
                            stats.high > 0 ? " High severity vulnerabilities were detected that poses significant risk." :
                                " No critical or high severity issues were detected, but review of lower severity items is recommended."}
                    </p>
                </div>

                {/* FINDINGS LIST */}
                <div className="space-y-6 print:space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-xl font-bold text-white flex items-center gap-2 print:text-black print:text-lg">
                            <span className="w-1 h-6 bg-accent rounded-full print:bg-black print:h-5" /> Detailed Findings
                        </h2>
                        <button
                            onClick={() => {
                                // Expand all
                                const all = new Set(groupedFindings.map(g => g.id));
                                if (all.size === expandedGroups.size) setExpandedGroups(new Set()); // Collapse all
                                else setExpandedGroups(all);
                            }}
                            className="text-xs text-accent hover:underline print:hidden"
                        >
                            {expandedGroups.size === groupedFindings.length ? "Collapse All" : "Expand All"}
                        </button>
                    </div>

                    {groupedFindings.map((group) => (
                        <FindingCard
                            key={group.id}
                            group={group}
                            isExpanded={expandedGroups.has(group.id)}
                            onToggle={() => toggleGroup(group.id)}
                            excluded={excludedGroups.has(group.id)}
                            onExcludeToggle={toggleExclude}
                        />
                    ))}
                </div>

                {/* FOOTER */}
                <div className="mt-16 pt-6 border-t border-slate-800 text-center text-slate-500 text-xs text-opacity-50 print:mt-8 print:border-slate-300 print:text-slate-400">
                    Generated by OmniProbe Scanner • Advanced Vulnerability Assessment
                </div>
            </div>
        </div>
    );
};

export default ReportView;
