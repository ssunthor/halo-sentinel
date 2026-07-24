import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  FileText, Activity, ShieldAlert, AlertTriangle, ShieldCheck, 
  Loader2, Upload, X, File as FileIcon, Code, Settings, Play, Terminal, Send, Search,
  Server, Database, Globe, Cpu, ChevronRight, ChevronDown, Download, Edit3, Save,
  CheckCircle2, RefreshCcw, CheckSquare, Square, Eye, ListFilter, LogOut
} from 'lucide-react';

// --- SHARED UI COMPONENTS ---
const MetricCard = ({ label, value, icon: Icon, color }) => (
  <div className="bg-[#0a0a0a] p-4 rounded-lg border border-gray-800 relative overflow-hidden group hover:border-gray-700 transition-colors">
    <div className="absolute top-0 left-0 w-1 h-full" style={{ backgroundColor: color }}></div>
    <div className="flex justify-between items-start relative z-10">
      <div>
        <div className="text-gray-500 text-[9px] font-bold uppercase tracking-wider mb-1">{label}</div>
        <div className="text-xl font-bold text-white font-mono">{value}</div>
      </div>
      <div className="p-1.5 rounded bg-[#121212] text-gray-400 group-hover:text-white transition-colors">
        <Icon size={16} />
      </div>
    </div>
  </div>
);

const SeverityBadge = ({ severity }) => {
  const styles = {
    High: "bg-red-500/10 text-red-500 border-red-500/20",
    Medium: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    Low: "bg-green-500/10 text-green-500 border-green-500/20"
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${styles[severity] || styles.Low}`}>
      {severity}
    </span>
  );
};

// --- EMBEDDED CONSTANTS ---
const FRAMEWORKS = [
  'Default Best Practices', 'PCI-DSS v4.0', 'SOC 2 Type II', 'HIPAA', 'CIS Benchmarks', 'NIST 800-53'
];

// --- INTERNAL COMPONENTS ---

const IngestionTabs = ({ onFileUpload, onApiIngest, loading, error, isConnected, deviceHostname, onDisconnect, onReconnect }) => {
  const [activeTab, setActiveTab] = useState(isConnected ? 1 : 0);
  const [dragActive, setDragActive] = useState(false);
  const [deviceType, setDeviceType] = useState('cisco-fmc');
  const [hostname, setHostname] = useState('');
  const [username, setUsername] = useState('');
  const [apiKey, setApiKey] = useState('');
  const inputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (loading) return; 
    if (e.type === "dragenter" || e.type === "dragover") setDragActive(true);
    else if (e.type === "dragleave") setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (loading) return; 
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onFileUpload(Array.from(e.dataTransfer.files));
    }
  };

  const handleChange = (e) => {
    if (loading) return; 
    if (e.target.files && e.target.files.length > 0) {
      onFileUpload(Array.from(e.target.files));
    }
  };

  return (
    <div className="flex flex-col bg-[#121212] border border-gray-800 rounded-lg overflow-hidden shrink-0">
      <div className="flex border-b border-gray-800 bg-[#0a0a0a]">
        {!isConnected && (
          <button 
            onClick={() => setActiveTab(0)}
            disabled={loading}
            className={`flex-1 py-2 text-[10px] font-bold uppercase tracking-widest transition-colors ${
              activeTab === 0 ? 'text-blue-500 bg-blue-500/5' : 'text-gray-500 hover:text-gray-300'
            } ${loading ? 'cursor-not-allowed opacity-50' : ''}`}
          >
            Upload Files
          </button>
        )}
        <button 
          onClick={() => setActiveTab(1)}
          disabled={loading}
          className={`flex-1 py-2 text-[10px] font-bold uppercase tracking-widest transition-colors ${
            activeTab === 1 || isConnected ? 'text-blue-500 bg-blue-500/5' : 'text-gray-500 hover:text-gray-300'
          } ${loading ? 'cursor-not-allowed opacity-50' : ''}`}
        >
          {isConnected ? 'Connected Device' : 'Import from Device'}
        </button>
      </div>

      <div className="p-3">
        {activeTab === 0 && !isConnected ? (
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => inputRef.current?.click()}
            className={`
              h-32 border-2 border-dashed rounded-lg flex flex-col items-center justify-center text-center transition-all
              ${loading ? 'cursor-not-allowed opacity-50 border-gray-700' : 'cursor-pointer'}
              ${dragActive && !loading ? 'border-green-500 bg-green-500/5' : 'border-gray-700 hover:border-gray-500 bg-[#0a0a0a]'}
            `}
          >
            <input type="file" ref={inputRef} className="hidden" onChange={handleChange} multiple disabled={loading} />
            {loading ? (
              <Loader2 size={24} className="animate-spin text-green-500 mb-2" />
            ) : (
              <Upload size={24} className={`mb-2 ${dragActive ? 'text-green-500' : 'text-gray-500'}`} />
            )}
            <div className="text-[11px] font-bold text-gray-300 uppercase tracking-tight">Drop config files here</div>
            <div className="text-[9px] text-gray-500 mt-1">Supports .txt, .cfg, .json</div>
          </div>
        ) : isConnected ? (
          <div className="space-y-3 py-2">
            <div className="flex items-center gap-3 p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
              <div className="w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center text-green-500">
                <CheckCircle2 size={18} />
              </div>
              <div className="flex-1 overflow-hidden">
                <div className="text-[10px] font-bold text-green-500 uppercase">Device Connected</div>
                <div className="text-[11px] text-gray-300 truncate font-mono">{deviceHostname}</div>
              </div>
            </div>
            <div className="flex gap-2">
              <button 
                onClick={onDisconnect}
                disabled={loading}
                className="flex-1 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[9px] font-bold uppercase transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <LogOut size={12} /> Change Device
              </button>
              <button 
                onClick={onReconnect}
                disabled={loading}
                className="flex-1 py-2 bg-[#1a1a1a] border border-gray-700 hover:bg-gray-800 text-gray-300 rounded text-[9px] font-bold uppercase transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 size={12} className="animate-spin" /> : <RefreshCcw size={12} />} Reconnect
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="space-y-1">
              <label className="text-[9px] font-bold text-gray-500 uppercase">Device Type</label>
              <select 
                value={deviceType}
                onChange={(e) => setDeviceType(e.target.value)}
                disabled={loading}
                className="w-full bg-black border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <option value="cisco-fmc">Cisco FMC</option>
                <option value="palo-alto-panorama">Palo Alto Panorama</option>
                <option value="fortigate">FortiGate</option>
              </select>
            </div>
            <input 
              placeholder="Hostname/IP"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              disabled={loading}
              className="w-full bg-black border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <div className="flex gap-2">
              <input 
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
                className="flex-1 bg-black border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <input 
                type="password"
                placeholder="API Key"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                disabled={loading}
                className="flex-1 bg-black border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>
            {error && (
              <div className="p-2 bg-red-900/20 border border-red-500/30 rounded flex items-start gap-2">
                <AlertTriangle size={12} className="text-red-500 shrink-0 mt-0.5" />
                <span className="text-[10px] text-red-400 leading-tight">{error}</span>
              </div>
            )}
            <button 
              onClick={() => onApiIngest(deviceType, hostname, username, apiKey)}
              disabled={loading}
              className="w-full bg-green-600 hover:bg-green-500 text-black py-2 rounded text-[11px] font-bold uppercase transition-colors flex items-center justify-center gap-2 disabled:bg-gray-800 disabled:text-gray-500 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Globe size={14} />}
              Connect & Import
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

const FileItem = ({ file, isActive, isLoading, metadata, onSelect, onRemove }) => {
  const meta = metadata[file.name];
  return (
    <div
      onClick={() => onSelect(file)}
      className={`p-2 rounded flex flex-col cursor-pointer border transition-all ${
        isActive ? 'bg-gray-800 border-gray-600 shadow-sm' : 'border-transparent hover:bg-gray-900'
      }`}
    >
      <div className="flex items-center justify-between w-full">
        <div className="flex items-center gap-2 truncate text-gray-300">
          {isLoading ? <Loader2 size={12} className="animate-spin text-blue-500" /> : <FileIcon size={12} className={isActive ? "text-blue-400" : "text-gray-500"} />}
          <span className={`truncate text-[11px] font-medium ${isActive ? 'text-white' : ''}`}>{file.name}</span>
        </div>
        <button onClick={(e) => { e.stopPropagation(); onRemove(file.id); }} className="text-gray-600 hover:text-red-500 p-0.5"><X size={12} /></button>
      </div>
      <div className="mt-1 flex gap-1.5 flex-wrap">
        {meta ? (
          <>
            <span className="text-[8px] px-1 bg-blue-500/20 text-blue-400 rounded border border-blue-500/30 font-bold uppercase">{meta.vendor}</span>
            <span className="text-[8px] px-1 bg-gray-700/50 text-gray-400 rounded border border-gray-600/50 font-mono">{meta.os} {meta.version}</span>
          </>
        ) : (
          <span className="text-[8px] px-1 bg-gray-700/30 text-gray-500 rounded border border-gray-600/30 font-bold italic">?</span>
        )}
      </div>
    </div>
  );
};

const FilePreviewer = ({ selectedFile }) => {
  const lines = (selectedFile?.content || '').split('\n');
  const codeRef = useRef(null);
  const lineNumbersRef = useRef(null);

  const handleScroll = (event) => {
    if (codeRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = event.target.scrollTop;
    }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-200">
      <div className="p-4 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center shrink-0">
        <h3 className="text-sm font-bold text-white flex items-center gap-2"><Code size={16} className="text-gray-400" /> {selectedFile.name}</h3>
        <span className="text-xs text-gray-500 bg-black px-2 py-1 rounded border border-gray-800 font-mono">{(selectedFile.size / 1024).toFixed(1)} KB</span>
      </div>
      <div className="flex-1 flex bg-[#050505] relative overflow-hidden"> 
        <div ref={lineNumbersRef} className="py-6 pl-4 pr-3 border-r border-gray-800 bg-[#0a0a0a] text-right select-none shrink-0 overflow-hidden">
            {lines.map((_, i) => (
                <div key={i} className="text-[12px] font-mono text-gray-600 leading-relaxed h-5">{i + 1}</div>
            ))}
        </div>
        <div ref={codeRef} className="flex-1 p-6 overflow-auto custom-scrollbar" onScroll={handleScroll}>
            <pre className="text-[12px] font-mono text-gray-300 leading-relaxed whitespace-pre min-w-max">
                {lines.map((line, i) => (
                    <div key={i} className="h-5">{line || ' '}</div>
                ))}
            </pre>
        </div>
      </div>
    </div>
  );
};

const PolicyBrowser = ({ policies, selectedIds, onToggleAll, onToggleOne, onPreview, previewData, previewLoadingId, hostname, loading }) => {
    const [focusedPolicy, setFocusedPolicy] = useState(null);

    const handleRowClick = (policy) => {
        setFocusedPolicy(policy);
        if (!previewData[policy.id]) {
            onPreview(policy);
        }
    };

    // Helper to parse rules string into array of objects for table
    const parseRules = (text) => {
        if (!text) return [];
        const lines = text.split('\n');
        const rules = [];
        let currentRule = null;

        lines.forEach(line => {
            if (line.startsWith('Rule: ')) {
                if (currentRule) rules.push(currentRule);
                const namePart = line.substring(6).split(' (')[0].trim();
                currentRule = { name: namePart, action: '', from: '', to: '', ports: '' };
            } else if (currentRule && line.trim().startsWith('Action: ')) {
                currentRule.action = line.trim().substring(8).trim();
            } else if (currentRule && line.trim().startsWith('Source: ')) {
                currentRule.from = line.trim().substring(8).trim();
            } else if (currentRule && line.trim().startsWith('Destination: ')) {
                currentRule.to = line.trim().substring(13).trim();
            } else if (currentRule && line.trim().startsWith('Ports: ')) {
                currentRule.ports = line.trim().substring(7).trim();
            }
        });
        if (currentRule) rules.push(currentRule);
        
        return rules;
    };

    const previewRules = focusedPolicy ? parseRules(previewData[focusedPolicy.id]) : [];

    return (
        <div className="flex-1 flex flex-col bg-[#050505] animate-in fade-in duration-300 overflow-hidden">
            {/* Header Area */}
            <div className="p-6 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-end shrink-0">
                <div>
                    <h2 className="text-xl font-black text-white mb-1 flex items-center gap-3">
                        <Server className="text-blue-500" size={24} /> 
                        POLICY DISCOVERY
                    </h2>
                    <p className="text-[11px] text-gray-500 font-mono flex items-center gap-2">
                        Connected Host: <span className="text-gray-300">{hostname}</span> 
                        <span className="text-gray-700">|</span> 
                        Discovered: <span className="text-blue-400 font-bold">{policies.length}</span>
                    </p>
                </div>
                <div className="text-[10px] text-gray-500 font-bold uppercase tracking-widest italic">
                    Alpha Version 0.1.0
                </div>
            </div>

            {/* Master-Detail Split */}
            <div className="flex-1 flex min-h-0">
                {/* Left: Policy List (Narrower) */}
                <div className="w-[320px] flex flex-col border-r border-gray-800 h-full overflow-hidden bg-[#0d0d0d]">
                    <div className="px-4 py-3 border-b border-gray-800 bg-[#0a0a0a] flex items-center shrink-0">
                        <button onClick={onToggleAll} disabled={loading} className="p-1 hover:text-white text-gray-500 mr-3 transition-colors disabled:opacity-50">
                            {selectedIds.size === policies.length && policies.length > 0 ? <CheckSquare size={14} className="text-blue-500" /> : <Square size={14} />}
                        </button>
                        <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest flex-1">Policies</span>
                    </div>
                    
                    <div className="flex-1 overflow-y-auto p-2 custom-scrollbar">
                        {policies.map(policy => {
                            const isSelected = selectedIds.has(policy.id);
                            const isFocused = focusedPolicy?.id === policy.id;
                            
                            return (
                                <div 
                                    key={policy.id}
                                    onClick={() => handleRowClick(policy)}
                                    className={`flex items-center px-3 py-2 mb-1 rounded cursor-pointer border transition-all ${
                                        isFocused ? 'bg-blue-500/10 border-blue-500/30 shadow-sm shadow-blue-500/5' : 'bg-[#121212] border-transparent hover:border-gray-700'
                                    }`}
                                >
                                    <button 
                                        onClick={(e) => { e.stopPropagation(); onToggleOne(policy.id); }} 
                                        disabled={loading}
                                        className="p-1 hover:text-white text-gray-500 mr-2 transition-colors disabled:opacity-50"
                                    >
                                        {isSelected ? <CheckSquare size={14} className="text-blue-500" /> : <Square size={14} />}
                                    </button>
                                    <div className="flex-1 min-w-0">
                                        <div className={`text-xs font-medium truncate ${isFocused ? 'text-white' : 'text-gray-300'}`}>{policy.name}</div>
                                        <div className="text-[9px] text-gray-600 font-mono truncate">{policy.id}</div>
                                    </div>
                                    <div className="ml-2">
                                        {previewLoadingId === policy.id ? (
                                            <Loader2 size={12} className="animate-spin text-blue-500" />
                                        ) : (
                                            <ChevronRight size={14} className={isFocused ? "text-blue-500" : "text-gray-700"} />
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* Right: Detail Table Pane */}
                <div className="flex-1 flex flex-col h-full bg-[#050505] min-w-0">
                    {focusedPolicy ? (
                        <>
                            <div className="px-6 py-3 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center shrink-0">
                                <h3 className="text-[11px] font-bold text-gray-300 flex items-center gap-2 uppercase tracking-tight">
                                    <ListFilter size={14} className="text-blue-500" /> Policy Rules: {focusedPolicy.name}
                                </h3>
                                <div className="text-[9px] text-gray-500 font-mono">
                                    {previewRules.length} Entries Loaded
                                </div>
                            </div>
                            <div className="flex-1 overflow-auto custom-scrollbar">
                                {previewLoadingId === focusedPolicy.id ? (
                                    <div className="h-full flex flex-col items-center justify-center text-gray-500 space-y-3">
                                        <Loader2 size={24} className="animate-spin text-blue-500" />
                                        <span className="text-xs font-mono">Parsing normalized data...</span>
                                    </div>
                                ) : previewRules.length > 0 ? (
                                    <table className="w-full border-collapse">
                                        <thead className="sticky top-0 bg-[#0a0a0a] z-10 border-b border-gray-800 shadow-sm">
                                            <tr>
                                                <th className="px-4 py-2 text-left text-[9px] font-bold text-gray-500 uppercase">Name</th>
                                                <th className="px-4 py-2 text-left text-[9px] font-bold text-gray-500 uppercase w-20">Action</th>
                                                <th className="px-4 py-2 text-left text-[9px] font-bold text-gray-500 uppercase">Source</th>
                                                <th className="px-4 py-2 text-left text-[9px] font-bold text-gray-500 uppercase">Destination</th>
                                                <th className="px-4 py-2 text-left text-[9px] font-bold text-gray-500 uppercase">Ports</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-800/50">
                                            {previewRules.map((rule, idx) => (
                                                <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                    <td className="px-4 py-2 text-[10px] font-medium text-gray-300 truncate max-w-[200px]">{rule.name}</td>
                                                    <td className="px-4 py-2">
                                                        <span className={`px-1.5 py-0.5 rounded-[3px] text-[8px] font-bold uppercase ${
                                                            rule.action === 'Allow' ? 'bg-green-500/10 text-green-500 border border-green-500/20' : 'bg-red-500/10 text-red-500 border border-red-500/20'
                                                        }`}>
                                                            {rule.action}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-2 text-[10px] text-gray-500 font-mono truncate max-w-[150px]">{rule.from}</td>
                                                    <td className="px-4 py-2 text-[10px] text-gray-500 font-mono truncate max-w-[150px]">{rule.to}</td>
                                                    <td className="px-4 py-2 text-[10px] text-gray-400 font-mono truncate max-w-[120px]">{rule.ports}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                ) : (
                                    <div className="h-full flex items-center justify-center text-gray-600 text-xs italic">
                                        No preview data available for this policy.
                                    </div>
                                )}
                            </div>
                        </>
                    ) : (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-600 p-8 text-center space-y-4">
                            <ShieldCheck size={48} className="text-gray-800" />
                            <div>
                                <div className="text-sm font-bold text-gray-400 mb-1">Select a policy from the list</div>
                                <div className="text-xs max-w-xs mx-auto text-gray-500">The rules will be displayed here in a structured table format for your review.</div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

// --- REMEDIATION WORKSPACE COMPONENT ---

const RemediationWorkspace = ({ issue, onDownload }) => {
    const [editableCode, setEditableCode] = useState(issue.proposedCode);
    const originLines = (issue.originalCode || '').split('\n');
    const remediatedLines = editableCode.split('\n');
    
    const leftLineNumbersRef = useRef(null);
    const rightLineNumbersRef = useRef(null);
    const leftCodeRef = useRef(null);
    const rightCodeRef = useRef(null);

    const syncScroll = (sourceRef, targetRef) => {
        if (targetRef.current && sourceRef.current) {
            targetRef.current.scrollTop = sourceRef.current.scrollTop;
        }
    };
    
    useEffect(() => {
        setEditableCode(issue.proposedCode);
    }, [issue]);

    const handleDownload = () => {
        onDownload(issue.file || 'remediation.cfg', editableCode);
    };

    return (
        <div className="flex flex-col h-full animate-in fade-in duration-300">
            {/* HEADER */}
            <div className="p-4 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center shrink-0">
                <div className="flex items-center gap-3">
                    <Terminal size={16} className="text-blue-500" />
                    <div>
                        <h3 className="text-sm font-bold text-white leading-tight">{issue.title}</h3>
                        <div className="text-[10px] text-gray-500 font-mono mt-0.5">{issue.file}</div>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <SeverityBadge severity={issue.severity} />
                    <button 
                        onClick={handleDownload}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-[10px] font-bold uppercase transition-colors"
                    >
                        <Download size={12} /> Download
                    </button>
                </div>
            </div>

            {/* DESCRIPTION & STRATEGY */}
            <div className="p-6 border-b border-gray-800 bg-[#0d0d0d] shrink-0">
                <div className="grid grid-cols-2 gap-8">
                    <div>
                        <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5"><ShieldAlert size={12} className="text-red-500" /> Issue Context</h4>
                        <p className="text-xs text-gray-400 leading-relaxed">{issue.description}</p>
                    </div>
                    <div>
                        <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5"><ShieldCheck size={12} className="text-green-500" /> Remediation Strategy</h4>
                        <p className="text-xs text-gray-400 leading-relaxed">{issue.strategy}</p>
                    </div>
                </div>
            </div>

            {/* SPLIT PANE EDITOR */}
            <div className="flex-1 flex min-h-0 bg-[#050505] overflow-hidden">
                {/* ORIGINAL (Left) */}
                <div className="w-1/2 flex flex-col border-r border-gray-800 h-full overflow-hidden">
                    <div className="px-4 py-2 border-b border-gray-800 bg-[#0a0a0a] flex items-center justify-between shrink-0">
                        <span className="text-[9px] font-bold text-gray-500 uppercase tracking-tighter flex items-center gap-1.5"><FileText size={12}/> Original Config</span>
                    </div>
                    <div className="flex-1 flex overflow-hidden min-h-0">
                         <div ref={leftLineNumbersRef} className="py-4 pl-4 pr-3 border-r border-gray-800 bg-[#0a0a0a] text-right select-none shrink-0 overflow-hidden">
                            {originLines.map((_, i) => (
                                <div key={i} className="text-[11px] font-mono text-gray-600 h-5 flex items-center justify-end" style={{ lineHeight: '20px' }}>{i + 1}</div>
                            ))}
                        </div>
                        <div 
                            ref={leftCodeRef}
                            onScroll={() => syncScroll(leftCodeRef, leftLineNumbersRef)}
                            className="flex-1 overflow-auto custom-scrollbar p-4"
                        >
                            <pre className="text-[11px] font-mono text-gray-400 whitespace-pre min-w-max" style={{ lineHeight: '20px' }}>
                                {issue.originalCode || 'No original source segment available.'}
                            </pre>
                        </div>
                    </div>
                </div>

                {/* REMEDIATION (Right) - Editable */}
                <div className="w-1/2 flex flex-col h-full overflow-hidden">
                    <div className="px-4 py-2 border-b border-gray-800 bg-[#0a0a0a] flex items-center justify-between shrink-0">
                        <span className="text-[9px] font-bold text-blue-400 uppercase tracking-tighter flex items-center gap-1.5"><Edit3 size={12}/> Hardened Version</span>
                        <span className="text-[8px] text-gray-600 italic">User Editable</span>
                    </div>
                    <div className="flex-1 flex overflow-hidden min-h-0">
                        <div ref={rightLineNumbersRef} className="py-4 pl-4 pr-3 border-r border-gray-800 bg-[#0a0a0a] text-right select-none shrink-0 overflow-hidden">
                            {remediatedLines.map((_, i) => (
                                <div key={i} className="text-[11px] font-mono text-gray-600 h-5 flex items-center justify-end" style={{ lineHeight: '20px' }}>{i + 1}</div>
                            ))}
                        </div>
                        <textarea 
                            ref={rightCodeRef}
                            value={editableCode}
                            onChange={(e) => setEditableCode(e.target.value)}
                            onScroll={() => syncScroll(rightCodeRef, rightLineNumbersRef)}
                            spellCheck={false}
                            className="flex-1 bg-transparent p-4 text-[11px] font-mono text-green-400 resize-none focus:outline-none overflow-auto custom-scrollbar h-full min-w-0"
                            style={{ lineHeight: '20px', whiteSpace: 'pre' }}
                        />
                    </div>
                </div>
            </div>
        </div>
    );
};

// --- MAIN COMPONENT ---

const SecurityAudit = () => {
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [analysisStatus, setAnalysisStatus] = useState('idle'); // idle | analyzing | complete
  const [selectedFramework, setSelectedFramework] = useState(FRAMEWORKS[0]);
  const [issues, setIssues] = useState([]);
  const [fileMetadata, setFileMetadata] = useState({});
  const [availablePolicies, setAvailablePolicies] = useState([]);
  const [selectedPolicyIds, setSelectedPolicyIds] = useState(new Set());
  const [policyPreviews, setPolicyPreviews] = useState({}); 
  const [previewLoadingId, setPreviewLoadingId] = useState(null);
  const [ingestError, setIngestError] = useState(null);
  const [connectionInfo, setConnectionInfo] = useState(null);

  const handleFileUpload = (files) => {
    files.forEach((file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result;
        const fileObj = {
          id: Math.random().toString(36).substr(2, 9),
          name: file.name,
          size: file.size,
          content: content,
          rawFile: file
        };
        setUploadedFiles(prev => {
          if (prev.length === 0) {
              setSelectedFile(fileObj);
          }
          return [...prev, fileObj];
        });
      };
      reader.readAsText(file);
    });
  };

  const handleApiIngest = async (deviceType, hostname, username, apiKey) => {
    setAnalysisStatus('analyzing');
    setIngestError(null);
    
    try {
      let vendor = deviceType === 'cisco-fmc' ? 'cisco' : deviceType;
      
      const policyRes = await fetch('/analyzer/v1/fetch/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vendor: vendor,
          host: hostname,
          username: username,
          password: apiKey,
          verify_ssl: false
        })
      });
      
      const policyData = await policyRes.json();
      if (!policyRes.ok) throw new Error(policyData.detail || policyData.message || "Failed to fetch policies");
      
      if (!policyData.policies || policyData.policies.length === 0) {
          throw new Error("No access policies found on the device.");
      }
      
      setAvailablePolicies(policyData.policies);
      setSelectedPolicyIds(new Set()); // Reset selection
      setConnectionInfo({ vendor, hostname, username, apiKey });
      setPolicyPreviews({}); // clear previews for new connection
      setSelectedFile(null);
      setSelectedIssue(null);
      
    } catch (err) {
       console.error("Ingest Error:", err);
       setIngestError(err.message);
    } finally {
       setAnalysisStatus('idle');
    }
  };

  const fetchPolicyRules = async (policyId) => {
      if (!connectionInfo) return null;
      const { vendor, hostname, username, apiKey } = connectionInfo;
      
      const rulesRes = await fetch('/analyzer/v1/fetch/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vendor: vendor,
          host: hostname,
          username: username,
          password: apiKey,
          verify_ssl: false,
          policy_id: policyId
        })
      });
      
      const rulesData = await rulesRes.json();
      if (!rulesRes.ok) throw new Error(rulesData.detail || rulesData.message || "Failed to fetch rules");
      return rulesData.normalized_configuration;
  };

  const handlePreviewPolicy = async (policy) => {
      if (policyPreviews[policy.id] || !connectionInfo) return;
      
      setPreviewLoadingId(policy.id);
      try {
          const content = await fetchPolicyRules(policy.id);
          setPolicyPreviews(prev => ({...prev, [policy.id]: content}));
      } catch (err) {
          console.error("Preview Fetch Error:", err);
          setPolicyPreviews(prev => ({...prev, [policy.id]: `Error fetching rules: ${err.message}`}));
      } finally {
          setPreviewLoadingId(null);
      }
  };

  const handleTogglePolicyAll = () => {
    if (selectedPolicyIds.size === availablePolicies.length) {
        setSelectedPolicyIds(new Set());
    } else {
        setSelectedPolicyIds(new Set(availablePolicies.map(p => p.id)));
    }
  };

  const handleTogglePolicyOne = (id) => {
    const newSet = new Set(selectedPolicyIds);
    if (newSet.has(id)) newSet.delete(id);
    else newSet.add(id);
    setSelectedPolicyIds(newSet);
  };

  const handleAnalyzeFromDiscovery = async () => {
    const selectedList = availablePolicies.filter(p => selectedPolicyIds.has(p.id));
    if (selectedList.length === 0 || !connectionInfo) return;

    setAnalysisStatus('analyzing');
    setIngestError(null);
    
    try {
        let combinedContent = `================================================================================\n`;
        combinedContent += `FMC CONNECTION: ${connectionInfo.hostname} (${connectionInfo.vendor})\n`;
        combinedContent += `USER: ${connectionInfo.username}\n`;
        combinedContent += `INGESTED ON: ${new Date().toLocaleString()}\n`;
        combinedContent += `================================================================================\n\n`;

        for (const policy of selectedList) {
            let content = policyPreviews[policy.id];
            if (!content) {
                content = await fetchPolicyRules(policy.id);
                setPolicyPreviews(prev => ({...prev, [policy.id]: content}));
            }
            
            combinedContent += `================================================================================\n`;
            combinedContent += `POLICY: ${policy.name}\n`;
            combinedContent += `ID: ${policy.id}\n`;
            combinedContent += `--------------------------------------------------------------------------------\n`;
            combinedContent += `${content}\n\n`;
        }

        const fileName = `${connectionInfo.hostname.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_consolidated_policies.txt`;
        const fileObj = {
            id: Math.random().toString(36).substr(2, 9),
            name: fileName,
            size: combinedContent.length,
            content: combinedContent,
            rawFile: new File([combinedContent], fileName, { type: "text/plain" })
        };

        const allFiles = [...uploadedFiles, fileObj];
        setUploadedFiles(allFiles);
        setSelectedFile(fileObj);
        setAvailablePolicies([]); 
        
        await executeAnalysis(allFiles, selectedFramework);
        
    } catch (err) {
       console.error("Bulk Rule Ingest Error:", err);
       setIngestError(err.message);
       setAnalysisStatus('idle');
    }
  };

  const handleDisconnect = () => {
      setConnectionInfo(null);
      setAvailablePolicies([]);
      setPolicyPreviews({});
      setIngestError(null);
      setSelectedPolicyIds(new Set());
  };

  const handleReconnect = () => {
      if (connectionInfo) {
          const deviceType = connectionInfo.vendor === 'cisco' ? 'cisco-fmc' : connectionInfo.vendor;
          handleApiIngest(deviceType, connectionInfo.hostname, connectionInfo.username, connectionInfo.apiKey);
      }
  };

  const executeAnalysis = async (filesToAnalyze, framework) => {
    setAnalysisStatus('analyzing');
    setIssues([]);
    setSelectedIssue(null);
    setSelectedFile(null); // Clear selected file to show dashboard summary
    
    try {
      const formData = new FormData();
      filesToAnalyze.forEach(file => {
        formData.append('files', file.rawFile);
      });
      formData.append('framework', framework);

      const response = await fetch('/analyzer/v1/configs/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Analysis failed with status: ${response.status} | ${errorText}`);
      }

      const rawData = await response.json();
      
      if (rawData.status === "error") {
        throw new Error(rawData.message || "Unknown analysis error");
      }

      const rawAiText = rawData.analysis;
      let parsedAnalysis;
      try {
        const cleanJson = rawAiText.replace(/^```json\n?/, '').replace(/\n?```$/, '').trim();
        parsedAnalysis = JSON.parse(cleanJson);
      } catch (e) {
        const match = rawAiText.match(/(\{.*\})/s);
        if (match) parsedAnalysis = JSON.parse(match[1]);
        else throw new Error("AI core returned invalid JSON structure.");
      }

      const { file_metadata, issues: aiIssues } = parsedAnalysis;

      if (file_metadata && Array.isArray(file_metadata)) {
        const newMetadata = {};
        file_metadata.forEach(meta => {
          newMetadata[meta.file] = {
            vendor: meta.vendor,
            os: meta.os,
            version: meta.version
          };
        });
        setFileMetadata(prev => ({ ...prev, ...newMetadata }));
      }

      const mappedIssues = (aiIssues || []).map((issue, index) => {
        const displayId = `ISSUE-${(index + 1).toString().padStart(2, '0')}`;
        return {
          id: issue.id || `ai-${index}`,
          displayId: displayId,
          title: issue.title || "Security Finding",
          severity: issue.severity || "Medium",
          description: issue.description || "No description provided.",
          strategy: issue.strategy || "Consult security documentation.",
          originalCode: issue.originalCode || "",
          proposedCode: issue.proposedCode || "",
          file: issue.file || "multiple"
        };
      });

      setIssues(mappedIssues);
      setAnalysisStatus('complete');
      
    } catch (error) {
      console.error("Analysis Error:", error);
      setAnalysisStatus('idle');
    }
  };

  const startAnalysis = () => {
    if (uploadedFiles.length === 0) return;
    executeAnalysis(uploadedFiles, selectedFramework);
  };

  const handleIssueClick = (issue) => {
    setSelectedIssue(issue);
    setSelectedFile(null);
    setAvailablePolicies([]);
  };

  const handleDownloadRemediation = (filename, content) => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `remediated-${filename}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDownloadFullReport = () => {
    if (issues.length === 0) return;

    let markdown = `# Security Audit Report\n\n`;
    markdown += `**Framework:** ${selectedFramework}\n`;
    markdown += `**Date:** ${new Date().toLocaleString()}\n`;
    markdown += `**Total Issues:** ${issues.length}\n\n`;

    markdown += `## Summary\n\n`;
    markdown += `- **High:** ${issues.filter(i => i.severity === 'High').length}\n`;
    markdown += `- **Medium:** ${issues.filter(i => i.severity === 'Medium').length}\n`;
    markdown += `- **Low:** ${issues.filter(i => i.severity === 'Low').length}\n\n`;

    markdown += `--- \n\n`;

    issues.forEach((issue, index) => {
      markdown += `### ${index + 1}. ${issue.title} [${issue.severity}]\n\n`;
      markdown += `**File:** ${issue.file}\n\n`;
      markdown += `#### Description\n${issue.description}\n\n`;
      markdown += `#### Remediation Strategy\n${issue.strategy}\n\n`;
      if (issue.originalCode) {
        markdown += `#### Original Config\n\`\`\`\n${issue.originalCode}\n\`\`\`\n\n`;
      }
      if (issue.proposedCode) {
        markdown += `#### Proposed Remediation\n\`\`\`\n${issue.proposedCode}\n\`\`\`\n\n`;
      }
      markdown += `---\n\n`;
    });

    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-audit-report.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const removeFile = (id) => {
    setUploadedFiles(prev => {
      const updated = prev.filter(f => f.id !== id);
      if (selectedFile?.id === id) setSelectedFile(updated[0] || null);
      return updated;
    });
    if (uploadedFiles.length <= 1) {
      setAnalysisStatus('idle');
      setIssues([]);
      setFileMetadata({});
    }
  };

  // Determine if we should show the Execute Audit controls in sidebar
  const showAuditControls = uploadedFiles.length > 0 || availablePolicies.length > 0;
  const isDiscoveryMode = availablePolicies.length > 0 && !selectedFile && !selectedIssue;

  return (
    <div className="flex flex-1 gap-4 overflow-hidden h-full animate-in fade-in slide-in-from-bottom-2 duration-300">
      {/* LEFT COLUMN: Controls & Files */}
      <div className="w-1/4 flex flex-col gap-4 min-h-0">
        <IngestionTabs 
          onFileUpload={handleFileUpload}
          onApiIngest={handleApiIngest}
          loading={analysisStatus === 'analyzing'}
          error={ingestError}
          isConnected={!!connectionInfo}
          deviceHostname={connectionInfo?.hostname}
          onDisconnect={handleDisconnect}
          onReconnect={handleReconnect}
        />

        <div className="flex-1 flex flex-col bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden min-h-0">
          <div className="p-3 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center">
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <Database size={14} className="text-blue-500" /> Repository
            </span>
            <span className="text-[9px] font-mono text-gray-600">{uploadedFiles.length} Objects</span>
          </div>
          
          <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
            {uploadedFiles.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-gray-600 text-[11px] p-6 text-center italic opacity-50">
                    No configurations loaded.
                </div>
            ) : (
                uploadedFiles.map(file => (
                    <FileItem
                        key={file.id}
                        file={file}
                        isActive={(selectedFile?.id === file.id)}
                        metadata={fileMetadata}
                        onSelect={(f) => { setSelectedIssue(null); setSelectedFile(f); setAvailablePolicies([]); }}
                        onRemove={removeFile}
                    />
                ))
            )}
          </div>

          {showAuditControls && (
            <div className="p-3 border-t border-gray-800 bg-[#0a0a0a] space-y-3">
              <div className="space-y-1">
                <label className="text-[9px] font-bold text-gray-500 uppercase flex items-center gap-1.5"><Settings size={12}/> Policy Framework</label>
                <select 
                  value={selectedFramework}
                  onChange={(e) => setSelectedFramework(e.target.value)}
                  disabled={analysisStatus === 'analyzing'}
                  className="w-full bg-black border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {FRAMEWORKS.map(fw => <option key={fw} value={fw}>{fw}</option>)}
                </select>
              </div>
              
              {isDiscoveryMode ? (
                <button 
                  onClick={handleAnalyzeFromDiscovery} 
                  disabled={analysisStatus === 'analyzing' || selectedPolicyIds.size === 0}
                  className={`w-full py-2.5 rounded text-[11px] font-bold uppercase transition-all flex items-center justify-center gap-2 ${
                    analysisStatus === 'analyzing' || selectedPolicyIds.size === 0
                    ? 'bg-gray-800 text-gray-500 cursor-not-allowed' 
                    : 'bg-green-600 hover:bg-green-500 text-black shadow-lg shadow-green-900/20'
                  }`}
                >
                  {analysisStatus === 'analyzing' ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                  Analyze Selected ({selectedPolicyIds.size})
                </button>
              ) : (
                <button 
                  onClick={startAnalysis} 
                  disabled={analysisStatus === 'analyzing' || uploadedFiles.length === 0}
                  className={`w-full py-2.5 rounded text-[11px] font-bold uppercase transition-all flex items-center justify-center gap-2 ${
                    analysisStatus === 'analyzing' || uploadedFiles.length === 0
                    ? 'bg-gray-800 text-gray-500 cursor-not-allowed' 
                    : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/20'
                  }`}
                >
                  {analysisStatus === 'analyzing' ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                  Analyze Files
                </button>
              )}
            </div>
          )}
        </div>

        {/* ISSUE LISTING (Miniature) */}
        {analysisStatus === 'complete' && (
          <div className="h-1/3 flex flex-col bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden shrink-0">
            <div className="p-3 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center">
              <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
                <ShieldAlert size={14} className="text-red-500" /> Findings ({issues.length})
              </span>
              <button 
                onClick={handleDownloadFullReport}
                className="p-1 hover:text-blue-400 text-gray-500 transition-colors"
                title="Download Report"
              >
                <Download size={14} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
              {issues.map(issue => (
                <div 
                  key={issue.id} 
                  onClick={() => handleIssueClick(issue)}
                  className={`p-2 rounded cursor-pointer border transition-all ${selectedIssue?.id === issue.id ? 'bg-red-500/10 border-red-500/50 shadow-sm' : 'bg-black border-gray-800 hover:border-gray-700'}`}
                >
                   <div className="flex justify-between items-center mb-1"><SeverityBadge severity={issue.severity} /></div>
                   <div className={`text-[11px] font-medium truncate ${selectedIssue?.id === issue.id ? 'text-white' : 'text-gray-300'}`}>{issue.title}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* RIGHT COLUMN: Workspace */}
      <div className="flex-1 flex flex-col bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden h-full">
        {isDiscoveryMode ? (
            <PolicyBrowser 
                policies={availablePolicies} 
                selectedIds={selectedPolicyIds}
                onToggleAll={handleTogglePolicyAll}
                onToggleOne={handleTogglePolicyOne}
                onPreview={handlePreviewPolicy}
                previewData={policyPreviews}
                previewLoadingId={previewLoadingId}
                hostname={connectionInfo?.hostname}
                loading={analysisStatus === 'analyzing'}
            />
        ) : selectedIssue ? (
          <RemediationWorkspace 
            issue={selectedIssue} 
            onDownload={handleDownloadRemediation}
          />
        ) : selectedFile ? (
          <FilePreviewer selectedFile={selectedFile} />
        ) : (
          <div className="flex-1 flex flex-col p-8 overflow-y-auto custom-scrollbar">
            <div className="max-w-3xl">
                <h2 className="text-2xl font-black text-white mb-2 flex items-center gap-3">
                    <ShieldCheck className="text-green-500" size={32} /> 
                    SECURITY AUDIT PIPELINE
                </h2>
                <p className="text-sm text-gray-400 mb-10 leading-relaxed">
                    Automated security auditing for multi-vendor network configurations. Our AI-driven engine identifies vulnerabilities, 
                    misconfigurations, and compliance gaps against industry standards.
                </p>
                
                <div className="grid grid-cols-2 gap-4 mb-10">
                    <MetricCard label="Active Workspace" value={uploadedFiles.length > 0 ? `${uploadedFiles.length} Configs` : 'Empty'} icon={FileText} color="#3b82f6" />
                    <MetricCard label="AI Core Status" value="Operational" icon={Cpu} color="#00D065" />
                </div>

                {analysisStatus === 'complete' && (
                    <div className="space-y-6">
                        <div className="grid grid-cols-3 gap-4 animate-in fade-in slide-in-from-top-4 duration-500">
                            <div className="bg-[#0a0a0a] p-4 rounded-lg border border-red-900/30 flex flex-col">
                                <span className="text-[9px] font-bold text-red-500 uppercase mb-1">Critical/High</span>
                                <span className="text-3xl font-black text-white">{issues.filter(i=>i.severity==='High').length}</span>
                            </div>
                            <div className="bg-[#0a0a0a] p-4 rounded-lg border border-orange-900/30 flex flex-col">
                                <span className="text-[9px] font-bold text-orange-500 uppercase mb-1">Medium Risk</span>
                                <span className="text-3xl font-black text-white">{issues.filter(i=>i.severity==='Medium').length}</span>
                            </div>
                            <div className="bg-[#0a0a0a] p-4 rounded-lg border border-green-900/30 flex flex-col">
                                <span className="text-[9px] font-bold text-green-500 uppercase mb-1">Compliant</span>
                                <span className="text-3xl font-black text-white">{issues.filter(i=>i.severity==='Low').length}</span>
                            </div>
                        </div>
                        <button 
                            onClick={handleDownloadFullReport}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-[11px] font-bold uppercase transition-all w-full justify-center"
                        >
                            <Download size={14} /> Download Full Audit Report (.md)
                        </button>
                    </div>
                )}

                {analysisStatus === 'idle' && (
                    <div className="mt-10 p-6 border border-gray-800 rounded-lg bg-gray-900/20">
                        <h4 className="text-sm font-bold text-gray-300 mb-4 flex items-center gap-2"><Activity size={16} className="text-blue-500" /> Getting Started</h4>
                        <div className="space-y-4">
                            <div className="flex items-start gap-3">
                                <div className="w-5 h-5 rounded-full bg-blue-600 text-black flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">1</div>
                                <p className="text-xs text-gray-400">Upload your device configurations (Cisco, Palo Alto, Fortinet) using the Repository panel.</p>
                            </div>
                            <div className="flex items-start gap-3">
                                <div className="w-5 h-5 rounded-full bg-blue-600 text-black flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">2</div>
                                <p className="text-xs text-gray-400">Select a policy framework (e.g., PCI-DSS, CIS, Default Best Practices).</p>
                            </div>
                            <div className="flex items-start gap-3">
                                <div className="w-5 h-5 rounded-full bg-blue-600 text-black flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">3</div>
                                <p className="text-xs text-gray-400">Click 'Execute Audit' to trigger the AI analysis pipeline.</p>
                            </div>
                        </div>
                    </div>
                )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityAudit;
