import React, { useState } from 'react';
import { Hammer, Sparkles, ShieldCheck, Zap, Server, Shield, ArrowRight, FileText, Loader2 } from 'lucide-react';

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

const PolicyGenerator = ({ addChatMessage }) => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedPolicy, setGeneratedPolicy] = useState(null);

  const handleGenerate = () => {
    setIsGenerating(true);
    addChatMessage("Generating Greenfield hardening policy based on global best practices...", "ai");
    setTimeout(() => {
        setIsGenerating(false);
        setGeneratedPolicy({
            name: "Enterprise-Standard-Hardening-v1",
            rules: 154,
            compliance: ["CIS Benchmark v8", "NIST 800-53", "PCI-DSS 4.0"]
        });
        addChatMessage("Greenfield policy generated successfully. You can now download or apply it to your staging environment.", "ai");
    }, 2000);
  };

  return (
    <div className="flex flex-1 gap-6 overflow-hidden h-full animate-in fade-in slide-in-from-right-4 duration-500">
      {/* LEFT: Configuration Panel */}
      <div className="w-1/3 flex flex-col gap-4">
        <div className="bg-[#121212] border border-gray-800 rounded-lg p-6 shadow-lg">
            <h2 className="text-xl font-black text-white mb-2 flex items-center gap-3">
                <Hammer className="text-blue-500" size={24} /> 
                POLICY BUILDER
            </h2>
            <p className="text-xs text-gray-500 mb-6 uppercase tracking-widest font-bold">Greenfield Deployment Engine</p>
            
            <div className="space-y-4">
                <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Target Architecture</label>
                    <div className="grid grid-cols-2 gap-2">
                        <button className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-md text-white text-xs font-bold flex flex-col items-center gap-2 hover:bg-blue-500/20 transition-all">
                            <Server size={18}/> Standard DC
                        </button>
                        <button className="p-3 bg-black border border-gray-800 rounded-md text-gray-500 text-xs font-bold flex flex-col items-center gap-2 hover:border-gray-600 transition-all">
                            <Zap size={18}/> Cloud Native
                        </button>
                    </div>
                </div>

                <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Compliance Level</label>
                    <select className="w-full bg-black border border-gray-800 rounded-md px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-blue-500 transition-colors">
                        <option>Level 1 (Essential)</option>
                        <option>Level 2 (Corporate)</option>
                        <option>Level 3 (High-Security / Gov)</option>
                    </select>
                </div>

                <div className="space-y-1.5 pt-4">
                    <button 
                        onClick={handleGenerate}
                        disabled={isGenerating}
                        className={`w-full py-3 rounded-md text-[11px] font-black uppercase tracking-[0.1em] transition-all flex items-center justify-center gap-2 ${
                            isGenerating ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-500 text-white shadow-xl shadow-blue-900/20'
                        }`}
                    >
                        {isGenerating ? <Loader2 size={16} className="animate-spin" /> : <Sparkles size={16} />}
                        {isGenerating ? 'Synthesizing...' : 'Generate Hardened Policy'}
                    </button>
                </div>
            </div>
        </div>

        <div className="bg-[#121212] border border-gray-800 rounded-lg p-4 flex-1">
             <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4">Builder Insights</h4>
             <div className="space-y-4">
                <div className="flex gap-3">
                    <div className="w-8 h-8 rounded bg-gray-900 border border-gray-800 flex items-center justify-center shrink-0">
                        <Shield size={16} className="text-green-500" />
                    </div>
                    <div>
                        <div className="text-[11px] font-bold text-gray-200">Zero Trust Default</div>
                        <div className="text-[9px] text-gray-500">All rules follow deny-by-default logic with implicit logging enabled.</div>
                    </div>
                </div>
                <div className="flex gap-3">
                    <div className="w-8 h-8 rounded bg-gray-900 border border-gray-800 flex items-center justify-center shrink-0">
                        <FileText size={16} className="text-blue-500" />
                    </div>
                    <div>
                        <div className="text-[11px] font-bold text-gray-200">CIS Alignment</div>
                        <div className="text-[9px] text-gray-500">Automatically maps to the latest CIS benchmarks for the selected OS.</div>
                    </div>
                </div>
             </div>
        </div>
      </div>

      {/* RIGHT: Preview / Workspace */}
      <div className="flex-1 bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden flex flex-col">
        <div className="p-4 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center">
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
                <ShieldCheck size={16} className="text-green-500" /> Policy Workbench
            </span>
            {generatedPolicy && (
                <div className="flex gap-2">
                    <button className="px-3 py-1 bg-gray-800 border border-gray-700 rounded text-[10px] font-bold text-gray-300 hover:text-white transition-colors">EXPORT JSON</button>
                    <button className="px-3 py-1 bg-green-600 rounded text-[10px] font-bold text-black hover:bg-green-500 transition-colors uppercase">Deploy Policy</button>
                </div>
            )}
        </div>
        
        <div className="flex-1 overflow-y-auto custom-scrollbar p-10 flex flex-col items-center justify-center bg-[#050505]">
            {isGenerating ? (
                <div className="flex flex-col items-center gap-6">
                    <div className="relative">
                        <div className="w-20 h-20 rounded-full border-2 border-blue-500/20 animate-ping absolute"></div>
                        <div className="w-20 h-20 rounded-full border-2 border-blue-500 flex items-center justify-center relative bg-black shadow-[0_0_30px_rgba(59,130,246,0.5)]">
                            <Sparkles size={32} className="text-blue-500 animate-pulse" />
                        </div>
                    </div>
                    <div className="text-center">
                        <h3 className="text-xl font-black text-white mb-1 tracking-widest uppercase italic">Synthesizing Policy</h3>
                        <p className="text-xs text-gray-500">AI is correlating benchmarks with architecture constraints...</p>
                    </div>
                </div>
            ) : generatedPolicy ? (
                <div className="w-full h-full space-y-8 animate-in zoom-in-95 duration-500">
                    <div className="grid grid-cols-3 gap-6">
                        <MetricCard label="Policy Version" value="1.0.4-STABLE" icon={Shield} color="#3b82f6" />
                        <MetricCard label="Enforced Rules" value={generatedPolicy.rules} icon={FileText} color="#00D065" />
                        <MetricCard label="Compliance Score" value="98%" icon={ShieldCheck} color="#a855f7" />
                    </div>

                    <div className="bg-[#0a0a0a] border border-gray-800 rounded-xl overflow-hidden shadow-2xl">
                        <div className="p-4 bg-gray-900/50 border-b border-gray-800 flex justify-between items-center">
                            <span className="text-xs font-bold text-white uppercase tracking-widest">Policy Summary</span>
                            <span className="text-[10px] text-green-500 font-mono">READY_FOR_DEPLOYMENT</span>
                        </div>
                        <div className="p-8 grid grid-cols-2 gap-8">
                            <div className="space-y-4">
                                <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Enforced Frameworks</h4>
                                <div className="flex flex-wrap gap-2">
                                    {generatedPolicy.compliance.map(c => (
                                        <span key={c} className="px-2 py-1 bg-blue-500/10 border border-blue-500/30 text-blue-400 text-[9px] font-black rounded uppercase">{c}</span>
                                    ))}
                                </div>
                            </div>
                            <div className="space-y-4 text-right">
                                <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Last Generated</h4>
                                <div className="text-xs text-gray-300 font-mono">{new Date().toLocaleString()}</div>
                                <div className="text-[10px] text-gray-600">Built by GTT Halo AI Core</div>
                            </div>
                        </div>
                        <div className="p-4 bg-blue-600/5 border-t border-gray-800 flex items-center justify-center gap-4 group cursor-pointer hover:bg-blue-600/10 transition-all">
                            <span className="text-[10px] font-bold text-blue-400 uppercase tracking-[0.2em]">Review Full Semantic Policy Object</span>
                            <ArrowRight size={14} className="text-blue-500 group-hover:translate-x-1 transition-transform" />
                        </div>
                    </div>
                </div>
            ) : (
                <div className="flex flex-col items-center justify-center text-center max-w-sm opacity-30">
                    <Hammer size={64} className="mb-6 text-gray-600" />
                    <h3 className="text-xl font-bold text-gray-500 mb-2">Build Engine Standby</h3>
                    <p className="text-sm text-gray-600">Configure your target environment on the left to start building a hardened policy from scratch.</p>
                </div>
            )}
        </div>
      </div>
    </div>
  );
};

export default PolicyGenerator;
