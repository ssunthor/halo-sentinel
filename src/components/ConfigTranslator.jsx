import React, { useState, useRef } from 'react';
import { FileText, Code, Upload, Settings, ArrowRight, Loader2, Copy, Check, RefreshCw } from 'lucide-react';

// --- EMBEDDED CONSTANTS ---
const VENDORS = [
  'Cisco IOS', 'Juniper Junos', 'Palo Alto PAN-OS', 'Fortinet FortiOS', 'Check Point Gaia'
];

const CrossVendor = () => {
  const [sourceFile, setSourceFile] = useState(null);
  const [translatedConfig, setTranslatedConfig] = useState('');
  const [translationStatus, setTranslationStatus] = useState('idle'); // idle | translating | complete
  const [selectedVendor, setSelectedVendor] = useState(VENDORS[0]);
  const [copied, setCopied] = useState(false);

  const sourceCodeRef = useRef(null);
  const sourceLineNumbersRef = useRef(null);
  const translatedCodeRef = useRef(null);
  const translatedLineNumbersRef = useRef(null);

  const handleSourceScroll = (event) => {
    if (sourceLineNumbersRef.current) {
      sourceLineNumbersRef.current.scrollTop = event.target.scrollTop;
    }
  };

  const handleTranslatedScroll = (event) => {
    if (translatedLineNumbersRef.current) {
      translatedLineNumbersRef.current.scrollTop = event.target.scrollTop;
    }
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      const fileObj = {
        id: Math.random().toString(36).substr(2, 9),
        name: file.name,
        size: file.size,
        content: content,
        rawFile: file
      };
      setSourceFile(fileObj);
      
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const handleTranslate = async () => {
    if (!sourceFile) return;
    setTranslationStatus('translating');
    setTranslatedConfig('');

    try {
      const formData = new FormData();
      formData.append('file', sourceFile.rawFile);
      formData.append('target_vendor', selectedVendor);

      const response = await fetch('/analyzer/v1/configs/translate', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Translation service error: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.status === 'error') {
        throw new Error(data.message || 'Unknown translation error');
      }

      setTranslatedConfig(data.translated_config);
      setTranslationStatus('complete');
      
      
      
      // Update parent state for AI context awareness
      
      
      // Proactively trigger AI to explain the translation if requested
      

    } catch (error) {
      console.error("Translation Error:", error);
      setTranslationStatus('idle');
      
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(translatedConfig);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sourceLines = (sourceFile?.content || '').split('\n');
  const translatedLines = (translatedConfig || '').split('\n');

  return (
    <div className="flex flex-1 gap-4 overflow-hidden h-full animate-in fade-in duration-300">
      {/* SOURCE COLUMN */}
      <div className="w-1/2 flex flex-col gap-4">
        <div className="flex-1 flex flex-col bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden min-h-0">
          <div className="p-3 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center">
            <span className="font-bold text-gray-400 uppercase tracking-widest text-[10px] flex items-center gap-1.5">
                <FileText size={14} className="text-blue-500"/> Source Configuration
            </span>
            {sourceFile && (
                <button 
                    onClick={() => setSourceFile(null)} 
                    className="text-[9px] text-gray-500 hover:text-red-400 font-bold uppercase tracking-tight flex items-center gap-1"
                >
                    <RefreshCw size={10}/> Reset
                </button>
            )}
          </div>
          
          <div className="flex-1 flex bg-[#050505] relative overflow-hidden">
            {sourceFile ? (
              <>
                <div ref={sourceLineNumbersRef} className="py-6 pl-4 pr-3 border-r border-gray-800 bg-[#0a0a0a] text-right select-none shrink-0 overflow-hidden" style={{ height: 'auto' }}>
                    {sourceLines.map((_, i) => (
                        <div key={i} className="text-[12px] font-mono text-gray-600 leading-relaxed h-5">{i + 1}</div>
                    ))}
                </div>
                <div ref={sourceCodeRef} className="flex-1 p-6 overflow-auto custom-scrollbar" onScroll={handleSourceScroll}>
                    <pre className="text-[12px] font-mono text-gray-400 leading-relaxed whitespace-pre min-w-max">
                        {sourceLines.map((line, i) => (
                            <div key={i} className="h-5">{line || ' '}</div>
                        ))}
                    </pre>
                </div>
              </>
            ) : (
              <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center group">
                <div className="w-full max-w-xs border-2 border-dashed border-gray-800 rounded-xl p-10 hover:border-blue-500/50 hover:bg-blue-500/5 transition-all cursor-pointer relative">
                    <Upload size={40} className="mb-4 text-gray-700 mx-auto group-hover:text-blue-500 transition-colors" />
                    <span className="text-sm font-bold text-gray-400 block mb-1">Upload Native Config</span>
                    <span className="text-[10px] text-gray-600 block">Select a configuration file to translate</span>
                    <input type="file" className="absolute inset-0 opacity-0 cursor-pointer" onChange={handleFileUpload} />
                </div>
              </div>
            )}
          </div>

          {sourceFile && (
            <div className="p-4 border-t border-gray-800 bg-[#0a0a0a] flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[9px] font-bold text-gray-500 uppercase tracking-widest flex items-center gap-1.5"><Settings size={12}/> Target Vendor</label>
                    <select 
                        value={selectedVendor}
                        onChange={(e) => setSelectedVendor(e.target.value)}
                        disabled={translationStatus === 'translating'}
                        className="w-full bg-black border border-gray-700 rounded-md px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-blue-500 transition-colors"
                    >
                        {VENDORS.map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                  <div className="flex items-end">
                    <button 
                        onClick={handleTranslate} 
                        disabled={translationStatus === 'translating' || !sourceFile}
                        className={`w-full h-9 ${translationStatus === 'translating' ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/20'} rounded text-xs font-bold flex justify-center items-center gap-2 transition-all`}
                    >
                        {translationStatus === 'translating' ? <Loader2 size={14} className="animate-spin" /> : <ArrowRight size={14} />}
                        {translationStatus === 'translating' ? 'Translating...' : 'Translate'}
                    </button>
                  </div>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* OUTPUT COLUMN */}
      <div className="w-1/2 flex flex-col bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden">
        <div className="p-3 border-b border-gray-800 bg-[#0a0a0a] flex justify-between items-center">
          <span className="font-bold text-gray-400 uppercase tracking-widest text-[10px] flex items-center gap-1.5">
            <Code size={14} className="text-green-500"/> Semantic Mapping Output
          </span>
          {translatedConfig && (
              <button 
                onClick={copyToClipboard}
                className="flex items-center gap-1.5 text-[10px] font-bold uppercase text-gray-500 hover:text-white transition-colors"
              >
                {copied ? <><Check size={12} className="text-green-500"/> Copied</> : <><Copy size={12}/> Copy Code</>}
              </button>
          )}
        </div>
        
        <div className="flex-1 flex bg-[#050505] relative overflow-hidden">
          {translationStatus === 'translating' && (
            <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-black/60 backdrop-blur-sm text-blue-500 gap-3">
              <Loader2 size={32} className="animate-spin" />
              <div className="flex flex-col items-center">
                <span className="text-[10px] font-black tracking-[0.2em] animate-pulse">SEMANTIC TRANSLATION IN PROGRESS</span>
                <span className="text-[9px] text-gray-500 mt-1 uppercase">Generating vendor-specific syntax...</span>
              </div>
            </div>
          )}
          
          {translatedConfig ? (
            <>
              <div ref={translatedLineNumbersRef} className="py-6 pl-4 pr-3 border-r border-gray-800 bg-[#0a0a0a] text-right select-none shrink-0 overflow-hidden" style={{ height: 'auto' }}>
                  {translatedLines.map((_, i) => (
                      <div key={i} className="text-[12px] font-mono text-gray-600 leading-relaxed h-5">{i + 1}</div>
                  ))}
              </div>
              <div ref={translatedCodeRef} className="flex-1 p-6 overflow-auto custom-scrollbar" onScroll={handleTranslatedScroll}>
                  <pre className="text-[12px] font-mono text-green-400/90 leading-relaxed whitespace-pre min-w-max">
                      {translatedLines.map((line, i) => (
                          <div key={i} className="h-5">{line || ' '}</div>
                      ))}
                  </pre>
              </div>
            </>
          ) : translationStatus !== 'translating' && (
            <div className="h-full flex flex-col items-center justify-center text-gray-700 p-10 text-center w-full">
                <div className="w-16 h-16 rounded-full border border-gray-800 flex items-center justify-center mb-4">
                    <Code size={24} className="opacity-20" />
                </div>
                <h4 className="text-xs font-bold text-gray-500 uppercase mb-1">Awaiting Translation</h4>
                <p className="text-[10px] text-gray-600 max-w-[200px]">Upload a source config and select a target vendor to generate mapping.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CrossVendor;
