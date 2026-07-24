import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, X, Send, Bot, User, Loader2, Sparkles, AlertTriangle } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const ChatWidget = ({ dashboardData, isOpen, setIsOpen, messages, setMessages }) => {
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async (e, forcedMessage = null) => {
    if (e) e.preventDefault();
    
    const userMessage = forcedMessage || input.trim();
    if (!userMessage || isLoading) return;

    if (!forcedMessage) setInput('');
    
    // If it's a forced message (system alert), we don't add a 'user' bubble, 
    // we just show the AI's response to the event.
    if (!forcedMessage) {
        setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    }
    
    setIsLoading(true);

    // Extract relevant context for the LLM
    const context = {
        metrics: dashboardData?.metrics,
        threat_level: dashboardData?.threat_score?.score,
        top_anomalies: dashboardData?.anomalies?.top_hosts?.slice(0, 5),
        top_bandwidth: dashboardData?.charts?.top_bandwidth,
        active_users: dashboardData?.metrics?.seen_users,
        active_hosts: dashboardData?.metrics?.seen_hosts,
        recent_netflow_stats: dashboardData?.netflow?.causes
    };

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage, context })
      });

      if (response.ok) {
        const data = await response.json();
        setMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
      } else {
        setMessages(prev => [...prev, { role: 'assistant', content: "Sorry, I encountered an error communicating with the neural core." }]);
      }
    } catch (error) {
      setMessages(prev => [...prev, { role: 'assistant', content: "Connection to Defense Halo AI was interrupted." }]);
    } finally {
      setIsLoading(false);
    }
  };

  // Expose handleSend via a ref or a simple trick: watch for a special prop?
  // Let's use a simpler approach: App.jsx will call the API and just update messages.
  // Actually, keeping the logic here is cleaner. I'll add a useEffect to watch for 'forced' prompts.

  return (
    <div className="fixed bottom-6 right-6 z-[200]">
      {/* CHAT WINDOW */}
      {isOpen && (
        <div className="absolute bottom-16 right-0 w-[400px] h-[600px] bg-[#0a0a0a] border border-purple-500/30 rounded-xl shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-bottom-4 duration-300 backdrop-blur-xl">
          {/* HEADER */}
          <div className="p-4 bg-gradient-to-r from-purple-900/40 to-blue-900/40 border-b border-white/10 flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Bot size={20} className="text-purple-400" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide">DEFENSE HALO AI</h3>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
                  <span className="text-[10px] text-gray-400 uppercase font-bold tracking-widest text-xs">Neural Core Active</span>
                </div>
              </div>
            </div>
            <button onClick={() => setIsOpen(false)} className="text-gray-500 hover:text-white transition-colors">
              <X size={20} />
            </button>
          </div>

          {/* MESSAGES */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]">
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : msg.role === 'system' ? 'justify-center' : 'justify-start'}`}>
                {msg.role === 'system' ? (
                    <div className="bg-red-500/10 border border-red-500/30 px-4 py-2 rounded-lg text-[10px] text-red-400 font-black uppercase tracking-tighter flex items-center gap-2">
                        <AlertTriangle size={12} /> {msg.content}
                    </div>
                ) : (
                    <div className={`flex gap-3 max-w-[85%] ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                    <div className={`mt-1 p-1.5 rounded-lg h-fit ${msg.role === 'user' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'}`}>
                        {msg.role === 'user' ? <User size={14} /> : <Bot size={14} />}
                    </div>
                    <div className={`p-3 rounded-2xl text-sm leading-relaxed ${
                        msg.role === 'user' 
                        ? 'bg-blue-600 text-white rounded-tr-none shadow-lg shadow-blue-900/20' 
                        : 'bg-zinc-900/80 border border-white/5 text-gray-200 rounded-tl-none backdrop-blur-sm'
                    }`}>
                        <ReactMarkdown 
                            remarkPlugins={[remarkGfm]}
                            components={{
                                p: ({node, ...props}) => <p className="mb-2 last:mb-0" {...props} />,
                                code: ({node, inline, ...props}) => 
                                    inline 
                                    ? <code className="bg-black/40 px-1 rounded text-purple-300 font-mono" {...props} />
                                    : <code className="block bg-black/60 p-2 rounded text-xs font-mono my-2 overflow-x-auto border border-white/5 text-blue-300" {...props} />
                            }}
                        >
                            {msg.content}
                        </ReactMarkdown>
                    </div>
                    </div>
                )}
              </div>
            ))}
            {isLoading && (
              <div className="flex justify-start">
                <div className="flex gap-3 bg-zinc-900/80 p-3 rounded-2xl rounded-tl-none border border-white/5 animate-pulse">
                  <Loader2 size={16} className="animate-spin text-purple-400" />
                  <span className="text-xs text-gray-400">Consulting threat intelligence...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* INPUT */}
          <form onSubmit={handleSend} className="p-4 bg-zinc-900/50 border-t border-white/10">
            <div className="relative flex items-center">
              <input 
                type="text" 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about your network..." 
                className="w-full bg-black/50 border border-white/10 rounded-full pl-4 pr-12 py-2.5 text-sm text-white focus:outline-none focus:border-purple-500/50 transition-all placeholder:text-gray-600 shadow-inner"
              />
              <button 
                type="submit" 
                disabled={!input.trim() || isLoading}
                className="absolute right-1.5 p-1.5 bg-purple-600 hover:bg-purple-500 disabled:bg-zinc-800 disabled:text-gray-600 text-white rounded-full transition-all"
              >
                <Send size={16} />
              </button>
            </div>
            <div className="mt-2 text-center">
                <p className="text-[9px] text-gray-600 uppercase font-bold tracking-tighter flex items-center justify-center gap-1">
                    Powered by <Sparkles size={8}/> Google Gemma 3 27B
                </p>
            </div>
          </form>
        </div>
      )}

      {/* FLOATING BUTTON */}
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className={`p-4 rounded-full shadow-2xl transition-all duration-300 hover:scale-110 active:scale-95 group flex items-center justify-center ${
          isOpen ? 'bg-zinc-800 text-white' : 'bg-purple-600 text-white hover:shadow-purple-500/20'
        }`}
      >
        {isOpen ? <X size={24} /> : (
            <div className="relative">
                <MessageSquare size={24} />
                {!isOpen && (
                    <span className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 border-2 border-purple-600 rounded-full animate-pulse"></span>
                )}
            </div>
        )}
      </button>
    </div>
  );
};

export default ChatWidget;
