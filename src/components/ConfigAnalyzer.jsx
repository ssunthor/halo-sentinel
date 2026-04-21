import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Activity, Send, Loader2, Copy, Check } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

import remarkGfm from 'remark-gfm';
import SecurityAudit from './SecurityAudit';
import CrossVendor from './CrossVendor';
import PolicyGenerator from './PolicyGenerator';

const MessageBubble = ({ msg }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(msg.text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isUser = msg.sender === 'user';

  return (
    <div className={`flex flex-col group ${isUser ? 'items-end' : 'items-start'}`}>
      <div className={`relative max-w-[90%] p-2.5 rounded-lg text-xs leading-relaxed ${
        isUser ? 'bg-blue-600 text-white rounded-br-none shadow-md' : 'bg-gray-800 text-gray-200 rounded-bl-none border border-gray-700'
      }`}>
        
        {/* Copy Button (Shows on Hover) */}
        <button 
          onClick={handleCopy}
          className={`absolute top-2 ${isUser ? '-left-8' : '-right-8'} p-1.5 rounded-md bg-gray-800 text-gray-400 border border-gray-700 opacity-0 group-hover:opacity-100 transition-opacity hover:text-white hover:bg-gray-700`}
          title="Copy message"
        >
          {copied ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
        </button>

        {isUser ? (
          msg.text
        ) : (
          <div className="prose prose-invert prose-xs max-w-none">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.text}</ReactMarkdown>
          </div>
        )}
      </div>
    </div>
  );
};

const ChatPanel = ({ messages, currentMessage, onMessageChange, onSendMessage, context, placeholder, isLoading }) => {
  const chatContainerRef = useRef(null);
  const [shouldAutoScroll, setShouldAutoScroll] = useState(true);

  // Smart auto-scroll: Only auto-scroll if the user is already near the bottom.
  const handleScroll = useCallback(() => {
    if (!chatContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = chatContainerRef.current;
    // If user is within 50px of the bottom, keep auto-scrolling
    const isNearBottom = scrollHeight - scrollTop - clientHeight < 50;
    setShouldAutoScroll(isNearBottom);
  }, []);

  useEffect(() => {
    if (shouldAutoScroll && chatContainerRef.current) {
        chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [messages, isLoading, shouldAutoScroll]);

  return (
    <div className="w-[25%] flex flex-col bg-[#121212] border border-gray-800 rounded-lg shadow-lg overflow-hidden">
      <div className="p-3 border-b border-gray-800 bg-[#0a0a0a]">
        <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
          <Activity size={14} className="text-green-500"/> Expert Chat
        </h3>
        <div className="text-[10px] text-blue-400 mt-1 truncate">Context: {context}</div>
      </div>
      <div 
        ref={chatContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-3 px-10" // Added px-10 to prevent copy button from overflowing
      >
        {messages.map((msg, idx) => (
          <MessageBubble key={idx} msg={msg} />
        ))}
        
        {isLoading && (
          <div className="flex items-start">
            <div className="bg-gray-800 p-2 rounded-lg rounded-bl-none border border-gray-700">
              <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />
            </div>
          </div>
        )}
      </div>
      <div className="p-3 bg-[#0a0a0a] border-t border-gray-800 shrink-0">
        <div className="relative">
          <input 
            type="text" 
            value={currentMessage} 
            onChange={onMessageChange} 
            onKeyDown={(e) => e.key === 'Enter' && !isLoading && onSendMessage()} 
            placeholder={placeholder} 
            disabled={isLoading}
            className="w-full bg-black border border-gray-700 rounded-md pl-3 pr-8 py-2.5 text-[11px] text-white focus:border-blue-500 focus:outline-none transition-colors disabled:opacity-50"
          />
          <button 
            onClick={onSendMessage} 
            disabled={isLoading || !currentMessage.trim()}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-blue-500 transition-colors disabled:opacity-30"
          >
            {isLoading ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
          </button>
        </div>
      </div>
    </div>
  );
};

const ConfigAnalyzer = ({ activeTab }) => {
  const [chatMessages, setChatMessages] = useState([{ sender: 'ai', text: 'How can I assist with your configuration analysis?' }]);
  const [currentMessage, setCurrentMessage] = useState('');
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [activeConfig, setActiveConfig] = useState('');
  const [allIssues, setAllIssues] = useState([]);

  const addChatMessage = useCallback((text, sender = 'ai') => {
    setChatMessages(prev => [...prev, { sender, text }]);
  }, []);

  const handleAiResponse = useCallback(async (userMsg, contextOverride = {}) => {
    // Show spinner only until the first chunk arrives
    setIsAiLoading(true);
    if (!contextOverride.silent) {
        addChatMessage(userMsg, 'user');
    }

    try {
      const response = await fetch('/analyzer/v1/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          message: userMsg, 
          context: { 
            active_tab: activeTab,
            config_content: activeConfig,
            all_issues: allIssues,
            history: chatMessages, // Send previous messages for memory
            ...contextOverride
          } 
        })
      });
      if (!response.ok) throw new Error('AI Service Unavailable');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let aiText = '';
      let isFirstChunk = true;
      
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.content) {
                aiText += data.content;
                
                if (isFirstChunk) {
                    // Turn off the spinner and insert the placeholder message once data starts flowing
                    setIsAiLoading(false);
                    setChatMessages(prev => [...prev, { sender: 'ai', text: aiText }]);
                    isFirstChunk = false;
                } else {
                    // Update the existing message with new text
                    setChatMessages(prev => {
                      const updated = [...prev];
                      updated[updated.length - 1] = { sender: 'ai', text: aiText };
                      return updated;
                    });
                }
              }
            } catch (e) {
              console.error("Error parsing AI chunk", e);
            }
          }
        }
      }
    } catch (error) {
      setIsAiLoading(false);
      addChatMessage(`I'm sorry, I encountered an error: ${error.message}`, 'ai');
    } finally {
      setIsAiLoading(false);
    }
  }, [addChatMessage, activeTab, activeConfig, allIssues, chatMessages]);

  const triggerAiQuery = useCallback((msg, context = {}) => {
    handleAiResponse(msg, context);
  }, [handleAiResponse]);

  const handleSendMessage = () => {
    if (!currentMessage.trim() || isAiLoading) return;
    const msg = currentMessage;
    setCurrentMessage('');
    handleAiResponse(msg);
  };

  const renderWorkspace = () => {
    switch (activeTab) {
      case 'analyzer':
        return (
          <SecurityAudit 
            addChatMessage={addChatMessage} 
            triggerAiQuery={triggerAiQuery} 
            onConfigChange={setActiveConfig}
            onIssuesFound={setAllIssues}
          />
        );
      case 'translate':
        return (
          <CrossVendor 
            addChatMessage={addChatMessage} 
            triggerAiQuery={triggerAiQuery} 
            onConfigChange={setActiveConfig}
          />
        );
      case 'greenfield':
        return (
          <PolicyGenerator 
            addChatMessage={addChatMessage} 
            triggerAiQuery={triggerAiQuery} 
          />
        );
      default:
        return (
          <div className="flex-1 flex items-center justify-center text-gray-500 italic">
            Select a sub-module from the Config Analyzer menu.
          </div>
        );
    }
  };

  return (
    <div className="flex space-x-6 h-[calc(100vh-180px)] min-h-0 bg-black overflow-hidden relative">
      <div className="flex-1 min-w-0 h-full">
        {renderWorkspace()}
      </div>

      <ChatPanel
        messages={chatMessages}
        currentMessage={currentMessage}
        onMessageChange={(e) => setCurrentMessage(e.target.value)}
        onSendMessage={handleSendMessage}
        context={activeTab === 'analyzer' ? "Security Audit" : activeTab === 'translate' ? "Cross-Vendor" : "Policy Builder"}
        placeholder="Ask the security expert..."
        isLoading={isAiLoading}
      />
    </div>
  );
};

export default ConfigAnalyzer;
