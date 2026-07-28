import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  X,
  Send,
  Loader2,
  Sparkles,
  RefreshCw,
  Terminal,
  ChevronDown,
  Shield,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const API_BASE = 'https://sentinalai-fxjz.onrender.com';

function AIChatbot({ reportContext, activeTarget }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        '👋 Hi analyst! I am your **Sentinal AI Security Assistant**.\n\nAsk me anything about active incidents, containment scripts, MITRE ATT&CK techniques, or log analysis.',
    },
  ]);
  const [inputMsg, setInputMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [suggestedActions, setSuggestedActions] = useState([
    'Summarize active report',
    'How to block malicious IPs?',
    'Explain Event ID 4625',
  ]);

  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen, isLoading]);

  const sendMessage = async (textToSend) => {
    const query = textToSend || inputMsg;
    if (!query.trim() || isLoading) return;

    const newMessages = [...messages, { role: 'user', content: query.trim() }];
    setMessages(newMessages);
    if (!textToSend) setInputMsg('');
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newMessages,
          report_context: reportContext || null,
          active_target: activeTarget || null,
        }),
      });

      if (!response.ok) {
        throw new Error('Chatbot request failed');
      }

      const data = await response.json();

      setMessages([
        ...newMessages,
        { role: 'assistant', content: data.reply },
      ]);

      if (data.suggested_actions && data.suggested_actions.length > 0) {
        setSuggestedActions(data.suggested_actions);
      }
    } catch (err) {
      console.error(err);
      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          content:
            '⚠️ *Error connecting to Sentinal AI Chatbot backend. Please check your network connection.*',
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        role: 'assistant',
        content:
          'Conversation reset. How can I assist you with your security operations?',
      },
    ]);
    setSuggestedActions([
      'Summarize active report',
      'Give firewall rules',
      'Explain MITRE ATT&CK',
    ]);
  };

  const markdownComponents = {
    p: ({ node, ...props }) => <p className="leading-relaxed mb-2 text-xs" {...props} />,
    h3: ({ node, ...props }) => (
      <h3 className="text-xs font-bold mt-3 mb-1 text-slate-100 border-b border-slate-800 pb-1" {...props} />
    ),
    ul: ({ node, ...props }) => <ul className="list-disc list-inside mb-2 text-xs space-y-1" {...props} />,
    ol: ({ node, ...props }) => <ol className="list-decimal list-inside mb-2 text-xs space-y-1" {...props} />,
    li: ({ node, ...props }) => <li className="text-slate-300" {...props} />,
    strong: ({ node, ...props }) => <strong className="font-semibold text-cyan-300" {...props} />,
    code: ({ node, inline, ...props }) =>
      inline ? (
        <code className="bg-slate-950 text-cyan-400 px-1 py-0.5 rounded text-[10px] border border-slate-800 font-mono" {...props} />
      ) : (
        <pre className="bg-slate-950/90 text-slate-200 p-3 rounded-lg overflow-x-auto my-2 text-[10px] font-mono border border-slate-800 shadow-inner">
          <code {...props} />
        </pre>
      ),
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 no-print flex flex-col items-end">
      <AnimatePresence>
        {/* Expanded Chat Window */}
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, scale: 0.85, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.85, y: 20 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
            className="cyber-glass rounded-2xl border border-slate-800/90 w-[360px] sm:w-[420px] h-[520px] flex flex-col shadow-2xl overflow-hidden mb-3"
          >
            {/* Header */}
            <div className="bg-slate-950/80 border-b border-slate-900 px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <motion.div 
                  animate={{ y: [0, -3, 0] }}
                  transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
                  className="bg-gradient-to-br from-indigo-500 to-cyan-500 p-1.5 rounded-lg text-white shadow-md shadow-cyan-500/20"
                >
                  <Bot size={16} />
                </motion.div>
                <div>
                  <div className="flex items-center gap-1.5">
                    <h3 className="text-xs font-bold text-slate-100">Sentinal AI Assistant</h3>
                    <span className="flex h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
                  </div>
                  <p className="text-[9px] text-slate-400">Tier-3 SOC Copilot • Context Aware</p>
                </div>
              </div>

              <div className="flex items-center gap-1">
                <button
                  onClick={clearChat}
                  className="text-slate-500 hover:text-slate-300 p-1 rounded-md hover:bg-slate-900 transition-colors"
                  title="Clear conversation"
                >
                  <RefreshCw size={12} />
                </button>
                <button
                  onClick={() => setIsOpen(false)}
                  className="text-slate-500 hover:text-slate-300 p-1 rounded-md hover:bg-slate-900 transition-colors"
                  title="Minimize"
                >
                  <ChevronDown size={14} />
                </button>
              </div>
            </div>

            {/* Active Context Banner */}
            {reportContext && (
              <div className="bg-cyan-950/20 border-b border-cyan-900/30 px-3 py-1.5 flex items-center gap-2 text-[10px] text-cyan-300 shrink-0">
                <Sparkles size={11} className="shrink-0 text-cyan-400 animate-pulse" />
                <span className="truncate">Active Report Context Linked ({reportContext.slice(0, 30)}...)</span>
              </div>
            )}

            {/* Message History */}
            <div className="flex-1 p-4 overflow-y-auto space-y-3 font-sans text-xs">
              {messages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`flex gap-2.5 items-start ${
                    msg.role === 'user' ? 'justify-end' : 'justify-start'
                  }`}
                >
                  {msg.role === 'assistant' && (
                    <div className="bg-slate-900 border border-slate-800 p-1.5 rounded-lg text-cyan-400 shrink-0 mt-0.5">
                      <Bot size={13} />
                    </div>
                  )}

                  <div
                    className={`max-w-[85%] rounded-xl px-3.5 py-2.5 leading-relaxed shadow-sm ${
                      msg.role === 'user'
                        ? 'bg-indigo-600/90 text-white rounded-tr-none border border-indigo-500/30'
                        : 'bg-slate-950/70 text-slate-200 rounded-tl-none border border-slate-800/80'
                    }`}
                  >
                    {msg.role === 'user' ? (
                      <p className="whitespace-pre-wrap">{msg.content}</p>
                    ) : (
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={markdownComponents}
                      >
                        {msg.content}
                      </ReactMarkdown>
                    )}
                  </div>
                </div>
              ))}

              {/* Loading typing state */}
              {isLoading && (
                <div className="flex gap-2.5 items-start">
                  <div className="bg-slate-900 border border-slate-800 p-1.5 rounded-lg text-cyan-400 shrink-0 mt-0.5">
                    <Bot size={13} />
                  </div>
                  <div className="bg-slate-950/70 text-slate-400 rounded-xl rounded-tl-none border border-slate-800/80 px-3.5 py-2.5 flex items-center gap-2">
                    <Loader2 size={13} className="animate-spin text-cyan-400" />
                    <span className="text-[10px] font-mono">Analyzing threat intelligence...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Quick Prompt Suggestions */}
            {suggestedActions && suggestedActions.length > 0 && (
              <div className="px-3 py-1.5 bg-slate-950/40 border-t border-slate-900/60 flex items-center gap-1.5 overflow-x-auto no-scrollbar shrink-0">
                {suggestedActions.map((action, i) => (
                  <button
                    key={i}
                    onClick={() => sendMessage(action)}
                    disabled={isLoading}
                    className="bg-slate-900/80 hover:bg-slate-800 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 text-[9px] px-2.5 py-1 rounded-full whitespace-nowrap transition-all shrink-0"
                  >
                    {action}
                  </button>
                ))}
              </div>
            )}

            {/* Input Area */}
            <div className="p-3 bg-slate-950/90 border-t border-slate-900 flex items-center gap-2">
              <input
                type="text"
                value={inputMsg}
                onChange={(e) => setInputMsg(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask Sentinal AI Assistant..."
                disabled={isLoading}
                className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 transition-all font-sans"
              />
              <button
                onClick={() => sendMessage()}
                disabled={!inputMsg.trim() || isLoading}
                className="bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-600 text-white p-2 rounded-xl transition-all shadow-md active:scale-95 shrink-0"
              >
                <Send size={13} />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Floating Anti-Gravity Toggle Button */}
      {!isOpen && (
        <motion.button
          animate={{ y: [0, -6, 0] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
          whileHover={{ scale: 1.1, y: -9 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setIsOpen(true)}
          className="group relative bg-gradient-to-br from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white p-3.5 rounded-full shadow-2xl shadow-cyan-500/30 flex items-center justify-center transition-all duration-300 border border-cyan-400/30 cursor-pointer"
          title="Open AI Security Assistant"
        >
          <div className="absolute inset-0 bg-cyan-400/20 rounded-full radar-pulse-ring pointer-events-none"></div>
          <Bot size={22} className="stroke-[2.2] text-white" />
          <span className="absolute -top-1 -right-1 flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-400"></span>
          </span>
        </motion.button>
      )}
    </div>
  );
}

export default AIChatbot;
