import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Link as LinkIcon, 
  FileText, 
  UploadCloud, 
  Search, 
  Download,
  AlertCircle,
  CheckCircle2,
  Cpu,
  Activity,
  Check,
  Loader2,
  Terminal,
  AlertTriangle,
  Brain,
  Shield,
  LogOut
} from 'lucide-react';
import { motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import AuthPage from './AuthPage';
import AIChatbot from './AIChatbot';

function parseReport(reportText) {
  if (!reportText) return [];

  const headings = [
    { title: "Incident Summary & Status", key: "summary", class: "section-summary" },
    { title: "1. Why & How Did It Occur?", key: "forensics", class: "section-forensics" },
    { title: "2. How to Stop and Contain It?", key: "containment", class: "section-containment" },
    { title: "3. How to Prevent It in the Future?", key: "prevention", class: "section-prevention" }
  ];

  const lines = reportText.split('\n');
  const sections = [];
  let currentSection = null;
  let currentContent = [];

  for (let line of lines) {
    let matchedHeading = null;
    if (line.startsWith('###')) {
      const cleanLine = line.replace(/[^\w\s.&?📑🔍🛡️🔮]/g, '').trim();
      for (const h of headings) {
        if (cleanLine.toLowerCase().includes(h.title.toLowerCase().replace(/[^\w\s.&?]/g, '').trim()) || 
            (h.key === 'summary' && cleanLine.toLowerCase().includes('summary')) ||
            (h.key === 'forensics' && cleanLine.toLowerCase().includes('why & how')) ||
            (h.key === 'containment' && cleanLine.toLowerCase().includes('stop and contain')) ||
            (h.key === 'prevention' && cleanLine.toLowerCase().includes('prevent'))) {
          matchedHeading = h;
          break;
        }
      }
    }

    if (matchedHeading) {
      if (currentSection) {
        sections.push({ ...currentSection, content: currentContent.join('\n') });
      }
      currentSection = {
        title: line,
        class: matchedHeading.class,
        key: matchedHeading.key
      };
      currentContent = [];
    } else {
      if (currentSection) {
        currentContent.push(line);
      } else {
        if (line.trim()) {
          currentSection = {
            title: "",
            class: "section-summary",
            key: "intro"
          };
          currentContent.push(line);
        }
      }
    }
  }

  if (currentSection) {
    sections.push({ ...currentSection, content: currentContent.join('\n') });
  }

  return sections;
}

const API_BASE = 'https://sentinalai-fxjz.onrender.com';

function App() {
  // --- Auth State ---
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return !!localStorage.getItem('sentinal_token');
  });
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const stored = localStorage.getItem('sentinal_user');
      return stored ? JSON.parse(stored) : null;
    } catch { return null; }
  });

  // --- App State (must be declared before any conditional return) ---
  const [activeTab, setActiveTab] = useState('url');
  const [isProcessing, setIsProcessing] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [report, setReport] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [analysisEngine, setAnalysisEngine] = useState('');
  const [analysisSeverity, setAnalysisSeverity] = useState('');
  const [analysisTime, setAnalysisTime] = useState(null);
  const [loadingStage, setLoadingStage] = useState(0);

  const loadingSteps = [
    { title: "Forensic Triage Agent Active", desc: "Analyzing structure, parsing timestamp, status codes and event IDs" },
    { title: "Threat Intelligence Query", desc: "Checking VirusTotal, URLScan.io, and local botnet CIDRs" },
    { title: "IP & Domain Correlation", desc: "Aggregating network vectors and evaluating reputation history" },
    { title: "Mitigation Playbook Compilation", desc: "Synthesizing immediate containment scripts and zero-trust blocks" },
    { title: "Finalizing Forensic Report", desc: "Drafting CIS security control recommendations and ATT&CK mappings" }
  ];

  useEffect(() => {
    let interval;
    if (isProcessing) {
      setLoadingStage(0);
      interval = setInterval(() => {
        setLoadingStage(prev => (prev < loadingSteps.length - 1 ? prev + 1 : prev));
      }, 4000);
    } else {
      setLoadingStage(0);
    }
    return () => clearInterval(interval);
  }, [isProcessing]);

  // --- Auth Handlers ---
  const handleLogin = (user) => {
    setCurrentUser(user);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('sentinal_token');
    localStorage.removeItem('sentinal_user');
    setIsAuthenticated(false);
    setCurrentUser(null);
  };

  // If not authenticated, show the auth page
  if (!isAuthenticated) {
    return <AuthPage onLogin={handleLogin} />;
  }

  const handleAnalyze = async () => {
    if (activeTab === 'url' && !urlInput) return;
    if (activeTab === 'log' && !selectedFile) return;

    setIsProcessing(true);
    setReport(null);
    setErrorMessage(null);
    setAnalysisEngine('');
    setAnalysisSeverity('');
    setAnalysisTime(null);

    try {
      let input_data = {};
      let intel_data = {
        aggregate_verdict: "clean",
        data_source: "mock",
        sources: []
      };

      if (activeTab === 'url') {
        // --- 1. Analyze URL Heuristics ---
        const urlAnalysisResponse = await fetch(`${API_BASE}/api/analyze-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlInput })
        });
        if (!urlAnalysisResponse.ok) {
          const err = await urlAnalysisResponse.json();
          throw new Error(err.detail || 'URL Heuristic Analysis failed');
        }
        const urlAnalysis = await urlAnalysisResponse.json();
        input_data = {
          url: urlAnalysis.url,
          domain: urlAnalysis.domain,
          risk_score: urlAnalysis.risk_score,
          indicators: urlAnalysis.indicators
        };

        // --- 2. Check URL Reputation ---
        const urlReputationResponse = await fetch(`${API_BASE}/api/threat-intel/url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlInput })
        });
        if (urlReputationResponse.ok) {
          const repData = await urlReputationResponse.json();
          intel_data = repData.result || repData;
        }

      } else {
        // --- 1. Upload Log File ---
        const formData = new FormData();
        formData.append('file', selectedFile);

        const logUploadResponse = await fetch(`${API_BASE}/api/upload-log`, {
          method: 'POST',
          body: formData
        });
        if (!logUploadResponse.ok) {
          const err = await logUploadResponse.json();
          throw new Error(err.detail || 'Log upload and parsing failed');
        }
        const logData = await logUploadResponse.json();
        
        input_data = {
          filename: logData.filename,
          total_lines: logData.total_lines,
          parsed_count: logData.parsed_count,
          skipped_count: logData.skipped_count,
          parsed_entries: logData.parsed_entries
        };

        // --- 2. Query Reputation for Top Source IPs ---
        const uniqueIps = [...new Set(logData.parsed_entries.map(e => e.source_ip).filter(Boolean))].slice(0, 5);
        
        const ipSources = [];
        let anyMalicious = false;
        
        for (const ip of uniqueIps) {
          try {
            const ipRepResponse = await fetch(`${API_BASE}/api/threat-intel/ip`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ ip })
            });
            if (ipRepResponse.ok) {
              const ipRep = await ipRepResponse.json();
              const resultData = ipRep.result || ipRep;
              if (resultData.aggregate_verdict === 'malicious') {
                anyMalicious = true;
              }
              if (resultData.sources) {
                resultData.sources.forEach(src => {
                  ipSources.push({
                    ...src,
                    queried_ip: ip
                  });
                });
              }
            }
          } catch (ipErr) {
            console.error(`Failed to lookup reputation for IP ${ip}:`, ipErr);
          }
        }

        intel_data = {
          aggregate_verdict: anyMalicious ? 'malicious' : 'clean',
          data_source: uniqueIps.length > 0 ? 'live' : 'mock',
          sources: ipSources
        };
      }

      // --- 3. Run Autonomous SOC Agentic Analysis ---
      const socResponse = await fetch(`${API_BASE}/api/soc-analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input_data, intel_data })
      });
      if (!socResponse.ok) {
        const err = await socResponse.json();
        throw new Error(err.detail || 'Autonomous SOC Analysis failed');
      }
      const socResult = await socResponse.json();

      setReport(socResult.report);
      setAnalysisEngine(socResult.engine);
      setAnalysisSeverity(socResult.severity);
      setAnalysisTime(socResult.execution_time_s);

    } catch (err) {
      console.error(err);
      setErrorMessage(err.message || 'An error occurred during analysis.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const ext = file.name.split('.').pop().toLowerCase();
      if (ext === 'log' || ext === 'txt') {
        setSelectedFile(file);
        setErrorMessage(null);
      } else {
        setErrorMessage('Invalid file type. Only .log and .txt files are allowed.');
      }
    }
  };

  const triggerFileInput = () => {
    document.getElementById('log-file-input').click();
  };

  const loadDemoLog = (type = 'mixed') => {
    let content = "";
    let filename = "";

    switch (type) {
      case 'web':
        filename = "web_access.log";
        content = `192.168.1.100 - - [09/Jul/2024:14:23:45 +0000] "GET /wp-admin/ HTTP/1.1" 200 4523
192.168.1.100 - - [09/Jul/2024:14:23:46 +0000] "POST /wp-login.php HTTP/1.1" 401 312
192.168.1.100 - - [09/Jul/2024:14:23:47 +0000] "POST /wp-login.php HTTP/1.1" 401 312
192.168.1.100 - - [09/Jul/2024:14:23:48 +0000] "POST /wp-login.php HTTP/1.1" 401 312
192.168.1.100 - - [09/Jul/2024:14:23:49 +0000] "GET /etc/passwd HTTP/1.1" 403 215
192.168.1.100 - - [09/Jul/2024:14:23:50 +0000] "GET /wp-config.php.bak HTTP/1.1" 403 215
192.168.1.102 - - [09/Jul/2024:14:24:00 +0000] "GET /index.php HTTP/1.1" 200 8593`;
        break;
      case 'win':
        filename = "windows_auth.log";
        content = `2024-07-09 14:35:00 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:35:01 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:35:02 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:35:03 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:36:12 Security EventID=4624 An account was successfully logged on. Source: 10.0.0.99 Target: DC01
2024-07-09 14:37:00 Security EventID=4720 A user account was created. Source: 10.0.0.55 Target: DC01`;
        break;
      case 'fw':
        filename = "firewall_ufw.log";
        content = `Jul  9 14:30:12 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.1 PROTO=TCP DPT=22
Jul  9 14:30:13 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.1 PROTO=TCP DPT=22
Jul  9 14:30:14 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.1 PROTO=TCP DPT=22
Jul  9 14:30:15 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.215.113.42 DST=10.0.0.1 PROTO=TCP DPT=22
Jul  9 14:30:18 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.99 DST=10.0.0.1 PROTO=TCP DPT=443`;
        break;
      case 'mixed':
      default:
        filename = "mixed_format.log";
        content = `192.168.1.100 - admin [09/Jul/2024:14:23:45 +0000] "GET /wp-admin/ HTTP/1.1" 200 4523
10.0.0.55 - - [09/Jul/2024:14:23:46 +0000] "POST /login HTTP/1.1" 401 312
10.0.0.55 - - [09/Jul/2024:14:23:47 +0000] "POST /login HTTP/1.1" 401 312
10.0.0.55 - - [09/Jul/2024:14:23:48 +0000] "POST /login HTTP/1.1" 401 312
10.0.0.55 - - [09/Jul/2024:14:23:49 +0000] "POST /login HTTP/1.1" 403 215
Jul  9 14:30:12 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.1 PROTO=TCP DPT=22
Jul  9 14:30:15 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.215.113.42 DST=10.0.0.1 PROTO=TCP DPT=22
2024-07-09 14:35:00 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:35:01 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:35:02 Security Event ID: 4625 An account failed to log on. Source: 10.0.0.55 Target: DC01
2024-07-09 14:37:00 Security EventID=4720 A user account was created. Source: 10.0.0.55 Target: DC01`;
        break;
    }

    const blob = new Blob([content], { type: 'text/plain' });
    const file = new File([blob], filename, { type: 'text/plain' });
    setSelectedFile(file);
    setErrorMessage(null);
  };

  const renderMarkdownComponents = {
    h3: ({node, ...props}) => {
      const id = props.children[0]?.toString().toLowerCase().replace(/[^a-z0-9]+/g, '-');
      return <h3 id={id} className="text-xl font-bold mt-8 mb-4 flex items-center gap-2 text-slate-100 border-b border-slate-800 pb-2" {...props} />;
    },
    table: ({node, ...props}) => (
      <div className="overflow-x-auto my-6 border border-slate-800 rounded-lg shadow-sm">
        <table className="w-full text-left border-collapse" {...props} />
      </div>
    ),
    th: ({node, ...props}) => <th className="bg-slate-900/60 text-slate-200 font-semibold p-3 border-b border-slate-800" {...props} />,
    td: ({node, ...props}) => <td className="p-3 border-b border-slate-800/80 text-slate-350 bg-slate-950/20" {...props} />,
    p: ({node, ...props}) => <p className="text-slate-300 leading-relaxed mb-4" {...props} />,
    ul: ({node, ...props}) => <ul className="list-disc list-inside mb-4 space-y-2 text-slate-350 ml-4" {...props} />,
    ol: ({node, ...props}) => <ol className="list-decimal list-inside mb-4 space-y-2 text-slate-350 ml-4" {...props} />,
    li: ({node, ...props}) => <li className="text-slate-350" {...props} />,
    strong: ({node, ...props}) => <strong className="font-semibold text-white" {...props} />,
    code: ({node, inline, ...props}) => 
      inline ? (
        <code className="bg-slate-950/80 text-cyan-400 px-1.5 py-0.5 rounded text-xs border border-slate-800/60 font-mono" {...props} />
      ) : (
        <pre className="bg-slate-950/90 text-slate-200 p-4 rounded-xl overflow-x-auto my-4 text-xs font-mono border border-slate-800 shadow-inner">
          <code {...props} />
        </pre>
      )
  };

  return (
    <div className="min-h-screen bg-transparent flex flex-col font-sans text-slate-250 selection:bg-indigo-500/20 selection:text-indigo-200">
      {/* Top Header */}
      <header className="bg-slate-950/45 backdrop-blur-xl border-b border-slate-900 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <motion.div
              animate={{ y: [0, -4, 0] }}
              transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
              className="bg-gradient-to-br from-cyan-600 to-indigo-600 p-2 rounded-xl text-white shadow-md shadow-cyan-500/20"
            >
              <Shield size={20} className="stroke-[2.5]" />
            </motion.div>
            <div>
              <h1 className="text-lg font-black tracking-tight text-white leading-tight">
                Sentinal AI
              </h1>
              <p className="text-[10px] text-slate-400 font-semibold tracking-wide">
                Autonomous WebAction Triage & Log Analytics
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-semibold text-slate-400">
            <motion.div 
              animate={{ y: [0, -3, 0] }}
              transition={{ duration: 5, repeat: Infinity, ease: 'easeInOut', delay: 0.5 }}
              className="flex items-center gap-2 bg-emerald-950/20 border border-emerald-900/30 text-emerald-400 px-3 py-1 rounded-full text-[11px] font-medium"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>System Online</span>
            </motion.div>
            <div className="h-4 w-px bg-slate-800"></div>
            {currentUser && (
              <span className="text-slate-400 text-[11px] font-medium hidden sm:inline">
                {currentUser.name}
              </span>
            )}
            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 bg-slate-900/80 border border-slate-800 hover:bg-rose-950/30 hover:border-rose-900/40 text-slate-400 hover:text-rose-400 px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all active:scale-[0.96]"
              title="Sign out"
            >
              <LogOut size={11} />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-6xl mx-auto px-4 py-8 w-full">
        {/* Error Alert */}
        {errorMessage && (
          <div className="bg-rose-950/25 border border-rose-900/40 text-rose-200 px-5 py-4 rounded-xl mb-6 flex items-start gap-3.5 animate-in fade-in duration-300 max-w-3xl mx-auto shadow-lg shadow-rose-950/10">
            <AlertTriangle className="shrink-0 text-rose-500 mt-0.5" size={20} />
            <div>
              <h4 className="font-bold text-sm text-rose-400">Incident Triage Failed</h4>
              <p className="text-xs mt-1 leading-relaxed text-rose-350">{errorMessage}</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left Column: Input Panel & Agents */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
            className="lg:col-span-5 flex flex-col gap-6 w-full no-print"
          >
            {/* Input & Tabs Container */}
            <motion.div 
              animate={{ y: [0, -5, 0] }}
              transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut' }}
              className="cyber-glass rounded-2xl border border-slate-800/80 overflow-hidden shadow-xl"
            >
              {/* Tabs */}
              <div className="flex border-b border-slate-900 bg-slate-950/40">
                <button
                  onClick={() => {
                    setActiveTab('url');
                    setErrorMessage(null);
                  }}
                  className={`flex-1 py-3 px-4 font-semibold text-xs flex items-center justify-center gap-2 transition-all duration-300 ${
                    activeTab === 'url'
                      ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-950/10 shadow-[inset_0_-10px_20px_-10px_rgba(6,182,212,0.15)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/5'
                  }`}
                >
                  <LinkIcon size={14} />
                  URL Phishing Analyzer
                </button>
                <button
                  onClick={() => {
                    setActiveTab('log');
                    setErrorMessage(null);
                  }}
                  className={`flex-1 py-3 px-4 font-semibold text-xs flex items-center justify-center gap-2 transition-all duration-300 ${
                    activeTab === 'log'
                      ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-950/10 shadow-[inset_0_-10px_20px_-10px_rgba(6,182,212,0.15)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/5'
                  }`}
                >
                  <FileText size={14} />
                  SOC Log File Upload
                </button>
              </div>

              {/* Tab Contents */}
              <div className="p-6">
                {activeTab === 'url' && (
                  <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                    <label className="text-slate-200 text-xs font-bold mb-2 block tracking-wide">
                      Suspicious URL
                    </label>
                    
                    <div className="relative mb-4">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                        <LinkIcon size={14} />
                      </div>
                      <input
                        type="url"
                        value={urlInput}
                        onChange={(e) => setUrlInput(e.target.value)}
                        placeholder="https://suspicious-site.example/login/verify"
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-950/60 border border-slate-800/80 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/80 transition-all font-mono text-xs"
                      />
                    </div>

                    <button
                      onClick={handleAnalyze}
                      disabled={!urlInput || isProcessing}
                      className="w-full bg-indigo-600/90 hover:bg-indigo-600 hover:disabled:bg-slate-800 disabled:bg-slate-800/50 disabled:text-slate-500 disabled:cursor-not-allowed text-slate-100 font-bold py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg active:scale-[0.98] text-xs border border-indigo-500/20"
                    >
                      {isProcessing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Search size={14} className="text-cyan-400" />
                      )}
                      Analyze Link
                    </button>

                    {/* Explainer note */}
                    <div className="mt-4 bg-slate-950/50 border border-slate-900 rounded-xl p-4 flex items-start gap-3">
                      <Shield size={16} className="text-slate-500 shrink-0 mt-0.5" />
                      <p className="text-slate-400 text-[10px] leading-relaxed">
                        The URL is screened against heuristic rules (suspicious TLDs, phishing keywords, IP-as-host) and enriched with VirusTotal / URLScan.io threat intelligence before the AI agents generate the forensic report.
                      </p>
                    </div>
                  </div>
                )}

                {activeTab === 'log' && (
                  <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                    <label className="text-slate-200 text-xs font-bold mb-2 block tracking-wide">
                      Upload Security Log
                    </label>

                    <input
                      type="file"
                      id="log-file-input"
                      accept=".log,.txt"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setSelectedFile(e.target.files[0]);
                          setErrorMessage(null);
                        }
                      }}
                    />

                    {selectedFile ? (
                      <div className="border border-cyan-900/30 bg-cyan-950/5 rounded-xl p-4 text-center animate-in fade-in duration-300">
                        <div className="mx-auto w-10 h-10 bg-cyan-950/60 border border-cyan-800/30 text-cyan-400 rounded-full flex items-center justify-center mb-2">
                          <FileText size={18} />
                        </div>
                        <h4 className="font-semibold text-xs text-slate-200 mb-0.5 truncate">{selectedFile.name}</h4>
                        <p className="text-slate-500 text-[10px] mb-3 font-mono">{(selectedFile.size / 1024).toFixed(2)} KB</p>
                        <div className="flex gap-2 justify-center">
                          <button
                            onClick={() => setSelectedFile(null)}
                            className="bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 px-3 py-1.5 rounded-lg text-[10px] font-semibold transition-all hover:text-white"
                          >
                            Remove
                          </button>
                          <button
                            onClick={handleAnalyze}
                            disabled={isProcessing}
                            className="bg-indigo-600/90 hover:bg-indigo-600 text-slate-100 px-4 py-1.5 rounded-lg text-[10px] font-bold flex items-center gap-1 transition-all active:scale-[0.98]"
                          >
                            {isProcessing ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Activity size={11} className="text-cyan-400" />
                            )}
                            Analyze File
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div
                        onDragOver={handleDragOver}
                        onDrop={handleDrop}
                        onClick={triggerFileInput}
                        className="border border-dashed border-slate-800 hover:border-cyan-500/50 rounded-xl p-6 text-center hover:bg-slate-950/20 transition-all duration-300 cursor-pointer group"
                      >
                        <div className="mx-auto w-10 h-10 bg-slate-900/60 border border-slate-800 rounded-full flex items-center justify-center mb-3 group-hover:scale-105 group-hover:border-cyan-500/20 transition-transform duration-300 shadow-inner">
                          <UploadCloud size={20} className="text-cyan-500/80 group-hover:text-cyan-400" />
                        </div>
                        <h3 className="text-xs font-semibold text-slate-200 mb-0.5">Click or drag log file to upload</h3>
                        <p className="text-slate-500 text-[9px] mb-3">Syslog, HTTP logs, or text files (max 10MB)</p>
                        
                        <div className="flex gap-2 justify-center" onClick={(e) => e.stopPropagation()}>
                          <button 
                            type="button"
                            onClick={triggerFileInput}
                            className="bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-355 px-3 py-1.5 rounded-lg font-semibold text-[10px] flex items-center gap-1 transition-all active:scale-[0.98] hover:text-white"
                          >
                            Select File
                          </button>
                          <select
                            onChange={(e) => {
                              if (e.target.value) {
                                loadDemoLog(e.target.value);
                                e.target.value = ""; // reset selection
                              }
                            }}
                            className="bg-indigo-950/40 border border-indigo-900/50 hover:bg-indigo-900/30 text-cyan-400 px-3 py-1.5 rounded-lg font-semibold text-[10px] flex items-center gap-1 transition-all cursor-pointer outline-none"
                          >
                            <option value="" disabled selected>Load Sample</option>
                            <option value="web" className="bg-slate-950 text-slate-200">Web Access Log</option>
                            <option value="win" className="bg-slate-950 text-slate-200">Windows Auth Log</option>
                            <option value="fw" className="bg-slate-950 text-slate-200">Firewall Log</option>
                            <option value="mixed" className="bg-slate-950 text-slate-200">Mixed Security Log</option>
                          </select>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </motion.div>

            {/* Active AI Agents Section */}
            <div className="flex flex-col gap-3">
              <h3 className="text-[10px] font-bold text-slate-500 tracking-wider uppercase pl-1">
                Active AI Agents
              </h3>

              {/* Agent 1 */}
              <motion.div
                animate={{ y: [0, -6, 0] }}
                transition={{ duration: 5, repeat: Infinity, ease: 'easeInOut' }}
                whileHover={{ y: -8, scale: 1.02 }}
                className="bg-slate-950/40 border border-slate-900 rounded-xl p-3 flex items-center gap-3 shadow-md hover:border-indigo-500/30 transition-colors"
              >
                <div className="bg-slate-900 border border-slate-800/80 p-2 rounded-lg text-slate-400 shrink-0">
                  <Activity size={16} className="text-indigo-400" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-200">Forensic Triage Agent</h4>
                  <p className="text-[10px] text-slate-500">Root cause & timeline reconstruction</p>
                </div>
              </motion.div>

              {/* Agent 2 */}
              <motion.div
                animate={{ y: [0, -6, 0] }}
                transition={{ duration: 5, repeat: Infinity, ease: 'easeInOut', delay: 2.5 }}
                whileHover={{ y: -8, scale: 1.02 }}
                className="bg-slate-950/40 border border-slate-900 rounded-xl p-3 flex items-center gap-3 shadow-md hover:border-cyan-500/30 transition-colors"
              >
                <div className="bg-slate-900 border border-slate-800/80 p-2 rounded-lg text-slate-400 shrink-0">
                  <Shield size={16} className="text-cyan-400" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-200">Playbook & Mitigation Agent</h4>
                  <p className="text-[10px] text-slate-500">Containment & hardening strategies</p>
                </div>
              </motion.div>
            </div>
          </motion.div>

          {/* Right Column: Dynamic Output Panel */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut', delay: 0.2 }}
            className="lg:col-span-7 w-full h-full min-h-[450px] flex flex-col"
          >
            {/* 1. Awaiting Input State */}
            {!isProcessing && !report && (
              <div className="border border-dashed border-slate-800 rounded-2xl p-10 text-center flex flex-col items-center justify-center flex-1 min-h-[400px] bg-slate-950/10">
                <motion.div 
                  animate={{ y: [0, -10, 0], rotate: [0, 2, -2, 0] }}
                  transition={{ duration: 5, repeat: Infinity, ease: 'easeInOut' }}
                  className="bg-slate-900/80 border border-slate-800 p-4 rounded-2xl text-slate-400 mb-4 shadow-lg shadow-indigo-500/5"
                >
                  <Brain size={32} className="text-indigo-400 stroke-[1.5]" />
                </motion.div>
                <h3 className="text-base font-bold text-slate-200 mb-2">Awaiting Input</h3>
                <p className="text-slate-500 text-xs max-w-sm leading-relaxed">
                  Submit a suspicious URL or upload a security log file. The AI agents will analyze the threat in real time and generate a structured forensic report.
                </p>
              </div>
            )}

            {/* 2. Processing/Loading State */}
            {isProcessing && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                className="cyber-glass rounded-2xl border border-slate-800/80 p-8 flex flex-col gap-6 items-center flex-1 justify-center"
              >
                <div className="relative shrink-0 w-16 h-16 flex items-center justify-center">
                  <div className="absolute inset-0 bg-cyan-500/10 border border-cyan-500/20 rounded-full radar-pulse-ring"></div>
                  <div className="absolute inset-1.5 bg-indigo-500/10 border border-indigo-500/20 rounded-full radar-pulse-ring" style={{ animationDelay: '0.6s' }}></div>
                  <motion.div
                    animate={{ y: [0, -4, 0] }}
                    transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
                    className="relative bg-slate-950 border border-slate-800 text-cyan-400 p-3 rounded-full shadow-lg shadow-cyan-500/5"
                  >
                    <Cpu size={24} className="animate-spin" style={{ animationDuration: '6s' }} />
                  </motion.div>
                </div>

                <div className="w-full max-w-md">
                  <h3 className="text-sm font-bold text-center text-white mb-0.5">Autonomous Investigation Underway</h3>
                  <p className="text-slate-500 text-center text-[10px] mb-4">AI Agents are running sandbox operations in the vault...</p>
                  
                  <div className="space-y-2.5 font-mono text-[10px] text-slate-400">
                    {loadingSteps.map((step, idx) => {
                      const isCompleted = loadingStage > idx;
                      const isActive = loadingStage === idx;
                      return (
                        <div key={idx} className={`flex items-start gap-2 transition-opacity duration-300 ${isCompleted ? 'text-slate-500' : isActive ? 'text-cyan-400 font-bold' : 'text-slate-600 opacity-40'}`}>
                          <div className="mt-0.5 shrink-0">
                            {isCompleted ? (
                              <div className="bg-emerald-950 border border-emerald-800 text-emerald-400 p-0.5 rounded-full">
                                <Check size={8} className="stroke-[3]" />
                              </div>
                            ) : isActive ? (
                              <Loader2 size={11} className="animate-spin text-cyan-400" />
                            ) : (
                              <div className="w-2.5 h-2.5 bg-slate-900 border border-slate-800 rounded-full"></div>
                            )}
                          </div>
                          <div>
                            <span className="font-bold uppercase">STEP 0{idx + 1}: {step.title}</span>
                            {isActive && <p className="text-[9px] text-slate-400 mt-0.5 font-sans leading-normal">{step.desc}</p>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </motion.div>
            )}

            {/* 3. Results Panel */}
            {report && !isProcessing && (
              <motion.div 
                initial={{ opacity: 0, y: 30, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
                className="flex flex-col h-full"
              >
                <div className="flex items-center justify-between mb-4 px-1 no-print">
                  <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                    <CheckCircle2 className="text-emerald-500" size={18} />
                    Investigation Report Ready
                  </h2>
                  <button 
                    onClick={() => window.print()}
                    className="flex items-center gap-1 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-350 px-3 py-1.5 rounded-lg text-[10px] font-bold transition-all shadow-sm active:scale-[0.98] hover:text-white"
                  >
                    <Download size={12} />
                    PDF Report
                  </button>
                </div>

                <div className="cyber-glass rounded-2xl overflow-hidden border border-slate-800/80 shadow-2xl flex-1 flex flex-col">
                  {/* Report Header Bar */}
                  <div className="bg-slate-950/80 border-b border-slate-900 px-6 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-slate-300 report-meta-header shrink-0 no-print">
                    <div className="flex items-center gap-2">
                      <FileText size={14} className="text-cyan-500" />
                      <span className="font-bold text-[10px] uppercase tracking-wider text-slate-100">Forensic Briefing Doc</span>
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono flex flex-wrap items-center gap-x-4 gap-y-1">
                      <span>Engine: <span className="text-cyan-400 uppercase font-semibold">{analysisEngine || 'N/A'}</span></span>
                      {analysisSeverity && (
                        <span>Severity: <span className={`px-1.5 py-0.5 rounded font-bold uppercase ${
                          analysisSeverity === 'CRITICAL' || analysisSeverity === 'HIGH' 
                            ? 'bg-rose-950/50 text-rose-400 border border-rose-900/30' 
                            : analysisSeverity === 'MEDIUM' 
                              ? 'bg-amber-950/50 text-amber-400 border border-amber-900/30' 
                              : 'bg-emerald-950/50 text-emerald-400 border border-emerald-900/30'
                        }`}>{analysisSeverity}</span></span>
                      )}
                      {analysisTime && <span>Telemetry: {analysisTime}s</span>}
                    </div>
                  </div>

                  {/* Report Body */}
                  <div className="p-6 md:p-8 prose prose-invert max-w-none w-full overflow-y-auto flex-1 max-h-[600px]">
                    <div className="markdown-report space-y-4">
                      {parseReport(report).map((sec, index) => (
                        <div key={index} className={sec.class}>
                          {sec.title && (
                            <ReactMarkdown 
                              remarkPlugins={[remarkGfm]}
                              components={renderMarkdownComponents}
                            >
                              {sec.title}
                            </ReactMarkdown>
                          )}
                          <ReactMarkdown 
                            remarkPlugins={[remarkGfm]}
                            components={renderMarkdownComponents}
                          >
                            {sec.content}
                          </ReactMarkdown>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </motion.div>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-900 bg-slate-950/20 py-5 text-center text-slate-500 text-[11px] font-medium tracking-wide">
        <p>SENTINAL AI &copy; 2026. SECURE DISCLOSURE SYSTEM. PRIVILEGED ACCESS ONLY.</p>
      </footer>

      {/* AI Security Assistant Chatbot */}
      <AIChatbot
        reportContext={report}
        activeTarget={activeTab === 'url' ? urlInput : (selectedFile ? selectedFile.name : null)}
      />
    </div>
  );
}

export default App;
