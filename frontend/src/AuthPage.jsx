import React, { useState } from 'react';
import {
  Shield,
  Mail,
  Lock,
  User,
  Loader2,
  AlertTriangle,
  ArrowRight,
  Eye,
  EyeOff,
  ShieldCheck,
  Fingerprint,
  Scan,
} from 'lucide-react';

const API_BASE = 'https://sentinalai-fxjz.onrender.com';

function AuthPage({ onLogin }) {
  const [mode, setMode] = useState('signin'); // 'signin' or 'signup'
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    const endpoint = mode === 'signup' ? '/api/auth/signup' : '/api/auth/signin';
    const payload = mode === 'signup'
      ? { name, email, password }
      : { email, password };

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Authentication failed');
      }

      // Store token and user info
      localStorage.setItem('sentinal_token', data.token);
      localStorage.setItem('sentinal_user', JSON.stringify(data.user));

      // Notify parent
      onLogin(data.user);
    } catch (err) {
      setError(err.message || 'Something went wrong. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const switchMode = () => {
    setMode(mode === 'signin' ? 'signup' : 'signin');
    setError(null);
    setName('');
    setEmail('');
    setPassword('');
  };

  return (
    <div className="min-h-screen bg-transparent flex flex-col font-sans text-slate-250 selection:bg-indigo-500/20 selection:text-indigo-200">
      {/* Background decorative elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl"></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-violet-500/3 rounded-full blur-3xl"></div>
      </div>

      {/* Content */}
      <div className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 py-8">
        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="inline-flex items-center justify-center bg-gradient-to-br from-cyan-600 to-indigo-600 p-3.5 rounded-2xl text-white shadow-lg shadow-cyan-500/20 mb-4">
            <Shield size={28} className="stroke-[2.5]" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-white leading-tight" style={{ fontFamily: "'Outfit', sans-serif" }}>
            Sentinal AI
          </h1>
          <p className="text-[11px] text-slate-400 font-semibold tracking-widest uppercase mt-1">
            Autonomous SOC Analyst Platform
          </p>
        </div>

        {/* Auth Card */}
        <div className="w-full max-w-md">
          <div className="auth-card cyber-glass rounded-2xl border border-slate-800/80 overflow-hidden shadow-2xl shadow-indigo-950/20">
            {/* Card Header with mode toggle */}
            <div className="flex border-b border-slate-900 bg-slate-950/40">
              <button
                type="button"
                onClick={() => { setMode('signin'); setError(null); }}
                className={`flex-1 py-3.5 px-4 font-semibold text-xs flex items-center justify-center gap-2 transition-all duration-300 ${
                  mode === 'signin'
                    ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-950/10 shadow-[inset_0_-10px_20px_-10px_rgba(6,182,212,0.15)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/5'
                }`}
              >
                <Fingerprint size={14} />
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setMode('signup'); setError(null); }}
                className={`flex-1 py-3.5 px-4 font-semibold text-xs flex items-center justify-center gap-2 transition-all duration-300 ${
                  mode === 'signup'
                    ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-950/10 shadow-[inset_0_-10px_20px_-10px_rgba(6,182,212,0.15)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/5'
                }`}
              >
                <ShieldCheck size={14} />
                Create Account
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              {/* Error display */}
              {error && (
                <div className="bg-rose-950/25 border border-rose-900/40 text-rose-200 px-4 py-3 rounded-xl flex items-start gap-3 animate-in fade-in duration-300">
                  <AlertTriangle className="shrink-0 text-rose-500 mt-0.5" size={16} />
                  <p className="text-xs leading-relaxed">{error}</p>
                </div>
              )}

              {/* Name field (signup only) */}
              {mode === 'signup' && (
                <div className="animate-in fade-in slide-in-from-top-2 duration-300">
                  <label className="text-slate-200 text-xs font-bold mb-1.5 block tracking-wide">
                    Full Name
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                      <User size={14} />
                    </div>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="John Doe"
                      required
                      className="auth-input w-full pl-10 pr-4 py-2.5 bg-slate-950/60 border border-slate-800/80 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/80 transition-all text-xs"
                    />
                  </div>
                </div>
              )}

              {/* Email field */}
              <div>
                <label className="text-slate-200 text-xs font-bold mb-1.5 block tracking-wide">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Mail size={14} />
                  </div>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@example.com"
                    required
                    className="auth-input w-full pl-10 pr-4 py-2.5 bg-slate-950/60 border border-slate-800/80 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/80 transition-all text-xs"
                  />
                </div>
              </div>

              {/* Password field */}
              <div>
                <label className="text-slate-200 text-xs font-bold mb-1.5 block tracking-wide">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Lock size={14} />
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={mode === 'signup' ? 'Min 6 characters' : 'Enter your password'}
                    required
                    minLength={mode === 'signup' ? 6 : undefined}
                    className="auth-input w-full pl-10 pr-10 py-2.5 bg-slate-950/60 border border-slate-800/80 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/80 transition-all text-xs"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>

              {/* Submit button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed text-white font-bold py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg shadow-indigo-500/20 active:scale-[0.98] text-xs mt-2"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    {mode === 'signup' ? 'Creating Account...' : 'Signing In...'}
                  </>
                ) : (
                  <>
                    <Scan size={14} />
                    {mode === 'signup' ? 'Create Account' : 'Sign In'}
                    <ArrowRight size={14} />
                  </>
                )}
              </button>
            </form>

            {/* Switch mode footer */}
            <div className="px-6 pb-5 text-center">
              <p className="text-slate-500 text-[11px]">
                {mode === 'signin' ? "Don't have an account?" : 'Already have an account?'}{' '}
                <button
                  type="button"
                  onClick={switchMode}
                  className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
                >
                  {mode === 'signin' ? 'Create one' : 'Sign in'}
                </button>
              </p>
            </div>
          </div>

          {/* Security badge */}
          <div className="mt-5 flex items-center justify-center gap-2 text-slate-600 text-[10px]">
            <Lock size={10} />
            <span>Secured with JWT Authentication • 256-bit Encryption</span>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="relative z-10 mt-auto border-t border-slate-900 bg-slate-950/20 py-5 text-center text-slate-500 text-[11px] font-medium tracking-wide">
        <p>SENTINAL AI &copy; 2026. SECURE DISCLOSURE SYSTEM. PRIVILEGED ACCESS ONLY.</p>
      </footer>
    </div>
  );
}

export default AuthPage;
