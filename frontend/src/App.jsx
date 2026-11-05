import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import {
  Activity, BrainCircuit, FlaskConical, LayoutDashboard, LogOut, ScrollText, Settings, ShieldHalf, UploadCloud, Users,
} from 'lucide-react'
import { api, setUnauthorizedHandler } from './api'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Analyses from './pages/Analyses'
import AnalysisDetail from './pages/AnalysisDetail'
import Testbed from './pages/Testbed'
import Model from './pages/Model'
import Admin from './pages/Admin'
import Account from './pages/Account'

const AuthCtx = createContext(null)
export const useAuth = () => useContext(AuthCtx)

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/analyses', label: 'Analyze Captures', icon: UploadCloud },
  { to: '/testbed', label: 'VPN Testbed', icon: FlaskConical },
  { to: '/model', label: 'AI Engine & Dataset', icon: BrainCircuit },
  { to: '/admin', label: 'Users & Audit', icon: Users, role: 'admin' },
  { to: '/account', label: 'Account', icon: Settings },
]

function Shell({ children }) {
  const { user, logout } = useAuth()
  return (
    <div className="min-h-screen flex">
      <aside className="w-64 shrink-0 border-r border-ink-700/70 bg-ink-900/60 hidden md:flex flex-col">
        <div className="px-5 py-5 flex items-center gap-3 border-b border-ink-700/70">
          <div className="p-2 rounded-lg bg-cyan-500/10 ring-1 ring-cyan-400/30"><ShieldHalf className="w-6 h-6 text-cyan-300" /></div>
          <div>
            <div className="font-semibold text-white leading-tight">IPsec Sentinel <span className="text-cyan-300">AI</span></div>
            <div className="text-[11px] text-slate-400">VPN Protocol Analyzer</div>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1">
          {NAV.filter(n => !n.role || n.role === user.role).map(n => (
            <NavLink key={n.to} to={n.to} end={n.end}
              className={({ isActive }) => `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition ${isActive ? 'bg-cyan-500/10 text-cyan-200 ring-1 ring-cyan-400/20' : 'text-slate-300 hover:bg-ink-800'}`}>
              <n.icon className="w-4 h-4" />{n.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-ink-700/70">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-ink-700 flex items-center justify-center text-sm font-semibold text-cyan-200">
              {user.username.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm text-white truncate">{user.full_name || user.username}</div>
              <div className="text-[11px] uppercase tracking-wider text-slate-400">{user.role}</div>
            </div>
            <button onClick={logout} className="p-2 rounded-lg hover:bg-ink-800 text-slate-400" title="Sign out" aria-label="Sign out">
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="md:hidden flex items-center justify-between px-4 py-3 border-b border-ink-700">
          <div className="flex items-center gap-2 font-semibold text-white"><ShieldHalf className="w-5 h-5 text-cyan-300" />IPsec Sentinel AI</div>
          <button onClick={logout} className="btn-ghost !py-1">Sign out</button>
        </header>
        <nav className="md:hidden flex gap-1 overflow-x-auto px-2 py-2 border-b border-ink-700 scroll-thin">
          {NAV.filter(n => !n.role || n.role === user.role).map(n => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => `whitespace-nowrap px-3 py-1.5 rounded-md text-xs ${isActive ? 'bg-cyan-500/15 text-cyan-200' : 'text-slate-300'}`}>{n.label}</NavLink>
          ))}
        </nav>
        <main className="flex-1 p-4 md:p-8 max-w-[1500px] w-full mx-auto">{children}</main>
        <footer className="px-8 py-4 text-[11px] text-slate-500 border-t border-ink-800 flex items-center gap-2">
          <Activity className="w-3 h-3" /> SIH26160 · NTRO · AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
        </footer>
      </div>
    </div>
  )
}

export default function App() {
  const [user, setUser] = useState(undefined)
  const nav = useNavigate()

  useEffect(() => { api.me().then(setUser).catch(() => setUser(null)) }, [])
  useEffect(() => { setUnauthorizedHandler(() => setUser(null)) }, [])

  const logout = useCallback(async () => {
    try { await api.logout() } catch { /* session may already be gone */ }
    setUser(null); nav('/login')
  }, [nav])

  if (user === undefined) {
    return <div className="min-h-screen flex items-center justify-center text-slate-400">Loading…</div>
  }
  return (
    <AuthCtx.Provider value={{ user, setUser, logout }}>
      {!user ? (
        <Routes>
          <Route path="*" element={<Login onLogin={(u) => { setUser(u); nav('/') }} />} />
        </Routes>
      ) : (
        <Shell>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyses" element={<Analyses />} />
            <Route path="/analyses/:id" element={<AnalysisDetail />} />
            <Route path="/testbed" element={<Testbed />} />
            <Route path="/model" element={<Model />} />
            <Route path="/admin" element={user.role === 'admin' ? <Admin /> : <Navigate to="/" />} />
            <Route path="/account" element={<Account />} />
            <Route path="/login" element={<Navigate to="/" />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </Shell>
      )}
    </AuthCtx.Provider>
  )
}
