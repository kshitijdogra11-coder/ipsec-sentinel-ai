import { useState } from 'react'
import { KeyRound, Lock, ShieldHalf } from 'lucide-react'
import { api } from '../api'
import { ErrorBox } from '../components/ui'

export default function Login({ onLogin }) {
  const [username, setU] = useState('')
  const [password, setP] = useState('')
  const [err, setErr] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setErr(null)
    try {
      const r = await api.login(username.trim(), password)
      setP('')
      onLogin(r.user)
    } catch (ex) { setErr(ex.message) } finally { setBusy(false) }
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-2">
      <div className="hidden lg:flex flex-col justify-between p-12 bg-gradient-to-br from-ink-900 via-ink-950 to-[#04222b] border-r border-ink-700">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 ring-1 ring-cyan-400/30"><ShieldHalf className="w-7 h-7 text-cyan-300" /></div>
          <div className="text-lg font-semibold text-white">IPsec Sentinel <span className="text-cyan-300">AI</span></div>
        </div>
        <div>
          <h1 className="text-4xl font-semibold text-white leading-tight tracking-tight">See inside your VPN's<br />security posture —<br /><span className="text-cyan-300">without decrypting it.</span></h1>
          <p className="mt-5 text-slate-400 max-w-md">AI-driven identification of IKE/ESP parameters, tunnel mode, cipher suites and application traffic from encrypted captures, with automated compliance scoring and signed reports.</p>
          <div className="mt-8 grid grid-cols-3 gap-3 max-w-md text-center">
            {[['IKEv1 / IKEv2', 'dissection'], ['4 AI models', 'classifiers'], ['NIST · RFC · CNSA', 'compliance']].map(([a, b]) => (
              <div key={a} className="card px-3 py-3"><div className="text-sm font-semibold text-white">{a}</div><div className="text-[11px] text-slate-400">{b}</div></div>
            ))}
          </div>
        </div>
        <div className="text-xs text-slate-500">Smart India Hackathon · SIH26160 · National Technical Research Organisation</div>
      </div>
      <div className="flex items-center justify-center p-6">
        <form onSubmit={submit} className="w-full max-w-sm space-y-5" autoComplete="on">
          <div>
            <div className="flex items-center gap-2 text-cyan-300 text-sm font-medium"><Lock className="w-4 h-4" />Secure sign-in</div>
            <h2 className="text-2xl font-semibold text-white mt-2">Analyst console</h2>
            <p className="text-sm text-slate-400 mt-1">Sessions use Argon2id, short-lived signed tokens and HttpOnly cookies.</p>
          </div>
          <ErrorBox error={err} />
          <div>
            <label className="label" htmlFor="u">Username</label>
            <input id="u" className="input" value={username} onChange={e => setU(e.target.value)} autoComplete="username" required maxLength={64} />
          </div>
          <div>
            <label className="label" htmlFor="p">Password</label>
            <input id="p" type="password" className="input" value={password} onChange={e => setP(e.target.value)} autoComplete="current-password" required maxLength={128} />
          </div>
          <button className="btn-primary w-full justify-center" disabled={busy}><KeyRound className="w-4 h-4" />{busy ? 'Verifying…' : 'Sign in'}</button>
          <p className="text-[11px] text-slate-500">Accounts lock for 15 minutes after 5 failed attempts. All access is recorded in a tamper-evident audit log.</p>
        </form>
      </div>
    </div>
  )
}
