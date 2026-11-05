import { useState } from 'react'
import { KeyRound } from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../App'
import { ErrorBox, Section } from '../components/ui'

export default function Account() {
  const { user, setUser } = useAuth()
  const [f, setF] = useState({ cur: '', n1: '', n2: '' })
  const [err, setErr] = useState(null)
  const submit = async (e) => {
    e.preventDefault(); setErr(null)
    if (f.n1 !== f.n2) { setErr('New passwords do not match'); return }
    try { await api.changePassword(f.cur, f.n1); alert('Password changed. Please sign in again.'); setUser(null) } catch (ex) { setErr(ex.message) }
  }
  return (
    <div className="max-w-xl space-y-6">
      <h1 className="h-title text-2xl">Account</h1>
      {user.must_change_password && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-200 text-sm px-3 py-2">Your password was set by an administrator. Please change it now.</div>}
      <Section title="Profile"><dl className="grid grid-cols-2 gap-3 text-sm">
        <div><dt className="text-xs text-slate-400">Username</dt><dd className="text-white">{user.username}</dd></div>
        <div><dt className="text-xs text-slate-400">Role</dt><dd className="text-white">{user.role}</dd></div></dl></Section>
      <Section title="Change password" icon={KeyRound}>
        <form onSubmit={submit} className="space-y-3">
          <ErrorBox error={err} />
          <div><label className="label">Current password</label><input type="password" className="input" required autoComplete="current-password" value={f.cur} onChange={e => setF({ ...f, cur: e.target.value })} /></div>
          <div><label className="label">New password</label><input type="password" className="input" required minLength={12} maxLength={128} autoComplete="new-password" value={f.n1} onChange={e => setF({ ...f, n1: e.target.value })} /></div>
          <div><label className="label">Confirm new password</label><input type="password" className="input" required minLength={12} maxLength={128} autoComplete="new-password" value={f.n2} onChange={e => setF({ ...f, n2: e.target.value })} /></div>
          <button className="btn-primary">Update password</button>
          <p className="text-[11px] text-slate-500">Changing your password signs out all of your active sessions.</p>
        </form>
      </Section>
    </div>
  )
}
