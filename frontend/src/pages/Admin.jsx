import { useCallback, useEffect, useState } from 'react'
import { Link2, Lock, ShieldCheck, ShieldX, Trash2, Unlock, UserPlus } from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../App'
import { ErrorBox, Section, fmtDate } from '../components/ui'

export default function Admin() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState([])
  const [audit, setAudit] = useState({ items: [], total: 0 })
  const [chain, setChain] = useState(null)
  const [err, setErr] = useState(null)
  const [nu, setNu] = useState({ username: '', full_name: '', password: '', role: 'analyst' })

  const load = useCallback(() => {
    api.users().then(setUsers).catch(e => setErr(e.message))
    api.audit().then(setAudit).catch(e => setErr(e.message))
  }, [])
  useEffect(() => { load() }, [load])

  const act = (p) => p.then(load).catch(e => setErr(e.message))
  const create = (e) => { e.preventDefault(); setErr(null); act(api.createUser(nu).then(() => setNu({ username: '', full_name: '', password: '', role: 'analyst' }))) }

  return (
    <div className="space-y-6">
      <h1 className="h-title text-2xl">Users & Audit</h1>
      <ErrorBox error={err} />
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Section title="Users" className="xl:col-span-2">
          <div className="overflow-x-auto -m-5 scroll-thin"><table className="w-full">
            <thead><tr>{['User', 'Role', 'Status', 'Last login', ''].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>{users.map(u => (
              <tr key={u.id}><td className="td"><div className="text-white">{u.username}</div><div className="text-xs text-slate-400">{u.full_name}</div></td>
                <td className="td"><select className="input !py-1 !w-auto" value={u.role} disabled={u.id === me.id} onChange={e => act(api.patchUser(u.id, { role: e.target.value }))}>
                  {['admin', 'analyst', 'viewer'].map(r => <option key={r}>{r}</option>)}</select></td>
                <td className="td">{u.locked ? <span className="chip bg-amber-500/15 text-amber-300"><Lock className="w-3 h-3" />locked</span> : u.is_active ? <span className="chip bg-emerald-500/15 text-emerald-300">active</span> : <span className="chip bg-slate-500/15 text-slate-300">disabled</span>}</td>
                <td className="td text-xs text-slate-400">{fmtDate(u.last_login)}</td>
                <td className="td whitespace-nowrap">{u.id !== me.id && (<>
                  {u.locked && <button title="Unlock" className="p-1.5 hover:bg-ink-800 rounded" onClick={() => act(api.unlockUser(u.id))}><Unlock className="w-4 h-4 text-amber-300" /></button>}
                  <button className="text-xs btn-ghost !py-1 !px-2 mr-1" onClick={() => act(api.patchUser(u.id, { is_active: !u.is_active }))}>{u.is_active ? 'Disable' : 'Enable'}</button>
                  <button title="Delete" className="p-1.5 hover:bg-red-500/10 rounded" onClick={() => confirm(`Delete ${u.username}?`) && act(api.deleteUser(u.id))}><Trash2 className="w-4 h-4 text-red-300" /></button></>)}</td>
              </tr>))}</tbody></table></div>
        </Section>
        <Section title="Create user" icon={UserPlus}>
          <form onSubmit={create} className="space-y-3">
            <div><label className="label">Username</label><input className="input" required minLength={3} maxLength={64} pattern="[A-Za-z0-9_.@-]+" value={nu.username} onChange={e => setNu({ ...nu, username: e.target.value })} /></div>
            <div><label className="label">Full name</label><input className="input" maxLength={128} value={nu.full_name} onChange={e => setNu({ ...nu, full_name: e.target.value })} /></div>
            <div><label className="label">Initial password</label><input className="input" type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={nu.password} onChange={e => setNu({ ...nu, password: e.target.value })} />
              <p className="text-[11px] text-slate-500 mt-1">≥12 chars with upper, lower, digit and symbol. User must change it at first login.</p></div>
            <div><label className="label">Role</label><select className="input" value={nu.role} onChange={e => setNu({ ...nu, role: e.target.value })}>{['analyst', 'viewer', 'admin'].map(r => <option key={r}>{r}</option>)}</select></div>
            <button className="btn-primary w-full justify-center"><UserPlus className="w-4 h-4" />Create</button>
          </form>
        </Section>
      </div>
      <Section title={`Tamper-evident audit log (${audit.total} entries)`} icon={Link2}
        right={<div className="flex items-center gap-3">
          {chain && (chain.valid ? <span className="chip bg-emerald-500/15 text-emerald-300"><ShieldCheck className="w-3 h-3" />chain intact · {chain.entries_checked}</span> : <span className="chip bg-red-500/15 text-red-300"><ShieldX className="w-3 h-3" />broken at #{chain.broken_at}</span>)}
          <button className="btn-ghost !py-1" onClick={() => api.verifyAudit().then(setChain).then(load).catch(e => setErr(e.message))}>Verify hash chain</button></div>}>
        <div className="overflow-x-auto max-h-[520px] -m-5 scroll-thin"><table className="w-full">
          <thead className="sticky top-0 bg-ink-900"><tr>{['#', 'Time', 'User', 'IP', 'Action', 'Target', 'Outcome', 'Hash'].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>{audit.items.map(e => (
            <tr key={e.id}><td className="td mono text-slate-500">{e.id}</td><td className="td text-xs whitespace-nowrap">{fmtDate(e.ts)}</td><td className="td">{e.username}</td><td className="td mono">{e.ip}</td>
              <td className="td mono text-cyan-200">{e.action}</td><td className="td text-xs mono max-w-[200px] truncate" title={e.detail}>{e.target}</td>
              <td className="td">{e.outcome === 'success' ? <span className="chip bg-emerald-500/10 text-emerald-300">success</span> : <span className="chip bg-red-500/10 text-red-300">{e.outcome}</span>}</td>
              <td className="td mono text-slate-500">{e.hash.slice(0, 12)}…</td></tr>))}</tbody></table></div>
      </Section>
    </div>
  )
}
