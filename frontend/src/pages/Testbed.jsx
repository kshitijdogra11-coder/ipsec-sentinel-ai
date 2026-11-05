import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FlaskConical, Play, ShieldCheck, ShieldX } from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../App'
import { ErrorBox, Section } from '../components/ui'

const TRAFFIC = ['web', 'voip', 'video', 'whatsapp', 'email', 'icmp']
const RISKY = ['legacy-ikev1-main', 'insecure-aggressive-psk', 'null-encryption', 'ah-integrity-only']

export default function Testbed() {
  const { user } = useAuth()
  const [presets, setPresets] = useState([])
  const [sel, setSel] = useState('enterprise-default')
  const [opt, setOpt] = useState({ traffic: 'web', ip_version: null, mode: null, nat_t: null, pfs: null, replay_attack: false, duration: 120 })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const nav = useNavigate()
  useEffect(() => { api.presets().then(setPresets).catch(e => setErr(e.message)) }, [])
  const set = (k, v) => setOpt(o => ({ ...o, [k]: v }))

  const run = async () => {
    setBusy(true); setErr(null)
    try { const a = await api.generate({ preset: sel, ...opt }); nav(`/analyses/${a.id}`) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  const Tri = ({ k, a, b, labels }) => (
    <div className="flex rounded-lg border border-ink-600 overflow-hidden text-xs">
      {[[null, 'preset'], [a, labels[0]], [b, labels[1]]].map(([v, l]) => (
        <button key={String(v)} type="button" onClick={() => set(k, v)} className={`flex-1 px-2 py-1.5 ${opt[k] === v ? 'bg-cyan-500/20 text-cyan-200' : 'text-slate-400 hover:bg-ink-800'}`}>{l}</button>))}
    </div>
  )
  return (
    <div className="space-y-6">
      <div>
        <h1 className="h-title text-2xl flex items-center gap-2"><FlaskConical className="w-6 h-6 text-cyan-300" />VPN Testbed</h1>
        <p className="muted text-sm mt-1">Establish a simulated IPsec VPN with a chosen security configuration, capture its traffic (IKE + ESP/AH + background) with real encryption, and analyse it end-to-end. Ground truth is kept to measure AI accuracy.</p>
      </div>
      <ErrorBox error={err} />
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-3">
          {presets.map(p => (
            <button key={p.name} onClick={() => setSel(p.name)} className={`card text-left p-4 transition ${sel === p.name ? 'ring-2 ring-cyan-400 border-transparent' : 'hover:border-ink-600'}`}>
              <div className="flex items-center justify-between">
                <div className="font-medium text-white">{p.name}</div>
                {RISKY.includes(p.name) ? <ShieldX className="w-4 h-4 text-red-400" /> : <ShieldCheck className="w-4 h-4 text-emerald-400" />}
              </div>
              <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
                <span className="text-slate-400">IKE</span><span className="mono text-slate-200">v{p.ike_version}{p.ike_version === 1 ? ` ${p.ikev1_mode}` : ''} · {p.auth}</span>
                <span className="text-slate-400">IKE SA</span><span className="mono text-slate-200 break-all">{p.ike}</span>
                <span className="text-slate-400">{p.protocol}</span><span className="mono text-slate-200 break-all">{p.esp}</span>
                <span className="text-slate-400">Mode / IP</span><span className="mono text-slate-200">{p.mode} · IPv{p.ip_version}{p.nat_t ? ' · NAT-T' : ''}</span>
                <span className="text-slate-400">PFS / lifetime</span><span className="mono text-slate-200">{p.pfs ? 'on' : 'off'} · {p.child_lifetime}s</span>
              </div>
            </button>))}
        </div>
        <Section title="Capture options" className="h-fit xl:sticky xl:top-6">
          <div className="space-y-4">
            <div><div className="label">Application traffic inside tunnel</div>
              <div className="grid grid-cols-3 gap-1.5">{TRAFFIC.map(t => <button key={t} type="button" onClick={() => set('traffic', t)} className={`rounded-md px-2 py-1.5 text-xs capitalize border ${opt.traffic === t ? 'border-cyan-400 bg-cyan-500/15 text-cyan-200' : 'border-ink-600 text-slate-300 hover:bg-ink-800'}`}>{t}</button>)}</div></div>
            <div><div className="label">Operating mode</div><Tri k="mode" a="tunnel" b="transport" labels={['tunnel', 'transport']} /></div>
            <div><div className="label">IP version</div><Tri k="ip_version" a={4} b={6} labels={['IPv4', 'IPv6']} /></div>
            <div><div className="label">Perfect Forward Secrecy</div><Tri k="pfs" a={true} b={false} labels={['enabled', 'disabled']} /></div>
            <div><div className="label">NAT traversal</div><Tri k="nat_t" a={true} b={false} labels={['UDP 4500', 'off']} /></div>
            <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={opt.replay_attack} onChange={e => set('replay_attack', e.target.checked)} className="accent-cyan-400" />Inject replay attack (re-sent ESP packets)</label>
            <div><div className="label">Capture duration: {opt.duration}s</div><input type="range" min={30} max={300} step={10} value={opt.duration} onChange={e => set('duration', +e.target.value)} className="w-full accent-cyan-400" /></div>
            <button className="btn-primary w-full justify-center" onClick={run} disabled={busy || user.role === 'viewer'}><Play className="w-4 h-4" />{busy ? 'Establishing VPN & capturing…' : 'Generate & analyse'}</button>
            {user.role === 'viewer' && <p className="text-xs text-slate-500">Viewer accounts cannot run the testbed.</p>}
            <p className="text-[11px] text-slate-500">For a real lab, see <span className="mono">testbed/</span> in the repository: strongSwan Docker topology with 12 configuration profiles and tcpdump capture scripts.</p>
          </div>
        </Section>
      </div>
    </div>
  )
}
