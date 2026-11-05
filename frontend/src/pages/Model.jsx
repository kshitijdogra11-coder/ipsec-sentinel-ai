import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { BrainCircuit, Database, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorBox, Section, Stat, tooltipStyle } from '../components/ui'

const NAMES = { cipher: 'ESP cipher family', icv: 'Integrity (ICV) class', mode: 'Tunnel vs transport', traffic: 'Traffic inside ESP' }

function Confusion({ m }) {
  const max = Math.max(...m.confusion_matrix.flat(), 1)
  return (
    <div className="overflow-x-auto scroll-thin">
      <table className="text-[11px] mx-auto">
        <thead><tr><th className="p-1 text-slate-500 text-right">true \ pred</th>{m.labels.map(l => <th key={l} className="p-1 text-slate-400 font-medium">{l}</th>)}</tr></thead>
        <tbody>{m.confusion_matrix.map((row, i) => (
          <tr key={i}><td className="p-1 text-slate-400 text-right pr-2">{m.labels[i]}</td>
            {row.map((v, j) => <td key={j} className="p-0.5"><div className="w-12 h-8 rounded flex items-center justify-center mono"
              style={{ background: i === j ? `rgba(34,211,238,${0.12 + 0.8 * v / max})` : v ? `rgba(239,68,68,${0.15 + 0.7 * v / max})` : '#0b1220', color: v ? '#fff' : '#334155' }}>{v}</div></td>)}
          </tr>))}</tbody>
      </table>
    </div>
  )
}

export default function Model() {
  const [m, setM] = useState(null)
  const [d, setD] = useState(null)
  const [err, setErr] = useState(null)
  useEffect(() => { api.model().then(setM).catch(e => setErr(e.message)); api.dataset().then(setD).catch(() => {}) }, [])
  if (err) return <ErrorBox error={err} />
  if (!m) return <div className="muted">Loading…</div>
  if (m.status !== 'verified') return <ErrorBox error={`Model unavailable: ${m.error}`} />
  const dist = (k) => Object.entries(d?.distributions?.[k] || {}).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
  return (
    <div className="space-y-6">
      <div>
        <h1 className="h-title text-2xl flex items-center gap-2"><BrainCircuit className="w-6 h-6 text-cyan-300" />AI Classification Engine</h1>
        <p className="muted text-sm mt-1">{m.algorithm} models trained on side-channel features of encrypted IPsec traffic. Evaluation on a grouped (per-capture) 20% hold-out set.</p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <Stat icon={Database} label="Training captures (ESP)" value={m.dataset?.captures} sub={`${m.dataset?.traffic_windows} traffic windows`} />
        <Stat icon={BrainCircuit} label="Models" value="4" sub="cipher · ICV · mode · traffic" tone="violet" />
        <Stat icon={ShieldCheck} label="Integrity" value="Verified" sub={`SHA-256 ${m.sha256?.slice(0, 16)}…`} tone="green" />
        <Stat label="Version" value={m.version} sub="RandomForest · scikit-learn" tone="amber" />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {Object.entries(m.metrics || {}).map(([k, v]) => (
          <Section key={k} title={NAMES[k] || k} right={<span className="text-xs mono text-slate-300">acc {(v.accuracy * 100).toFixed(1)}% · F1 {(v.macro_f1 * 100).toFixed(1)}%</span>}>
            <Confusion m={v} />
            <div className="mt-4 label">Top features</div>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={v.top_features.slice(0, 8)} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid stroke="#1c2843" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={10} />
                <YAxis type="category" dataKey="feature" stroke="#94a3b8" fontSize={10} width={110} />
                <Tooltip {...tooltipStyle} cursor={{ fill: '#131d33' }} />
                <Bar dataKey="importance" fill="#a78bfa" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Section>))}
      </div>
      <Section title="Training / testing dataset" icon={Database}>
        {d?.available ? (
          <>
            <p className="text-sm text-slate-300 mb-4">{d.captures} labelled captures · {d.total_packets?.toLocaleString()} packets ({d.esp_packets?.toLocaleString()} data-plane). Generated from the configuration matrix (tunnel/transport, AES-128/256, AES-GCM, AES-CBC+HMAC, 3DES, NULL, DH groups 1–31, PFS on/off, IPv4/IPv6, NAT-T, 6 traffic classes).</p>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              {['traffic', 'mode', 'esp_encr', 'dh_group', 'ike_version', 'pfs', 'ip_version', 'esp_integ'].map(k => (
                <div key={k} className="rounded-lg border border-ink-700 p-3"><div className="label">{k}</div>
                  <ul className="text-xs space-y-1">{dist(k).map(x => <li key={x.name} className="flex justify-between"><span className="text-slate-300">{x.name}</span><span className="mono text-slate-400">{x.value}</span></li>)}</ul></div>))}
            </div>
            {d.sample_files?.length > 0 && <p className="text-xs text-slate-500 mt-4">Sample captures shipped in <span className="mono">dataset/samples/</span>: {d.sample_files.join(', ')}</p>}
          </>
        ) : <Empty>Dataset summary not available.</Empty>}
      </Section>
    </div>
  )
}
