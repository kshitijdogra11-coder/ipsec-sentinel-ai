import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { AlertOctagon, BrainCircuit, FileSearch, Gauge as GaugeIcon, ArrowRight, Radar } from 'lucide-react'
import { api } from '../api'
import { Empty, GRADE, GradeBadge, PALETTE, Section, Stat, StatusChip, fmtDate, tooltipStyle } from '../components/ui'

const toArr = (o) => Object.entries(o || {}).map(([name, value]) => ({ name, value }))

export default function Dashboard() {
  const [s, setS] = useState(null)
  useEffect(() => {
    const load = () => api.stats().then(setS).catch(() => {})
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])
  if (!s) return <div className="muted">Loading dashboard…</div>
  const acc = s.testbed_accuracy
  const gradeData = ['A', 'B', 'C', 'D', 'F'].map(g => ({ name: g, value: s.grades[g] || 0 }))
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="h-title text-2xl">Security Operations Overview</h1>
          <p className="muted text-sm mt-1">Posture of analysed IPsec deployments across uploaded and testbed captures.</p>
        </div>
        <div className="flex gap-2">
          <Link to="/testbed" className="btn-ghost"><Radar className="w-4 h-4" />Generate test VPN</Link>
          <Link to="/analyses" className="btn-primary"><FileSearch className="w-4 h-4" />Analyze capture</Link>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <Stat icon={FileSearch} label="Captures analysed" value={s.done} sub={`${s.running} in progress · ${s.failed} failed`} />
        <Stat icon={GaugeIcon} label="Average security score" value={s.avg_score ?? '–'} sub="0 – 100, higher is better" tone="green" />
        <Stat icon={AlertOctagon} label="Critical / High findings" value={`${s.critical_findings} / ${s.high_findings}`} sub="across all tunnels" tone="red" />
        <Stat icon={BrainCircuit} label="AI accuracy (testbed)" tone="violet"
          value={acc ? `${Math.round(((acc.mode + acc.traffic + acc.encryption) / 3) * 100)}%` : '–'}
          sub={acc ? `mode ${Math.round(acc.mode * 100)}% · cipher ${Math.round(acc.encryption * 100)}% · traffic ${Math.round(acc.traffic * 100)}% (n=${acc.n})` : 'run testbed captures to measure'} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Section title="Security score trend" className="xl:col-span-2">
          {s.score_trend.length ? (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={s.score_trend.map((d, i) => ({ ...d, i: i + 1 }))}>
                <CartesianGrid stroke="#1c2843" vertical={false} />
                <XAxis dataKey="i" stroke="#64748b" fontSize={11} />
                <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                <Tooltip {...tooltipStyle} formatter={(v) => [v, 'score']} labelFormatter={(i) => s.score_trend[i - 1]?.file} />
                <Line type="monotone" dataKey="score" stroke="#22d3ee" strokeWidth={2} dot={{ r: 3, fill: '#22d3ee' }} />
              </LineChart>
            </ResponsiveContainer>
          ) : <Empty>No completed analyses yet.</Empty>}
        </Section>
        <Section title="Grade distribution">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={gradeData}>
              <CartesianGrid stroke="#1c2843" vertical={false} />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis allowDecimals={false} stroke="#64748b" fontSize={11} />
              <Tooltip {...tooltipStyle} cursor={{ fill: '#131d33' }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>{gradeData.map(d => <Cell key={d.name} fill={GRADE[d.name]} />)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </Section>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[['Traffic inside tunnels (AI)', s.traffic], ['Encryption identified', s.encryption], ['IPsec mode', s.modes]].map(([t, d]) => (
          <Section key={t} title={t}>
            {toArr(d).length ? (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width="50%" height={160}>
                  <PieChart><Pie data={toArr(d)} dataKey="value" nameKey="name" innerRadius={42} outerRadius={70} paddingAngle={2} stroke="none">
                    {toArr(d).map((_, i) => <Cell key={i} fill={PALETTE[i % PALETTE.length]} />)}</Pie>
                    <Tooltip {...tooltipStyle} /></PieChart>
                </ResponsiveContainer>
                <ul className="text-xs space-y-1.5 flex-1 min-w-0">
                  {toArr(d).sort((a, b) => b.value - a.value).map((x, i) => (
                    <li key={x.name} className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: PALETTE[toArr(d).findIndex(y => y.name === x.name) % PALETTE.length] }} />
                      <span className="truncate text-slate-300">{x.name}</span><span className="ml-auto mono text-slate-400">{x.value}</span></li>
                  ))}
                </ul>
              </div>
            ) : <Empty>No data</Empty>}
          </Section>
        ))}
      </div>

      <Section title="Recent analyses" right={<Link to="/analyses" className="text-xs text-cyan-300 hover:underline flex items-center gap-1">View all <ArrowRight className="w-3 h-3" /></Link>}>
        {s.recent.length ? (
          <div className="overflow-x-auto -m-5 scroll-thin">
            <table className="w-full">
              <thead><tr><th className="th">Capture</th><th className="th">Status</th><th className="th">Grade</th><th className="th">IKE</th><th className="th">Mode</th><th className="th">Encryption</th><th className="th">Traffic</th><th className="th">When</th></tr></thead>
              <tbody>{s.recent.map(a => (
                <tr key={a.id} className="hover:bg-ink-800/50">
                  <td className="td"><Link to={`/analyses/${a.id}`} className="text-cyan-200 hover:underline">{a.filename}</Link></td>
                  <td className="td"><StatusChip s={a.status} /></td>
                  <td className="td"><GradeBadge grade={a.grade} size="sm" /></td>
                  <td className="td">{a.ike_version || '–'}</td><td className="td">{a.mode || '–'}</td>
                  <td className="td mono">{a.encryption || '–'}</td><td className="td">{a.traffic || '–'}</td>
                  <td className="td text-slate-400 text-xs">{fmtDate(a.created_at)}</td>
                </tr>))}
              </tbody>
            </table>
          </div>
        ) : <Empty>Upload a capture or generate one in the VPN Testbed to get started.</Empty>}
      </Section>
    </div>
  )
}
