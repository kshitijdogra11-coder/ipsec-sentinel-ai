import { AlertTriangle, Info, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react'

export const SEV = {
  Critical: { cls: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30', dot: '#ef4444' },
  High: { cls: 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/30', dot: '#f97316' },
  Medium: { cls: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30', dot: '#f59e0b' },
  Low: { cls: 'bg-blue-500/15 text-blue-300 ring-1 ring-blue-500/30', dot: '#3b82f6' },
  Info: { cls: 'bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/30', dot: '#64748b' },
}
export const GRADE = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' }
export const PALETTE = ['#22d3ee', '#a78bfa', '#f472b6', '#34d399', '#fbbf24', '#60a5fa', '#fb7185', '#94a3b8']

export function SevChip({ s }) {
  return <span className={`chip ${SEV[s]?.cls || SEV.Info.cls}`}>{s}</span>
}

export function StatusChip({ s }) {
  const m = {
    done: 'bg-emerald-500/15 text-emerald-300', running: 'bg-cyan-500/15 text-cyan-300 animate-pulse',
    queued: 'bg-slate-500/15 text-slate-300', failed: 'bg-red-500/15 text-red-300',
  }
  return <span className={`chip ${m[s] || m.queued}`}>{s}</span>
}

export function GradeBadge({ grade, size = 'md' }) {
  const c = GRADE[grade] || '#64748b'
  const sz = size === 'lg' ? 'w-14 h-14 text-2xl' : size === 'sm' ? 'w-7 h-7 text-xs' : 'w-9 h-9 text-base'
  return (
    <span className={`${sz} inline-flex items-center justify-center rounded-lg font-bold`}
      style={{ background: c + '22', color: c, boxShadow: `inset 0 0 0 1px ${c}55` }}>{grade || '–'}</span>
  )
}

export function RiskIcon({ level, className = 'w-5 h-5' }) {
  if (level === 'Low') return <ShieldCheck className={`${className} text-emerald-400`} />
  if (level === 'Moderate') return <ShieldAlert className={`${className} text-amber-400`} />
  if (level === 'High') return <AlertTriangle className={`${className} text-orange-400`} />
  if (level === 'Critical') return <ShieldX className={`${className} text-red-400`} />
  return <Info className={`${className} text-slate-400`} />
}

export function ConfBar({ value, className = '' }) {
  const v = Math.max(0, Math.min(1, value || 0))
  const col = v >= 0.9 ? 'bg-emerald-400' : v >= 0.7 ? 'bg-cyan-400' : v >= 0.5 ? 'bg-amber-400' : 'bg-red-400'
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="h-1.5 flex-1 rounded-full bg-ink-700 overflow-hidden">
        <div className={`h-full ${col} rounded-full`} style={{ width: `${v * 100}%` }} />
      </div>
      <span className="mono text-slate-300 w-10 text-right">{(v * 100).toFixed(0)}%</span>
    </div>
  )
}

export function Gauge({ score, grade, size = 180 }) {
  const s = Math.max(0, Math.min(100, score ?? 0))
  const r = 70, c = Math.PI * r
  const col = GRADE[grade] || '#64748b'
  return (
    <svg viewBox="0 0 180 110" width={size} height={size * 110 / 180} role="img" aria-label={`Security score ${s}`}>
      <path d="M20 95 A70 70 0 0 1 160 95" stroke="#1c2843" strokeWidth="14" fill="none" strokeLinecap="round" />
      <path d="M20 95 A70 70 0 0 1 160 95" stroke={col} strokeWidth="14" fill="none" strokeLinecap="round"
        strokeDasharray={`${(c * s) / 100} ${c}`} style={{ transition: 'stroke-dasharray .8s ease' }} />
      <text x="90" y="82" textAnchor="middle" fill="#fff" fontSize="34" fontWeight="700">{score == null ? '–' : Math.round(s)}</text>
      <text x="90" y="102" textAnchor="middle" fill="#94a3b8" fontSize="10">SECURITY SCORE</text>
    </svg>
  )
}

export function Stat({ icon: Icon, label, value, sub, tone = 'cyan' }) {
  const tones = { cyan: 'text-cyan-300 bg-cyan-500/10', red: 'text-red-300 bg-red-500/10', green: 'text-emerald-300 bg-emerald-500/10', violet: 'text-violet-300 bg-violet-500/10', amber: 'text-amber-300 bg-amber-500/10' }
  return (
    <div className="card card-pad flex items-start gap-4">
      {Icon && <div className={`p-2.5 rounded-lg ${tones[tone]}`}><Icon className="w-5 h-5" /></div>}
      <div className="min-w-0">
        <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
        <div className="text-2xl font-semibold text-white mt-0.5">{value}</div>
        {sub && <div className="text-xs text-slate-400 mt-0.5 truncate">{sub}</div>}
      </div>
    </div>
  )
}

export function Section({ title, icon: Icon, right, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      <header className="flex items-center justify-between px-5 py-3.5 border-b border-ink-700/70">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-white">{Icon && <Icon className="w-4 h-4 text-cyan-400" />}{title}</h3>
        {right}
      </header>
      <div className="p-5">{children}</div>
    </section>
  )
}

export function Empty({ children }) {
  return <div className="text-center text-sm text-slate-400 py-10">{children}</div>
}

export function ErrorBox({ error }) {
  if (!error) return null
  return <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-200 text-sm px-3 py-2">{String(error)}</div>
}

export const fmtBytes = (b) => {
  if (b == null) return '–'
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0; let v = b
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`
}
export const fmtDate = (s) => s ? new Date(s).toLocaleString() : '–'
export const pct = (v) => v == null ? '–' : `${(v * 100).toFixed(0)}%`

export const tooltipStyle = {
  contentStyle: { background: '#0b1220', border: '1px solid #2a3a5e', borderRadius: 8, fontSize: 12, color: '#e2e8f0' },
  itemStyle: { color: '#e2e8f0' }, labelStyle: { color: '#94a3b8' },
}
