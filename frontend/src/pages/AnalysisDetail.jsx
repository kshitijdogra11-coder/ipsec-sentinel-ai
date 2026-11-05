import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import {
  ArrowLeft, BadgeCheck, CheckCircle2, ChevronDown, CircleHelp, Cpu, Download, Eye, FileJson, FileText, Fingerprint, KeyRound,
  ListChecks, Network, ScanSearch, ShieldAlert, Target, Timer, XCircle,
} from 'lucide-react'
import { api } from '../api'
import {
  ConfBar, Empty, ErrorBox, Gauge, GradeBadge, PALETTE, RiskIcon, SEV, Section, SevChip, StatusChip, fmtBytes, fmtDate, pct, tooltipStyle,
} from '../components/ui'

const TABS = [
  ['overview', 'Overview', Target], ['ident', 'Protocol Identification', Fingerprint], ['ike', 'IKE Negotiation', KeyRound],
  ['sa', 'Security Associations', Network], ['traffic', 'Traffic & Metadata', ScanSearch], ['threats', 'Threat Matrix & Findings', ShieldAlert],
  ['compliance', 'Compliance', ListChecks],
]
const LABELS = {
  ipsec_protocol: 'IPsec protocol', ike_version: 'IKE version', ip_version: 'IP version', nat_traversal: 'NAT traversal',
  mode: 'Operating mode', encryption: 'ESP encryption', integrity: 'Authentication / integrity', key_exchange: 'Key exchange',
  ike_encryption: 'IKE SA encryption', ike_integrity: 'IKE SA PRF / integrity', exchange_mode: 'Exchange mode',
  authentication: 'Peer authentication', pfs: 'Perfect Forward Secrecy', child_lifetime: 'Child SA lifetime (s)',
  security_associations: 'Security Associations', traffic_type: 'Traffic inside ESP',
}
const show = (v) => v === true ? 'Enabled' : v === false ? 'Disabled' : v == null ? 'Undetermined' : String(v)

export default function AnalysisDetail() {
  const { id } = useParams()
  const [a, setA] = useState(null)
  const [err, setErr] = useState(null)
  const [tab, setTab] = useState('overview')
  const [ti, setTi] = useState(0)

  useEffect(() => {
    let t
    const load = () => api.analysis(id).then(r => { setA(r); if (r.status === 'queued' || r.status === 'running') t = setTimeout(load, 1500) }).catch(e => setErr(e.message))
    load()
    return () => clearTimeout(t)
  }, [id])

  const r = a?.result
  const tun = r?.tunnels?.[ti]
  const asmt = useMemo(() => r?.assessment?.tunnels?.find(x => x.tunnel === tun?.id), [r, tun])

  if (err) return <ErrorBox error={err} />
  if (!a) return <div className="muted">Loading…</div>

  const dl = (kind, ext) => api.download(`/analyses/${a.id}/report/${kind}`, `ipsec-${kind}-report-${a.id.slice(0, 8)}.${ext}`).catch(e => setErr(e.message))

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link to="/analyses" className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1"><ArrowLeft className="w-3 h-3" />All analyses</Link>
          <h1 className="h-title text-2xl mt-1 break-all">{a.filename}</h1>
          <div className="flex flex-wrap items-center gap-3 mt-2 text-xs text-slate-400">
            <StatusChip s={a.status} /><span>{fmtBytes(a.size_bytes)}</span><span>by {a.owner}</span><span>{fmtDate(a.created_at)}</span>
            <span className="mono" title="Evidence SHA-256">sha256 {a.sha256.slice(0, 24)}…</span>
            {a.encrypted_at_rest && <span className="chip bg-emerald-500/10 text-emerald-300"><BadgeCheck className="w-3 h-3" />encrypted at rest</span>}
          </div>
        </div>
        {a.status === 'done' && (
          <div className="flex flex-wrap gap-2">
            <button className="btn-primary" onClick={() => dl('executive', 'pdf')}><FileText className="w-4 h-4" />Executive report</button>
            <button className="btn-ghost" onClick={() => dl('technical', 'pdf')}><Download className="w-4 h-4" />Technical report</button>
            <button className="btn-ghost" onClick={() => dl('json', 'json')}><FileJson className="w-4 h-4" />JSON</button>
          </div>
        )}
      </div>

      {(a.status === 'queued' || a.status === 'running') && (
        <div className="card card-pad flex items-center gap-4">
          <Cpu className="w-6 h-6 text-cyan-300 animate-pulse" />
          <div><div className="text-white font-medium">Analysing capture…</div><div className="text-sm text-slate-400">Parsing IKE/ESP, extracting side-channel features and running AI classifiers.</div></div>
        </div>
      )}
      {a.status === 'failed' && <ErrorBox error={a.error} />}

      {r && !tun && <Section title="Result"><Empty>{r.assessment?.summary || 'No IPsec tunnels found in this capture.'}</Empty></Section>}

      {r && tun && asmt && (
        <>
          {r.tunnels.length > 1 && (
            <div className="flex flex-wrap gap-2 items-center"><span className="text-xs text-slate-400">Tunnel:</span>
              {r.tunnels.map((t, i) => <button key={t.id} onClick={() => setTi(i)} className={`chip !py-1 ${i === ti ? 'bg-cyan-500/20 text-cyan-200' : 'bg-ink-800 text-slate-300'}`}>{t.id} · {t.protocol}</button>)}
            </div>
          )}
          <div className="flex gap-1 overflow-x-auto border-b border-ink-700 scroll-thin">
            {TABS.concat(a.ground_truth ? [['truth', 'Ground Truth vs AI', CheckCircle2]] : []).map(([k, l, Icon]) => (
              <button key={k} onClick={() => setTab(k)} className={`flex items-center gap-2 whitespace-nowrap px-4 py-2.5 text-sm border-b-2 -mb-px transition ${tab === k ? 'border-cyan-400 text-cyan-200' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
                <Icon className="w-4 h-4" />{l}</button>
            ))}
          </div>
          {tab === 'overview' && <Overview r={r} tun={tun} asmt={asmt} />}
          {tab === 'ident' && <Ident tun={tun} asmt={asmt} />}
          {tab === 'ike' && <Ike tun={tun} />}
          {tab === 'sa' && <SAs tun={tun} />}
          {tab === 'traffic' && <Traffic tun={tun} asmt={asmt} r={r} />}
          {tab === 'threats' && <Threats asmt={asmt} />}
          {tab === 'compliance' && <Compliance asmt={asmt} />}
          {tab === 'truth' && <Truth gt={a.ground_truth} tun={tun} />}
          <p className="text-[11px] text-slate-500">Result SHA-256 {a.result_sha256} · model {r.model?.version} ({r.model?.status}) · processed in {r.processing_ms} ms</p>
        </>
      )}
    </div>
  )
}

function Overview({ r, tun, asmt }) {
  const radar = Object.entries(asmt.category_scores).map(([k, v]) => ({ k: k.replace(' & ', ' & ').replace('Protocol & configuration compliance', 'Compliance').replace('Key lifetime / SA management', 'Key lifetime').replace('Integrity & authentication', 'Integrity'), v }))
  const idn = tun.identification
  const top = asmt.findings.filter(f => f.severity !== 'Info').slice(0, 5)
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card card-pad flex flex-col items-center justify-center text-center">
          <Gauge score={asmt.score} grade={asmt.grade} size={220} />
          <div className="flex items-center gap-3 mt-3">
            <GradeBadge grade={asmt.grade} size="lg" />
            <div className="text-left">
              <div className="flex items-center gap-1.5 text-white font-medium"><RiskIcon level={asmt.risk_level} />{asmt.risk_level} risk</div>
              <div className="text-xs text-slate-400">Risk score <span className="mono text-slate-200">{asmt.risk_score}</span> / 100</div>
            </div>
          </div>
          <div className="w-full mt-5">
            <div className="flex justify-between text-xs text-slate-400 mb-1"><span>AI confidence (overall)</span></div>
            <ConfBar value={asmt.ai_confidence.overall} />
          </div>
        </div>
        <Section title="Security posture by category" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={radar} outerRadius="72%">
              <PolarGrid stroke="#1c2843" />
              <PolarAngleAxis dataKey="k" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} />
              <Radar dataKey="v" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.25} isAnimationActive={false} />
              <Tooltip {...tooltipStyle} />
            </RadarChart>
          </ResponsiveContainer>
        </Section>
      </div>
      <Section title="Executive summary" icon={FileText}>
        <p className="text-sm leading-relaxed text-slate-300">{r.assessment.summary}</p>
      </Section>
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">
        {['ike_version', 'ipsec_protocol', 'mode', 'encryption', 'integrity', 'key_exchange', 'pfs', 'traffic_type'].map(k => idn[k] && (
          <div key={k} className="card px-4 py-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-400">{LABELS[k]}</div>
            <div className="text-sm text-white font-medium mt-1 break-words">{show(idn[k].value)}</div>
            <ConfBar value={idn[k].confidence} className="mt-2" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section title="Top findings" icon={ShieldAlert}>
          {top.length ? <ul className="space-y-3">{top.map(f => (
            <li key={f.id} className="flex gap-3"><SevChip s={f.severity} /><div><div className="text-sm text-white">{f.title}</div><div className="text-xs text-slate-400 mt-0.5">{f.recommendation}</div></div></li>
          ))}</ul> : <Empty>No significant weaknesses identified.</Empty>}
        </Section>
        <Section title="Capture summary" icon={Eye}>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            {[['Packets', r.capture.packets.toLocaleString()], ['Duration', `${r.capture.duration_s} s`], ['Tunnels', r.tunnels.length],
              ['Data-plane packets', tun.stats.packets.toLocaleString()], ['Throughput', `${(tun.stats.throughput_bps / 1000).toFixed(1)} kbit/s`],
              ['Malformed frames', r.capture.malformed], ...Object.entries(r.protocol_breakdown).slice(0, 6)].map(([k, v]) => (
              <div key={k}><dt className="text-xs text-slate-400">{k}</dt><dd className="text-white mono">{String(v)}</dd></div>
            ))}
          </dl>
        </Section>
      </div>
    </div>
  )
}

function Ident({ tun }) {
  const idn = tun.identification
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {Object.entries(idn).map(([k, v]) => (
        <div key={k} className="card card-pad">
          <div className="flex items-start justify-between gap-3">
            <div className="text-xs uppercase tracking-wider text-slate-400">{LABELS[k] || k}</div>
            <span className={`chip ${v.method?.startsWith('AI') ? 'bg-violet-500/15 text-violet-300' : 'bg-cyan-500/10 text-cyan-300'}`}>{v.method?.startsWith('AI') ? 'AI inference' : 'Protocol field'}</span>
          </div>
          <div className="text-lg text-white font-semibold mt-2 break-words">{show(v.value)}{v.group ? <span className="text-sm text-slate-400 font-normal"> · group {v.group}</span> : null}</div>
          <ConfBar value={v.confidence} className="mt-3" />
          <div className="text-xs text-slate-400 mt-3">{v.method}</div>
          {v.evidence && <div className="text-xs text-slate-500 mt-1">{v.evidence}</div>}
          {v.distribution && Object.keys(v.distribution).length > 0 && (
            <div className="mt-3 space-y-1">{Object.entries(v.distribution).slice(0, 6).map(([c, p]) => (
              <div key={c} className="flex items-center gap-2 text-xs"><span className="w-24 truncate text-slate-300">{c}</span>
                <div className="flex-1 h-1.5 bg-ink-700 rounded-full"><div className="h-full rounded-full bg-violet-400" style={{ width: `${p * 100}%` }} /></div>
                <span className="mono w-10 text-right text-slate-400">{(p * 100).toFixed(0)}%</span></div>))}</div>
          )}
        </div>
      ))}
    </div>
  )
}

function Ike({ tun }) {
  const ike = tun.ike
  if (!ike.present) return <Section title="IKE negotiation"><Empty>No IKE negotiation captured — parameters are inferred from ESP by the AI engine.</Empty></Section>
  const n = ike.negotiated
  const maxT = Math.max(...ike.timeline.map(m => m.t), 1)
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section title="Negotiated IKE SA" icon={KeyRound}>
          <dl className="grid grid-cols-2 gap-3 text-sm">
            {[['Version / mode', `IKEv${ike.version} · ${ike.exchange_mode}`], ['Initiator', ike.initiator], ['Responder', ike.responder], ['IKE SPI (i)', ike.ike_spi_i],
              ['Encryption', `${n.encr || '–'} ${n.key_len || ''}`], ['PRF / hash', n.prf || '–'], ['Integrity', n.integ || 'AEAD'], ['DH group', `${n.dh_id} · ${n.dh}`],
              ['Authentication', show(ike.auth_method?.value)], ['IKE lifetime', ike.ike_lifetime?.value ? `${ike.ike_lifetime.value} s` : 'not on wire'],
              ['NAT-T', ike.nat_t ? 'yes (UDP 4500)' : 'no'], ['Fragmentation', ike.fragmentation ? 'supported' : '–']].map(([k, v]) => (
              <div key={k}><dt className="text-xs text-slate-400">{k}</dt><dd className="text-white mono break-all">{String(v)}</dd></div>))}
          </dl>
        </Section>
        <Section title="Offered proposals & fingerprints">
          <table className="w-full"><thead><tr>{['#', 'Encr', 'Key', 'PRF/Hash', 'Integ', 'DH'].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>{ike.offered_proposals.map((p, i) => <tr key={i}><td className="td">{i + 1}</td><td className="td mono">{p.encr}</td><td className="td mono">{p.key_len || '–'}</td><td className="td mono">{p.prf || p.hash}</td><td className="td mono">{p.integ || '–'}</td><td className="td mono">{p.dh}</td></tr>)}</tbody></table>
          <div className="mt-4 space-y-2 text-sm">
            <div><span className="text-xs text-slate-400">Vendor IDs: </span>{ike.vendor_ids.length ? ike.vendor_ids.map(v => <span key={v} className="chip bg-ink-800 text-slate-200 mr-1">{v}</span>) : '–'}</div>
            <div><span className="text-xs text-slate-400">Notifies: </span>{ike.notifies.map(v => <span key={v} className="chip bg-ink-800 text-slate-300 mr-1 mb-1">{v}</span>)}</div>
            {ike.identities.length > 0 && <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3 text-red-200 text-xs">Cleartext identities exposed: {ike.identities.map(i => `${i.type}=${i.value}`).join(', ')}</div>}
          </div>
        </Section>
      </div>
      <Section title="Exchange timeline" icon={Timer}>
        <div className="relative h-16 mb-4 rounded-lg bg-ink-950 border border-ink-700">
          {ike.timeline.map((m, i) => (
            <div key={i} title={`${m.t}s ${m.exchange} ${m.dir} ${m.length}B`} className="absolute top-2 bottom-2 w-1 rounded"
              style={{ left: `${(m.t / maxT) * 98 + 1}%`, background: PALETTE[['IKE_SA_INIT', 'IKE_AUTH', 'CREATE_CHILD_SA', 'INFORMATIONAL', 'Main Mode', 'Aggressive Mode', 'Quick Mode'].indexOf(m.exchange) % 8] || '#94a3b8' }} />
          ))}
        </div>
        <div className="overflow-x-auto max-h-96 scroll-thin -mx-5">
          <table className="w-full"><thead className="sticky top-0 bg-ink-900"><tr>{['t (s)', 'Exchange', 'Dir', 'Length', 'Encrypted', 'NAT-T', 'Payloads'].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>{ike.timeline.map((m, i) => <tr key={i}><td className="td mono">{m.t.toFixed(3)}</td><td className="td">{m.exchange}</td><td className="td mono">{m.dir}</td><td className="td mono">{m.length}</td>
              <td className="td">{m.encrypted ? <span className="chip bg-emerald-500/10 text-emerald-300">SK</span> : <span className="chip bg-amber-500/10 text-amber-300">clear</span>}</td>
              <td className="td">{m.natt ? '4500' : '500'}</td><td className="td text-xs text-slate-400">{m.payloads.join(' · ')}</td></tr>)}</tbody></table>
        </div>
      </Section>
    </div>
  )
}

function SAs({ tun }) {
  const rp = tun.replay
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card card-pad"><div className="text-xs text-slate-400 uppercase tracking-wider">Replay verdict</div>
          <div className={`text-lg font-semibold mt-1 ${rp.duplicates ? 'text-red-300' : 'text-emerald-300'}`}>{rp.verdict}</div>
          <div className="text-xs text-slate-400 mt-1">{rp.duplicates} duplicate (SPI, seq) · {rp.reordered} reordered</div></div>
        <div className="card card-pad"><div className="text-xs text-slate-400 uppercase tracking-wider">Child SA lifetime</div>
          <div className="text-lg font-semibold mt-1 text-white">{tun.identification.child_lifetime.value ? `${tun.identification.child_lifetime.value} s` : 'Not observed'}</div>
          <div className="text-xs text-slate-400 mt-1">{tun.identification.child_lifetime.evidence}</div></div>
        <div className="card card-pad"><div className="text-xs text-slate-400 uppercase tracking-wider">Security Associations</div>
          <div className="text-lg font-semibold mt-1 text-white">{tun.sas.length} SPIs</div>
          <div className="text-xs text-slate-400 mt-1">Rekeys at: {tun.ike.rekey_times?.length ? tun.ike.rekey_times.join('s, ') + 's' : '–'}</div></div>
      </div>
      <Section title="SA inventory">
        <div className="overflow-x-auto -m-5 scroll-thin">
          <table className="w-full"><thead><tr>{['SPI', 'Source → Destination', 'Packets', 'Bytes', 'Sequence', 'Duplicates', 'Reordered', 'Gaps', 'Active window'].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>{tun.sas.map(s => <tr key={s.spi + s.src} className={s.duplicates ? 'bg-red-500/5' : ''}>
              <td className="td mono text-cyan-200">{s.spi}</td><td className="td mono text-xs">{s.src} → {s.dst}</td><td className="td mono">{s.packets}</td><td className="td mono">{fmtBytes(s.bytes)}</td>
              <td className="td mono">{s.seq_first}–{s.seq_last}</td><td className={`td mono ${s.duplicates ? 'text-red-300' : ''}`}>{s.duplicates}</td><td className="td mono">{s.reordered}</td><td className="td mono">{s.gaps}</td>
              <td className="td mono text-xs">{s.first_seen}s – {s.last_seen}s</td></tr>)}</tbody></table>
        </div>
      </Section>
    </div>
  )
}

function Traffic({ tun, asmt, r }) {
  const s = tun.stats.series
  const series = s.t.map((t, i) => ({ t, up: s.up[i] * 8 / 1000, down: s.down[i] * 8 / 1000 }))
  const tp = tun.traffic.prediction
  const dist = Object.entries(tp.distribution || {}).map(([k, v]) => ({ k, v: +(v * 100).toFixed(1) }))
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Section title="Encrypted throughput (kbit/s)" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={series}>
              <defs>
                <linearGradient id="gu" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#22d3ee" stopOpacity={0.5} /><stop offset="1" stopColor="#22d3ee" stopOpacity={0} /></linearGradient>
                <linearGradient id="gd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#a78bfa" stopOpacity={0.5} /><stop offset="1" stopColor="#a78bfa" stopOpacity={0} /></linearGradient>
              </defs>
              <CartesianGrid stroke="#1c2843" vertical={false} />
              <XAxis dataKey="t" stroke="#64748b" fontSize={11} unit="s" />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip {...tooltipStyle} formatter={(v) => v.toFixed(1)} />
              <Area type="monotone" dataKey="up" name="initiator → responder" stroke="#22d3ee" fill="url(#gu)" />
              <Area type="monotone" dataKey="down" name="responder → initiator" stroke="#a78bfa" fill="url(#gd)" />
            </AreaChart>
          </ResponsiveContainer>
        </Section>
        <Section title="AI traffic classification" icon={Cpu}>
          <div className="text-3xl font-semibold text-white capitalize">{tp.label}</div>
          <ConfBar value={tp.confidence} className="mt-2" />
          <div className="mt-4 space-y-1.5">{dist.map((d, i) => (
            <div key={d.k} className="flex items-center gap-2 text-xs"><span className="w-20 capitalize text-slate-300">{d.k}</span>
              <div className="flex-1 h-2 bg-ink-700 rounded-full"><div className="h-full rounded-full" style={{ width: `${d.v}%`, background: PALETTE[i % 8] }} /></div>
              <span className="mono w-12 text-right text-slate-400">{d.v}%</span></div>))}</div>
        </Section>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section title="Packet size distribution">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={tun.stats.size_histogram}><CartesianGrid stroke="#1c2843" vertical={false} />
              <XAxis dataKey="bin" stroke="#64748b" fontSize={10} /><YAxis stroke="#64748b" fontSize={11} />
              <Tooltip {...tooltipStyle} cursor={{ fill: '#131d33' }} /><Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} /></BarChart>
          </ResponsiveContainer>
        </Section>
        <Section title="Per-window inference timeline (30 s)">
          <div className="space-y-1.5 max-h-56 overflow-y-auto scroll-thin">{tun.traffic.timeline.map((w, i) => (
            <div key={i} className="flex items-center gap-3 text-xs"><span className="mono text-slate-400 w-24">{w.t0}–{w.t1}s</span>
              <span className="capitalize w-20 text-white">{w.label}</span><ConfBar value={w.confidence} className="flex-1" /></div>))}
            {!tun.traffic.timeline.length && <Empty>Not enough packets for windowed inference.</Empty>}</div>
        </Section>
      </div>
      <Section title="Metadata exposure analysis" icon={Eye}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">{asmt.metadata_exposure.map(e => (
          <div key={e.id} className="rounded-lg border border-ink-700 bg-ink-950/50 p-4">
            <div className="flex items-center justify-between gap-2"><div className="text-sm text-white font-medium">{e.title}</div><SevChip s={e.level} /></div>
            <div className="text-xs text-slate-300 mt-2">{e.detail}</div>
            <div className="text-xs text-slate-500 mt-2">Mitigation: {e.mitigation}</div>
          </div>))}</div>
        {Object.keys(r.capture.cleartext).length > 0 && <div className="text-xs text-slate-400 mt-4">Cleartext traffic in capture: {Object.entries(r.capture.cleartext).map(([k, v]) => `${k} (${v})`).join(', ')}</div>}
      </Section>
    </div>
  )
}

function Threats({ asmt }) {
  const [open, setOpen] = useState(null)
  const sev = Object.fromEntries(asmt.findings.map(f => [f.id, f.severity]))
  const heat = ['#052e1a', '#1a2e05', '#3b2f06', '#43200a', '#4c0d0d']
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <Section title="Threat matrix — likelihood × impact" className="xl:col-span-3">
          <div className="flex gap-3">
            <div className="flex flex-col justify-between text-[10px] text-slate-400 py-1"><span>Impact ↑</span></div>
            <div className="flex-1">
              <div className="grid grid-cols-5 gap-1.5">
                {[4, 3, 2, 1, 0].map(imp => [0, 1, 2, 3, 4].map(lik => {
                  const ids = asmt.threat_matrix.grid[imp][lik]
                  return (
                    <div key={`${imp}-${lik}`} className="aspect-[4/3] rounded-md p-1.5 flex flex-wrap content-start gap-1 border border-ink-700/40" style={{ background: heat[Math.min(4, Math.floor((imp + lik) / 2))] }}>
                      {ids.map(id => <span key={id} className="chip !px-1.5 !text-[10px] bg-ink-950/70" style={{ color: SEV[sev[id]]?.dot }}>{id}</span>)}
                    </div>)
                }))}
              </div>
              <div className="grid grid-cols-5 text-center text-[10px] text-slate-400 mt-1">{[1, 2, 3, 4, 5].map(i => <span key={i}>{i}</span>)}</div>
              <div className="text-center text-[10px] text-slate-400">Likelihood →</div>
            </div>
          </div>
        </Section>
        <Section title="STRIDE mapping" className="xl:col-span-2">
          {Object.keys(asmt.threat_matrix.stride).length ? <ul className="space-y-3">{Object.entries(asmt.threat_matrix.stride).map(([k, ids]) => (
            <li key={k}><div className="text-sm text-white">{k}</div><div className="flex flex-wrap gap-1 mt-1">{ids.map(i => <span key={i} className="chip bg-ink-800 text-slate-300">{i}</span>)}</div></li>))}</ul> : <Empty>No threats mapped.</Empty>}
          <div className="grid grid-cols-5 gap-2 mt-6 text-center">{Object.entries(asmt.severity_counts).map(([k, v]) => (
            <div key={k} className="rounded-lg bg-ink-950 border border-ink-700 py-2"><div className="text-lg font-semibold" style={{ color: SEV[k].dot }}>{v}</div><div className="text-[10px] text-slate-400">{k}</div></div>))}</div>
        </Section>
      </div>
      <Section title={`Findings (${asmt.findings.length})`}>
        <ul className="divide-y divide-ink-800 -my-2">{asmt.findings.map(f => (
          <li key={f.id} className="py-3">
            <button className="w-full flex items-center gap-3 text-left" onClick={() => setOpen(open === f.id ? null : f.id)} aria-expanded={open === f.id}>
              <SevChip s={f.severity} /><span className="mono text-xs text-slate-400 w-16">{f.id}</span>
              <span className="text-sm text-white flex-1">{f.title}</span><span className="text-xs text-slate-500 hidden md:block">{f.category}</span>
              <ChevronDown className={`w-4 h-4 text-slate-400 transition ${open === f.id ? 'rotate-180' : ''}`} />
            </button>
            {open === f.id && (
              <div className="mt-3 ml-2 md:ml-24 grid md:grid-cols-2 gap-4 text-xs">
                <div><div className="label">Evidence</div><div className="text-slate-300">{f.evidence}</div></div>
                <div><div className="label">Recommendation</div><div className="text-slate-300">{f.recommendation}</div></div>
                <div className="text-slate-400">Likelihood {f.likelihood}/5 · Impact {f.impact}/5 · STRIDE {f.stride || '–'}</div>
                <div className="text-slate-400">ATT&CK {f.mitre_attack || '–'} · Ref {f.references || '–'}</div>
              </div>)}
          </li>))}</ul>
      </Section>
    </div>
  )
}

function Compliance({ asmt }) {
  const groups = {}
  asmt.compliance.forEach(c => { (groups[c.framework] ||= []).push(c) })
  const icon = (s) => s === 'pass' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : s === 'fail' ? <XCircle className="w-4 h-4 text-red-400" /> : <CircleHelp className="w-4 h-4 text-slate-500" />
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">{Object.entries(groups).map(([fw, items]) => {
      const p = items.filter(i => i.status === 'pass').length
      return (
        <Section key={fw} title={fw} right={<span className="mono text-xs text-slate-400">{p}/{items.length} pass</span>}>
          <ul className="space-y-2.5">{items.map(c => (
            <li key={c.control} className="flex items-start gap-3">{icon(c.status)}<div className="flex-1"><div className="text-sm text-white">{c.control}</div><div className="text-xs text-slate-400 mono">{c.observed}</div></div></li>))}</ul>
        </Section>)
    })}</div>
  )
}

function Truth({ gt, tun }) {
  const idn = tun.identification
  const enc = idn.encryption?.value || ''
  const pfsV = idn.pfs?.value
  const rows = [
    ['IKE version', `IKEv${gt.ike_version}`, idn.ike_version?.value],
    ['Exchange mode', gt.ike_version === 1 ? `${gt.ikev1_mode === 'aggressive' ? 'Aggressive' : 'Main'} Mode` : 'IKEv2', idn.exchange_mode?.value],
    ['Protocol', gt.protocol, idn.ipsec_protocol?.value],
    ['Mode', gt.mode, idn.mode?.value],
    ['ESP encryption', gt.esp_encr + (gt.esp_key_bits ? `-${gt.esp_key_bits}` : ''), enc],
    ['ESP integrity', gt.esp_integ, idn.integrity?.value],
    ['DH group', String(gt.dh_group), String(idn.key_exchange?.group ?? '')],
    ['PFS', String(gt.pfs), String(pfsV)],
    ['IP version', `IPv${gt.ip_version}`, idn.ip_version?.value],
    ['NAT-T', String(gt.nat_t), String(idn.nat_traversal?.value)],
    ['Traffic', gt.traffic, idn.traffic_type?.value],
    ['Replay injected', `${gt.replayed_packets} pkts`, `${tun.replay.duplicates} detected`],
    ['Child lifetime', `${gt.child_lifetime}s (${gt.rekeys} rekeys)`, idn.child_lifetime?.value ? `${idn.child_lifetime.value}s` : 'not observed'],
  ]
  const match = (a, b, k) => {
    if (b == null) return null
    const A = String(a).toLowerCase(), B = String(b).toLowerCase()
    if (k === 'ESP integrity') return (A.includes('none') && B.includes('aead')) || (A.includes('sha2-256') && B.includes('256')) || (A.includes('512') && B.includes('512')) || ((A.includes('sha1') || A.includes('md5')) && B.includes('96'))
    if (k === 'ESP encryption') return B.startsWith(A.split('-').slice(0, 2).join('-').toLowerCase()) || (A.startsWith('none') && B.startsWith('none')) || (A.startsWith('3des') && B.startsWith('3des'))
    if (k === 'PFS' && B === 'null') return null
    if (k === 'Child lifetime' || k === 'Replay injected') return null
    return A === B || B.includes(A) || A.includes(B)
  }
  return (
    <Section title="Testbed ground truth vs. analyzer output" icon={CheckCircle2}>
      <table className="w-full"><thead><tr><th className="th">Attribute</th><th className="th">Configured (truth)</th><th className="th">Identified</th><th className="th">Match</th></tr></thead>
        <tbody>{rows.map(([k, a, b]) => { const m = match(a, b, k); return (
          <tr key={k}><td className="td text-slate-300">{k}</td><td className="td mono">{a}</td><td className="td mono">{show(b)}</td>
            <td className="td">{m === null ? <span className="text-slate-500 text-xs">n/a</span> : m ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}</td></tr>) })}</tbody></table>
      <p className="text-xs text-slate-500 mt-3">Preset: {gt.name} · {gt.total_packets} packets · {gt.esp_packets} data-plane packets. AES key length is not observable from ciphertext; it is inferred from the IKE SA proposal.</p>
    </Section>
  )
}
