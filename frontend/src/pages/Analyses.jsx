import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { FileUp, Lock, Trash2, UploadCloud } from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../App'
import { Empty, ErrorBox, GradeBadge, Section, StatusChip, fmtBytes, fmtDate, pct } from '../components/ui'

export default function Analyses() {
  const { user } = useAuth()
  const [rows, setRows] = useState([])
  const [err, setErr] = useState(null)
  const [busy, setBusy] = useState(false)
  const [drag, setDrag] = useState(false)
  const input = useRef()
  const nav = useNavigate()
  const canWrite = user.role !== 'viewer'

  const load = useCallback(() => api.analyses().then(setRows).catch(e => setErr(e.message)), [])
  useEffect(() => { load(); const t = setInterval(load, 3000); return () => clearInterval(t) }, [load])

  const upload = async (file) => {
    if (!file) return
    if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) { setErr('Only .pcap / .pcapng captures are accepted'); return }
    setBusy(true); setErr(null)
    try { const a = await api.upload(file); nav(`/analyses/${a.id}`) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  const del = async (id) => {
    if (!confirm('Delete this analysis and securely erase its evidence?')) return
    try { await api.deleteAnalysis(id); load() } catch (e) { setErr(e.message) }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="h-title text-2xl">Analyze Captures</h1>
        <p className="muted text-sm mt-1">Upload Wireshark / tcpdump captures (pcap, pcapng). Evidence is hashed (SHA-256) and encrypted at rest with AES-256-GCM.</p>
      </div>
      <ErrorBox error={err} />
      {canWrite && (
        <div onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
          onDrop={e => { e.preventDefault(); setDrag(false); upload(e.dataTransfer.files[0]) }}
          onClick={() => input.current?.click()} role="button" tabIndex={0}
          onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
          className={`card cursor-pointer border-dashed border-2 px-6 py-12 text-center transition ${drag ? 'border-cyan-400 bg-cyan-500/5' : 'border-ink-600 hover:border-ink-600/100 hover:bg-ink-850'}`}>
          <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={e => upload(e.target.files[0])} />
          <div className="mx-auto w-14 h-14 rounded-xl bg-cyan-500/10 ring-1 ring-cyan-400/30 flex items-center justify-center">
            {busy ? <FileUp className="w-7 h-7 text-cyan-300 animate-bounce" /> : <UploadCloud className="w-7 h-7 text-cyan-300" />}
          </div>
          <div className="mt-4 text-white font-medium">{busy ? 'Uploading & encrypting evidence…' : 'Drop a capture here or click to browse'}</div>
          <div className="text-xs text-slate-400 mt-1 flex items-center justify-center gap-1.5"><Lock className="w-3 h-3" />IKE, ESP, AH, NAT-T · IPv4/IPv6 · up to 200 MB</div>
        </div>
      )}
      <Section title={`Analyses (${rows.length})`}>
        {rows.length ? (
          <div className="overflow-x-auto -m-5 scroll-thin">
            <table className="w-full">
              <thead><tr>{['Capture', 'Source', 'Status', 'Score', 'Risk', 'Protocol', 'Encryption', 'Traffic', 'AI conf.', 'Size', 'Owner', 'Created', ''].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>{rows.map(a => (
                <tr key={a.id} className="hover:bg-ink-800/50">
                  <td className="td max-w-[260px]"><Link to={`/analyses/${a.id}`} className="text-cyan-200 hover:underline break-all">{a.filename}</Link>
                    <div className="mono text-slate-500 truncate" title={a.sha256}>{a.sha256.slice(0, 16)}…</div></td>
                  <td className="td"><span className={`chip ${a.source === 'testbed' ? 'bg-violet-500/15 text-violet-300' : 'bg-slate-500/15 text-slate-300'}`}>{a.source}</span></td>
                  <td className="td"><StatusChip s={a.status} />{a.error && <div className="text-xs text-red-300 mt-1 max-w-[200px]">{a.error}</div>}</td>
                  <td className="td"><div className="flex items-center gap-2"><GradeBadge grade={a.grade} size="sm" /><span className="mono">{a.score ?? '–'}</span></div></td>
                  <td className="td">{a.risk_level || '–'}</td>
                  <td className="td text-xs">{a.ike_version} {a.protocol} {a.mode}</td>
                  <td className="td mono">{a.encryption || '–'}</td>
                  <td className="td">{a.traffic || '–'}</td>
                  <td className="td mono">{pct(a.ai_confidence)}</td>
                  <td className="td text-xs text-slate-400">{fmtBytes(a.size_bytes)}</td>
                  <td className="td text-xs">{a.owner}</td>
                  <td className="td text-xs text-slate-400 whitespace-nowrap">{fmtDate(a.created_at)}</td>
                  <td className="td">{canWrite && (user.role === 'admin' || a.owner === user.username) &&
                    <button onClick={() => del(a.id)} className="p-1.5 rounded hover:bg-red-500/10 text-slate-400 hover:text-red-300" aria-label="Delete"><Trash2 className="w-4 h-4" /></button>}</td>
                </tr>))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No analyses yet.</Empty>}
      </Section>
    </div>
  )
}
