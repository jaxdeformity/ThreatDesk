import { useEffect, useMemo, useRef, useState } from 'react'
import { ContextStrip } from '@/kit/ContextStrip'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import {
  Search, Link as LinkIcon, FileText, Upload, AlertCircle,
  Play, Trash2, Copy, CheckCircle2, ExternalLink, Globe, Binary,
  Loader2, ArrowRight, Radar, ChevronUp, ChevronDown, Pencil, ListChecks,
} from 'lucide-react'
import { api, type TriageSummary, type TriageDetail, type TriageResult } from '@/api/client'
import { useTriageStream } from '@/hooks/useTriageStream'
import { ThreatFeedRail } from './ThreatFeedRail'
import { cn } from '@/lib/cn'
import { formatDistanceToNowStrict, parseISO } from 'date-fns'

type InputMode = 'url' | 'threat_name' | 'text' | 'file'

interface TriagePrefill {
  mode: InputMode
  value: string       // URL or threat name
  question?: string
  customName?: string // seeds the triage's display name (e.g. RSS article headline)
}

/**
 * Pick the best user-facing label for a triage. Priority:
 *   1. responder-set custom_name
 *   2. agent-produced headline from result.json
 *   3. raw input_ref (URL / threat name)
 *   4. the responder's question
 *   5. fallback
 * Used everywhere a triage is displayed in a list / header.
 */
function triageLabel(t: {
  custom_name?: string | null
  headline?: string | null
  input_ref?: string | null
  question?: string | null
}): string {
  return (
    (t.custom_name && t.custom_name.trim()) ||
    (t.headline && t.headline.trim()) ||
    (t.input_ref && t.input_ref.trim()) ||
    (t.question && t.question.trim()) ||
    '(untitled)'
  )
}

/**
 * Standalone Triage workbench.
 *
 * The responder lands here with a question: "what's this suspicious
 * file?", "is CVE-2026-xxxxx real?", "tell me about OtterCookie".
 * They paste/upload/name it, pick their SIEM, and hit Run. The
 * threat-triage agent produces a markdown report + structured result;
 * the UI renders it with copy-ready hunt queries, detection rules, and
 * a one-click MISP export of the triage's indicators.
 */
// Defensive render for chip-style fields that the LLM occasionally returns
// as an object instead of a string (e.g. {name, attribution_confidence,
// tracked_alias, motivation}). Prefer .name, fall back to a stable string.
function flattenChip(v: unknown): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    if (typeof o.name === 'string') return o.name
    if (typeof o.label === 'string') return o.label
    try { return JSON.stringify(v) } catch { return String(v) }
  }
  return String(v)
}

export function TriageView() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [composerOpen, setComposerOpen] = useState(true)
  const [prefill, setPrefill] = useState<TriagePrefill | null>(null)
  const [historyOpen, setHistoryOpen] = useState(true)

  const triagesQ = useQuery({
    queryKey: ['triages'],
    queryFn: async () => (await api.listTriages()).triages,
    refetchInterval: 5_000,
  })

  const triages = triagesQ.data || []

  // Auto-select the newest triage on first load ONLY. Once the user
  // has interacted (opened the composer, deleted a triage, etc.) we
  // stop clobbering their intent, otherwise clicking "New triage"
  // would just snap back to the newest existing triage as soon as the
  // query resolved.
  const autoSelectDone = useRef(false)
  useEffect(() => {
    if (autoSelectDone.current) return
    if (triagesQ.isLoading) return
    autoSelectDone.current = true
    if (triages.length > 0) {
      setSelectedId(triages[0].triage_id)
      setComposerOpen(false)
    }
  }, [triagesQ.isLoading, triages])

  function openComposerWith(p: TriagePrefill) {
    setPrefill(p)
    setSelectedId(null)
    setComposerOpen(true)
  }

  // /triage?threat=CVE-2024-3400 (from the Vulnerabilities tab) opens the
  // composer pre-filled; the analyst still presses Run.
  const [params, setParams] = useSearchParams()
  useEffect(() => {
    const t = params.get('threat')
    if (!t) return
    // The deep link is an explicit intent: stop the first-load auto-select
    // from swapping the composer for the newest old triage when the list
    // resolves after mount.
    autoSelectDone.current = true
    openComposerWith({ mode: 'threat_name', value: t.slice(0, 200) })
    params.delete('threat')
    setParams(params, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="h-full flex flex-col">
      <ContextStrip
        title="TRIAGE"
        actions={[
          { label: historyOpen ? 'Hide history' : 'History', onClick: () => setHistoryOpen(v => !v) },
          { label: 'New triage', onClick: () => { setComposerOpen(true); setSelectedId(null); setPrefill(null) } },
        ]}
      />

      <div className="flex-1 flex overflow-hidden min-h-0">
        {/* History rail (left) — collapsible. */}
        {historyOpen && (
          <aside className="w-[260px] flex-shrink-0 border-r border-border bg-surface overflow-y-auto">
            <TriageHistory
              triages={triages}
              selectedId={selectedId}
              loading={triagesQ.isLoading}
              onSelect={(id) => { setSelectedId(id); setComposerOpen(false) }}
            />
          </aside>
        )}

        {/* Main pane */}
        <main className="flex-1 overflow-hidden min-w-0 flex flex-col">
          {composerOpen || !selectedId ? (
            <TriageComposer
              prefill={prefill}
              onConsumePrefill={() => setPrefill(null)}
              onCreated={(id) => {
                setSelectedId(id)
                setComposerOpen(false)
              }}
            />
          ) : (
            <TriageRun
              key={selectedId}
              triageId={selectedId}
              onDeleted={() => {
                setSelectedId(null)
                setComposerOpen(true)
              }}
            />
          )}
        </main>

        {/* Threat feed rail (right) */}
        <aside className="w-[320px] flex-shrink-0 border-l border-border overflow-hidden">
          <ThreatFeedRail
            onTriageUrl={(url, headline) => openComposerWith({
              mode: 'url',
              value: url,
              question: headline ? `Tell me about this: ${headline}` : '',
              // Seed the triage's display name with the article
              // headline so the sidebar shows "Malware X campaign…"
              // instead of a long URL.
              customName: headline || undefined,
            })}
            onTriageThreatName={(name) => openComposerWith({
              mode: 'threat_name',
              value: name,
              customName: name,
            })}
          />
        </aside>
      </div>
    </div>
  )
}

// ── History rail ──────────────────────────────────────────────────────

function TriageHistory({
  triages, selectedId, loading, onSelect,
}: {
  triages: TriageSummary[]
  selectedId: string | null
  loading: boolean
  onSelect: (id: string) => void
}) {
  const [filter, setFilter] = useState('')
  const filtered = useMemo(() => {
    if (!filter) return triages
    const q = filter.toLowerCase()
    return triages.filter(t =>
      (t.headline || '').toLowerCase().includes(q) ||
      (t.input_ref || '').toLowerCase().includes(q) ||
      (t.question || '').toLowerCase().includes(q) ||
      (t.triage_id || '').toLowerCase().includes(q),
    )
  }, [filter, triages])

  return (
    <>
      <div className="sticky top-0 bg-surface border-b border-border px-3 py-2 z-10">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-faint pointer-events-none" />
          <input
            className="input pl-7 !py-1 !text-xs"
            placeholder="Filter triages…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />
        </div>
      </div>

      {loading ? (
        <div className="p-4 text-xs text-ink-faint">loading…</div>
      ) : filtered.length === 0 ? (
        <div className="p-6 text-center text-xs text-ink-faint">
          No triages yet. Start one on the right.
        </div>
      ) : (
        <ul className="py-1">
          {filtered.map(t => (
            <TriageHistoryRow
              key={t.triage_id}
              triage={t}
              selected={selectedId === t.triage_id}
              onSelect={() => onSelect(t.triage_id)}
            />
          ))}
        </ul>
      )}
    </>
  )
}

/** One row in the history rail. Owns its own rename state so the
 * whole list doesn't re-render when a single row enters edit mode. */
function TriageHistoryRow({
  triage, selected, onSelect,
}: {
  triage: TriageSummary
  selected: boolean
  onSelect: () => void
}) {
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(triage.custom_name || triageLabel(triage))
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (editing) {
      inputRef.current?.focus()
      inputRef.current?.select()
    }
  }, [editing])

  const rename = useMutation({
    mutationFn: (name: string | null) => api.renameTriage(triage.triage_id, name),
    onSuccess: () => {
      setEditing(false)
      qc.invalidateQueries({ queryKey: ['triages'] })
      qc.invalidateQueries({ queryKey: ['triage', triage.triage_id] })
    },
  })

  function commit() {
    const next = draft.trim()
    const current = (triage.custom_name || '').trim()
    if (next === current) { setEditing(false); return }
    rename.mutate(next || null)
  }

  return (
    <li>
      <div
        className={cn(
          'group relative w-full px-3 py-2 border-b border-border hover:bg-surface2 transition-colors',
          selected && 'bg-surface2 border-l-2 border-l-accent',
        )}
      >
        {editing ? (
          <div className="flex items-center gap-2">
            <InputTypeIcon type={triage.input_type} />
            <input
              ref={inputRef}
              value={draft}
              onChange={e => setDraft(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') { e.preventDefault(); commit() }
                else if (e.key === 'Escape') { e.preventDefault(); setDraft(triage.custom_name || triageLabel(triage)); setEditing(false) }
              }}
              onBlur={commit}
              className="input !py-0.5 !text-sm flex-1"
              placeholder="name this triage…"
              disabled={rename.isPending}
            />
          </div>
        ) : (
          <button
            className="w-full text-left"
            onClick={onSelect}
          >
            <div className="flex items-center gap-2">
              <InputTypeIcon type={triage.input_type} />
              <span className="text-sm text-ink truncate flex-1 min-w-0 leading-snug" title={triageLabel(triage)}>
                {triageLabel(triage)}
              </span>
              <StatusDot status={triage.status} />
            </div>
            <div className="mt-1 flex items-center gap-2 text-2xs text-ink-faint">
              {typeof triage.prioritization_score === 'number' && (
                <span className={cn('tnum font-semibold', severityToColor(triage.severity))}>
                  {triage.prioritization_score}
                </span>
              )}
              {triage.severity && <span>{triage.severity}</span>}
              {triage.created_at && (
                <span className="ml-auto">
                  {formatDistanceToNowStrict(parseISO(triage.created_at), { addSuffix: true })}
                </span>
              )}
            </div>
          </button>
        )}

        {!editing && (
          <button
            onClick={(e) => {
              e.stopPropagation()
              setDraft(triage.custom_name || triageLabel(triage))
              setEditing(true)
            }}
            className="absolute top-2 right-2 p-1 rounded text-ink-faint hover:text-ink hover:bg-surface3 opacity-0 group-hover:opacity-100 transition"
            title="Rename"
          >
            <Pencil className="w-3 h-3" />
          </button>
        )}
      </div>
    </li>
  )
}

function InputTypeIcon({ type }: { type?: string }) {
  const cls = 'w-3 h-3 text-ink-faint flex-shrink-0'
  if (type === 'url') return <LinkIcon className={cls} />
  if (type === 'file') return <Binary className={cls} />
  if (type === 'threat_name') return <Globe className={cls} />
  return <FileText className={cls} />
}

function StatusDot({ status }: { status?: string }) {
  const cls = 'w-1.5 h-1.5 rounded-full flex-shrink-0'
  if (status === 'running') return <span className={cn(cls, 'bg-info animate-pulse')} title="running" />
  if (status === 'done') return <span className={cn(cls, 'bg-success')} title="done" />
  if (status === 'error') return <span className={cn(cls, 'bg-danger')} title="error" />
  return <span className={cn(cls, 'bg-ink-faint/40')} title={status || 'pending'} />
}

function severityToColor(severity: string | null | undefined): string {
  switch (severity) {
    case 'critical': return 'text-danger'
    case 'high': return 'text-danger'
    case 'medium': return 'text-warning'
    case 'low': return 'text-info'
    default: return 'text-ink-dim'
  }
}

// ── Composer ──────────────────────────────────────────────────────────

type Siem = 'splunk' | 'xsiam' | 'elastic' | 'sentinel' | 'chronicle' | 'kql' | 'generic'

function TriageComposer({
  onCreated, prefill, onConsumePrefill,
}: {
  onCreated: (id: string) => void
  prefill?: TriagePrefill | null
  onConsumePrefill?: () => void
}) {
  const [mode, setMode] = useState<InputMode>('threat_name')
  const [urlInput, setUrlInput] = useState('')
  const [threatName, setThreatName] = useState('')
  const [pastedText, setPastedText] = useState('')
  const [files, setFiles] = useState<File[]>([])
  const [question, setQuestion] = useState('')
  const [customName, setCustomName] = useState('')
  const [siem, setSiem] = useState<Siem>('splunk')
  const [useEnv, setUseEnv] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  // Consume prefill exactly once when it arrives (e.g. user clicked
  // "triage" on a feed item). The feed passes the article headline as
  // customName so the triage doesn't land in history with a raw URL
  // as its label.
  useEffect(() => {
    if (!prefill) return
    setMode(prefill.mode)
    if (prefill.mode === 'url') setUrlInput(prefill.value)
    else if (prefill.mode === 'threat_name') setThreatName(prefill.value)
    else if (prefill.mode === 'text') setPastedText(prefill.value)
    if (prefill.question) setQuestion(prefill.question)
    if (prefill.customName) setCustomName(prefill.customName)
    onConsumePrefill?.()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.mode, prefill?.value])

  const canSubmit = useMemo(() => {
    if (submitting) return false
    if (mode === 'url') return urlInput.trim().length > 0
    if (mode === 'threat_name') return threatName.trim().length > 0
    if (mode === 'text') return pastedText.trim().length > 0
    if (mode === 'file') return files.length > 0
    return false
  }, [mode, urlInput, threatName, pastedText, files, submitting])

  async function submit() {
    if (!canSubmit) return
    setSubmitting(true); setError(null)
    try {
      const fd = new FormData()
      fd.append('input_type', mode)
      if (mode === 'url') fd.append('input_ref', urlInput.trim())
      if (mode === 'threat_name') fd.append('input_ref', threatName.trim())
      if (mode === 'text') fd.append('input_text', pastedText)
      if (mode === 'file') files.forEach(f => fd.append('files', f))
      fd.append('question', question.trim())
      fd.append('siem_preference', siem)
      fd.append('use_environment', useEnv ? 'true' : 'false')
      if (customName.trim()) fd.append('custom_name', customName.trim())

      const res = await api.createTriage(fd)
      qc.invalidateQueries({ queryKey: ['triages'] })
      onCreated(res.triage_id)
    } catch (e) {
      setError(String((e as Error).message || e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-ink mb-1">What are we looking at?</h2>
          <p className="text-sm text-ink-dim">
            Pick the shape of your input. The threat-triage agent will research it and produce an analysis with hunt queries and detection logic.
          </p>
        </div>

        <ModeTabs mode={mode} onChange={setMode} />

        <div className="card p-4 space-y-4">
          {mode === 'url' && (
            <div>
              <label className="label">URL</label>
              <input
                className="input"
                placeholder="https://www.bleepingcomputer.com/… or a vendor advisory / CISA alert"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                autoFocus
              />
              <p className="text-2xs text-ink-faint mt-1">
                The agent will WebFetch this URL and analyze the content.
              </p>
            </div>
          )}

          {mode === 'threat_name' && (
            <div>
              <label className="label">Threat name or CVE</label>
              <input
                className="input"
                placeholder='e.g. "OtterCookie", "Lockbit 3.0", "CVE-2026-12345"'
                value={threatName}
                onChange={e => setThreatName(e.target.value)}
                autoFocus
              />
              <p className="text-2xs text-ink-faint mt-1">
                The agent will search the web (preferring primary sources) and triangulate.
              </p>
            </div>
          )}

          {mode === 'text' && (
            <div>
              <label className="label">Paste content</label>
              <textarea
                className="textarea min-h-[180px]"
                placeholder="Paste an email header, a log excerpt, analyst notes, IOC list, whatever you want analyzed."
                value={pastedText}
                onChange={e => setPastedText(e.target.value)}
                autoFocus
              />
            </div>
          )}

          {mode === 'file' && (
            <FileDrop files={files} onChange={setFiles} />
          )}

          {/* Question */}
          <div>
            <label className="label">Display name (optional)</label>
            <input
              className="input"
              placeholder="e.g. 'OtterCookie', shown in history instead of raw URL"
              value={customName}
              onChange={e => setCustomName(e.target.value)}
            />
          </div>

          <div>
            <label className="label">Question (optional)</label>
            <input
              className="input"
              placeholder='e.g. "Is this malicious?", "What is this?", "What detections should I build?"'
              value={question}
              onChange={e => setQuestion(e.target.value)}
            />
          </div>

          {/* SIEM + environment */}
          <div className="flex flex-wrap items-end gap-4">
            <div className="min-w-[180px]">
              <label className="label">Hunt queries for…</label>
              <select
                className="input !py-1.5"
                value={siem}
                onChange={e => setSiem(e.target.value as Siem)}
              >
                <option value="splunk">Splunk (SPL)</option>
                <option value="xsiam">Cortex XSIAM (XQL)</option>
                <option value="elastic">Elastic (KQL/ES|QL)</option>
                <option value="sentinel">Azure Sentinel (KQL)</option>
                <option value="chronicle">Google Chronicle (YARA-L / UDM)</option>
                <option value="kql">Generic Kusto</option>
                <option value="generic">Generic pseudo-query</option>
              </select>
            </div>

            <label className="flex items-center gap-2 text-sm text-ink cursor-pointer select-none pb-2">
              <input
                type="checkbox"
                className="accent-accent"
                checked={useEnv}
                onChange={e => setUseEnv(e.target.checked)}
              />
              <span>Cross-reference with our environment <span className="text-xs text-ink-dim">(org profile + tech inventory, Settings)</span></span>
            </label>
          </div>

          {error && (
            <div className="chip chip-danger !text-xs flex items-start gap-2 max-w-full">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span className="break-words">{error}</span>
            </div>
          )}

          <div className="flex items-center justify-end gap-2">
            <button
              className="btn btn-primary"
              disabled={!canSubmit}
              onClick={submit}
            >
              {submitting ? (
                <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Submitting…</>
              ) : (
                <><Play className="w-3.5 h-3.5" /> Run triage</>
              )}
            </button>
          </div>
        </div>

        <div className="text-xs text-ink-faint space-y-2">
          <p>The agent writes a markdown report and a structured JSON result. Both live under <code className="font-mono text-ink-dim">triages/&lt;id&gt;/</code> on disk.</p>
          <p>Output is a self-contained analysis. IOCs, CVE/EPSS/KEV context, ATT&amp;CK mapping, SIEM-specific hunt queries, detection rules (Sigma/vendor-native), and ranked recommended actions.</p>
        </div>
      </div>
    </div>
  )
}

function ModeTabs({ mode, onChange }: { mode: InputMode; onChange: (m: InputMode) => void }) {
  const tabs: Array<{ key: InputMode; label: string; icon: React.ReactNode; hint: string }> = [
    { key: 'threat_name', label: 'Threat name', icon: <Globe className="w-3.5 h-3.5" />, hint: 'Malware family, actor group, CVE ID' },
    { key: 'url', label: 'URL', icon: <LinkIcon className="w-3.5 h-3.5" />, hint: 'Blog post, advisory, CISA alert' },
    { key: 'text', label: 'Paste', icon: <FileText className="w-3.5 h-3.5" />, hint: 'Logs, headers, IOCs, notes' },
    { key: 'file', label: 'File', icon: <Binary className="w-3.5 h-3.5" />, hint: 'Unknown binary, document, script' },
  ]
  return (
    <div className="grid grid-cols-4 gap-2">
      {tabs.map(t => (
        <button
          key={t.key}
          onClick={() => onChange(t.key)}
          className={cn(
            'p-3 rounded border text-left transition-colors',
            mode === t.key
              ? 'border-accent bg-accent/10 text-ink'
              : 'border-border bg-surface hover:bg-surface2 text-ink-dim',
          )}
        >
          <div className="flex items-center gap-2 mb-1">
            {t.icon}
            <span className="text-xs font-medium">{t.label}</span>
          </div>
          <div className="text-2xs text-ink-faint">{t.hint}</div>
        </button>
      ))}
    </div>
  )
}

function FileDrop({ files, onChange }: { files: File[]; onChange: (fs: File[]) => void }) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  return (
    <div>
      <label className="label">Files</label>
      <div
        className={cn(
          'border-2 border-dashed rounded p-6 text-center cursor-pointer transition-colors',
          dragging ? 'border-accent bg-accent/5' : 'border-border hover:border-border-strong',
        )}
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => {
          e.preventDefault(); setDragging(false)
          const dropped = Array.from(e.dataTransfer.files || [])
          if (dropped.length) onChange([...files, ...dropped])
        }}
      >
        <Upload className="w-5 h-5 text-ink-faint mx-auto mb-2" />
        <div className="text-sm text-ink">Drop file(s) or click to browse</div>
        <div className="text-2xs text-ink-faint mt-1">Any file. The agent will hash, identify, and analyze.</div>
      </div>
      <input
        ref={inputRef}
        type="file"
        multiple
        className="hidden"
        onChange={e => {
          const picked = Array.from(e.target.files || [])
          if (picked.length) onChange([...files, ...picked])
        }}
      />
      {files.length > 0 && (
        <ul className="mt-2 space-y-1">
          {files.map((f, i) => (
            <li key={i} className="flex items-center gap-2 text-xs text-ink-dim">
              <Binary className="w-3 h-3" />
              <span className="font-mono truncate flex-1">{f.name}</span>
              <span className="text-2xs text-ink-faint">{(f.size / 1024).toFixed(1)} KB</span>
              <button
                className="btn btn-ghost btn-xs"
                onClick={() => onChange(files.filter((_, j) => j !== i))}
              >remove</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// ── Run view ──────────────────────────────────────────────────────────

function TriageRun({ triageId, onDeleted }: { triageId: string; onDeleted: () => void }) {
  const stream = useTriageStream(triageId)
  const qc = useQueryClient()

  // Also fetch the triage once on mount as a fallback for cases where
  // SSE misses the initial snapshot (e.g. the agent finished before we
  // connected).
  const detailQ = useQuery({
    queryKey: ['triage', triageId],
    queryFn: () => api.getTriage(triageId),
    refetchInterval: stream.status === 'running' ? 5_000 : false,
  })

  const detail: TriageDetail | null = useMemo(() => {
    const live: TriageDetail | null = detailQ.data ?? null
    if (!live) return null
    // Prefer streamed updates where available.
    return {
      ...live,
      status: { ...live.status, status: (stream.status === 'unknown' ? live.status.status : stream.status) },
      result: stream.result ?? live.result,
      report_md: stream.reportMd ?? live.report_md,
      input: stream.input ?? live.input,
    }
  }, [detailQ.data, stream])

  async function exportMisp() {
    const r = await fetch(`/api/tip/misp-export?triage_id=${encodeURIComponent(triageId)}`)
    if (!r.ok) return
    const blob = new Blob([JSON.stringify(await r.json(), null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${triageId}.misp.json`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  async function del() {
    if (!confirm(`Delete triage ${triageId}?`)) return
    await api.deleteTriage(triageId)
    qc.invalidateQueries({ queryKey: ['triages'] })
    onDeleted()
  }

  if (detailQ.isLoading && !detail) {
    return <div className="h-full flex items-center justify-center text-xs text-ink-faint">loading…</div>
  }
  if (!detail) {
    return <div className="h-full flex items-center justify-center text-xs text-ink-faint">not found</div>
  }

  const status = detail.status.status
  const isRunning = status === 'pending' || status === 'running'
  const result = detail.result
  const reportMd = detail.report_md

  return (
    <div className="h-full flex flex-col">
      <header className="px-6 pt-4 pb-3 border-b border-border">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-1">
              <StatusDot status={status} />
              <span className="text-2xs uppercase tracking-[0.1em] text-ink-faint">{status}</span>
              <code className="font-mono text-2xs text-ink-faint">{triageId}</code>
            </div>
            <TriageDetailTitle
              triageId={triageId}
              customName={detail.input.custom_name ?? null}
              fallback={triageLabel({
                headline: result?.headline ?? null,
                input_ref: detail.input.input_ref,
                question: detail.input.question,
              })}
            />
            <div className="flex items-center gap-2 mt-1 text-2xs text-ink-dim">
              <InputTypeIcon type={detail.input.input_type} />
              <span className="font-mono truncate max-w-[520px]">
                {detail.input.input_ref || (detail.input.input_type === 'text' ? '(pasted content)' : '(file)')}
              </span>
              <span className="mx-1">·</span>
              <span>SIEM: {detail.input.siem_preference}</span>
              <span className="mx-1">·</span>
              <span>env: {detail.input.use_environment ? 'on' : 'off'}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              className="btn btn-primary"
              disabled={!result || isRunning}
              title={isRunning ? 'Wait for analysis to finish' : !result ? 'No structured result yet' : 'Download this triage as a MISP Event'}
              onClick={exportMisp}
            >
              <ArrowRight className="w-3.5 h-3.5" /> MISP export
            </button>
            <button className="btn btn-ghost" onClick={del} title="Delete triage">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {detail.status.error && (
          <div className="mt-3 chip chip-danger !text-xs flex items-start gap-2 max-w-full">
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <span className="break-words">{detail.status.error}</span>
          </div>
        )}
      </header>

      {/* Main: report + structured widgets */}
      <section className="flex-1 overflow-y-auto min-w-0">
        {isRunning && !result && (
          <div className="p-6 text-sm text-ink-dim">
            <Loader2 className="w-4 h-4 inline-block animate-spin mr-2 text-info" />
            Analysis in progress, live agent output in the panel at the bottom.
          </div>
        )}
        {(result || reportMd) && (
          <div className="max-w-4xl mx-auto px-6 py-6 space-y-6">
            {result && <ResultSummary result={result} />}
            {result && (result.key_findings?.length || 0) > 0 && (
              <KeyFindings findings={result.key_findings!} />
            )}
            {reportMd && <ReportCard md={reportMd} />}
            {result && (result.hunts?.length || 0) > 0 && (
              <HuntsPanel hunts={result.hunts!} />
            )}
            {result && (result.detections?.length || 0) > 0 && (
              <DetectionsPanel detections={result.detections!} />
            )}
            {result && (result.actions?.length || 0) > 0 && (
              <ActionsPanel actions={result.actions!} />
            )}
            {result && ((result.iocs?.length || 0) > 0 || (result.cves?.length || 0) > 0) && (
              <IocsCvesPanel iocs={result.iocs || []} cves={result.cves || []} />
            )}
            {result && (result.sources?.length || 0) > 0 && (
              <SourcesPanel sources={result.sources!} />
            )}
          </div>
        )}
        {!isRunning && !result && !reportMd && (
          <div className="h-full flex items-center justify-center text-xs text-ink-faint p-8 text-center">
            Agent finished but produced no report. Check the event stream.
          </div>
        )}
      </section>

      {/* Bottom drawer: live agent stream, expanded while running,
          collapsible to a status bar once done so it doesn't steal
          vertical space from the finished report. */}
      <LiveStreamDrawer stream={stream} autoExpandWhileRunning={isRunning} />
    </div>
  )
}

// ── Collapsible bottom drawer for the live agent stream ──────────────

function LiveStreamDrawer({
  stream, autoExpandWhileRunning,
}: {
  stream: ReturnType<typeof useTriageStream>
  autoExpandWhileRunning: boolean
}) {
  const [open, setOpen] = useState(autoExpandWhileRunning)
  // When the triage transitions into running, auto-expand. When it
  // finishes, auto-collapse after a beat so the report can breathe.
  useEffect(() => {
    if (autoExpandWhileRunning) setOpen(true)
  }, [autoExpandWhileRunning])

  return (
    <div className="flex-shrink-0 border-t border-border bg-surface/80">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full px-4 py-1.5 flex items-center gap-2 text-2xs uppercase tracking-[0.1em] text-ink-faint hover:text-ink-dim transition-colors"
      >
        {stream.status === 'running' && <Loader2 className="w-3 h-3 animate-spin text-info" />}
        Live stream · {stream.status}
        <span className="text-ink-faint">· {stream.liveEvents.length} events</span>
        {open
          ? <ChevronDown className="w-3 h-3 ml-auto" />
          : <ChevronUp className="w-3 h-3 ml-auto" />}
      </button>
      {open && (
        <div className="border-t border-border max-h-[280px]">
          <LiveRun stream={stream} compact />
        </div>
      )}
    </div>
  )
}

// ── Result summary ────────────────────────────────────────────────────

/** Inline-editable title for the triage run header. Click to rename. */
function TriageDetailTitle({
  triageId, customName, fallback,
}: {
  triageId: string
  customName: string | null
  fallback: string
}) {
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(customName || fallback)
  const inputRef = useRef<HTMLInputElement>(null)

  // Keep the draft in sync when the underlying name changes (e.g.
  // another tab renamed the same triage).
  useEffect(() => {
    if (!editing) setDraft(customName || fallback)
  }, [customName, fallback, editing])

  useEffect(() => {
    if (editing) { inputRef.current?.focus(); inputRef.current?.select() }
  }, [editing])

  const rename = useMutation({
    mutationFn: (name: string | null) => api.renameTriage(triageId, name),
    onSuccess: () => {
      setEditing(false)
      qc.invalidateQueries({ queryKey: ['triages'] })
      qc.invalidateQueries({ queryKey: ['triage', triageId] })
    },
  })

  function commit() {
    const next = draft.trim()
    const current = (customName || '').trim()
    if (next === current) { setEditing(false); return }
    rename.mutate(next || null)
  }

  if (editing) {
    return (
      <input
        ref={inputRef}
        className="input !py-0.5 !text-base font-semibold text-ink w-full"
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); setDraft(customName || fallback); setEditing(false) }
        }}
        placeholder="name this triage…"
        disabled={rename.isPending}
      />
    )
  }
  return (
    <h2
      className="text-base font-semibold text-ink group cursor-text flex items-center gap-1.5 min-w-0"
      onClick={() => setEditing(true)}
      title={customName ? 'Click to rename' : 'Click to set a custom name'}
    >
      <span className="truncate min-w-0">{customName || fallback}</span>
      <Pencil className="w-3 h-3 text-ink-faint opacity-0 group-hover:opacity-100 transition flex-shrink-0" />
    </h2>
  )
}

// Disposition → visual treatment for a key finding. Color carries the
// signal: red = malicious, amber = suspicious, green = benign, blue = info.
const FINDING_DISPO: Record<string, { dot: string; text: string; label: string }> = {
  malicious:  { dot: 'bg-danger',  text: 'text-danger',  label: 'malicious' },
  suspicious: { dot: 'bg-warning', text: 'text-warning', label: 'suspicious' },
  benign:     { dot: 'bg-success', text: 'text-success', label: 'benign' },
  info:       { dot: 'bg-info',    text: 'text-info',    label: 'info' },
}

type Finding = { disposition?: string; statement: string; evidence?: string }

/**
 * Key findings — the scannable lead of the analysis. Each finding is one
 * plain-English line with a disposition dot; its evidence expands on
 * demand. This is what replaces "read three paragraphs to extract the
 * facts" — the pattern every agentic-IR tool converges on.
 */
function KeyFindings({ findings }: { findings: Finding[] }) {
  return (
    <section className="card p-5">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-2xs uppercase tracking-[0.1em] text-ink-faint flex items-center gap-1.5">
          <ListChecks className="w-3 h-3" /> Key findings
        </h3>
        <span className="text-2xs text-ink-faint tnum">{findings.length}</span>
      </div>
      <ul className="divide-y divide-border">
        {findings.map((f, i) => <FindingRow key={i} f={f} />)}
      </ul>
    </section>
  )
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false)
  const d = FINDING_DISPO[(f.disposition || 'info').toLowerCase()] || FINDING_DISPO.info
  const hasEvidence = !!(f.evidence && f.evidence.trim())
  return (
    <li>
      <button
        onClick={() => hasEvidence && setOpen(o => !o)}
        className={cn('w-full flex items-start gap-2.5 py-2 text-left', hasEvidence ? 'cursor-pointer group' : 'cursor-default')}
      >
        <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0 mt-[7px]', d.dot)} title={d.label} />
        <span className="flex-1 min-w-0 text-sm text-ink leading-snug">{f.statement}</span>
        <span className={cn('text-[10px] uppercase tracking-wide flex-shrink-0 mt-0.5', d.text)}>{d.label}</span>
        {hasEvidence && (
          open
            ? <ChevronUp className="w-3 h-3 text-ink-faint flex-shrink-0 mt-1" />
            : <ChevronDown className="w-3 h-3 text-ink-faint flex-shrink-0 mt-1 opacity-50 group-hover:opacity-100" />
        )}
      </button>
      {open && hasEvidence && (
        <div className="ml-4 mb-2 pl-3 border-l-2 border-border text-xs text-ink-dim leading-relaxed whitespace-pre-wrap">
          {f.evidence}
        </div>
      )}
    </li>
  )
}

/**
 * The agent's narrative report. The structured widgets above (summary,
 * key findings, hunts, detections, actions, IOCs) carry the scannable
 * facts; this is the supporting prose. A long report is collapsed behind
 * a fade so it doesn't bury those widgets in a wall of text — the analyst
 * expands it only when they want the full reasoning.
 */
function ReportCard({ md }: { md: string }) {
  const long = md.length > 1600
  const [expanded, setExpanded] = useState(!long)
  return (
    <section className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-2xs uppercase tracking-[0.1em] text-ink-faint flex items-center gap-1.5">
          <FileText className="w-3 h-3" /> Analysis
        </h3>
        {long && (
          <button onClick={() => setExpanded(v => !v)} className="btn btn-ghost btn-xs">
            {expanded
              ? <><ChevronUp className="w-3 h-3" /> collapse</>
              : <><ChevronDown className="w-3 h-3" /> expand</>}
          </button>
        )}
      </div>
      <div className={cn('md-body relative', !expanded && 'max-h-[22rem] overflow-hidden')}>
        <ReactMarkdown>{md}</ReactMarkdown>
        {!expanded && (
          <div className="absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-surface to-transparent pointer-events-none" />
        )}
      </div>
      {long && !expanded && (
        <button
          onClick={() => setExpanded(true)}
          className="mt-2 text-2xs text-accent hover:text-accent-hot"
        >
          Show full analysis (~{Math.round(md.length / 1000)}k chars) →
        </button>
      )}
    </section>
  )
}

function ResultSummary({ result }: { result: TriageResult }) {
  const score = result.prioritization_score
  return (
    <section className="card p-5">
      <div className="flex items-start gap-5">
        {typeof score === 'number' && (
          <div className="flex-shrink-0 flex flex-col items-center">
            <ScoreDial score={score} severity={result.severity} />
            <div className="text-2xs text-ink-faint mt-1 uppercase tracking-[0.1em]">score</div>
          </div>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            {result.severity && (
              <span className={cn('chip !text-2xs uppercase',
                result.severity === 'critical' || result.severity === 'high' ? 'chip-danger' :
                result.severity === 'medium' ? 'chip-warning' :
                result.severity === 'low' ? 'chip-info' : '',
              )}>{result.severity}</span>
            )}
            {result.exploitation_status && (
              <span className={cn('chip !text-2xs',
                result.exploitation_status === 'in-the-wild' || result.exploitation_status === 'mass-scanning' ? 'chip-danger' :
                result.exploitation_status === 'PoC' ? 'chip-warning' : '',
              )}>{result.exploitation_status}</span>
            )}
            {result.malware_family && <span className="chip chip-accent !text-2xs">{flattenChip(result.malware_family)}</span>}
            {result.actor_group && <span className="chip !text-2xs">{flattenChip(result.actor_group)}</span>}
          </div>
          {result.short_answer && (
            <p className="text-sm text-ink leading-relaxed">{result.short_answer}</p>
          )}
          {result.our_exposure && (
            <div className="mt-3 text-xs text-ink-dim">
              <span className={result.our_exposure.applicable_to_env ? 'text-danger font-semibold' : 'text-ink-dim'}>
                {result.our_exposure.applicable_to_env ? 'Applicable to your env' : 'Not applicable to your env'}
              </span>
              {typeof result.our_exposure.hosts_potentially_affected === 'number' && (
                <> · {result.our_exposure.hosts_potentially_affected} hosts</>
              )}
              {result.our_exposure.notes && <div className="mt-1 text-ink-faint">{result.our_exposure.notes}</div>}
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function ScoreDial({ score, severity }: { score: number; severity?: string }) {
  const pct = Math.max(0, Math.min(100, score))
  const hue = severity === 'critical' || severity === 'high' || score >= 80 ? '#e04a4a' :
              severity === 'medium' || score >= 60 ? '#e0a95a' :
              severity === 'low' || score >= 40 ? '#5a89ab' : '#6b7a8c'
  const r = 26, circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ
  return (
    <div className="relative">
      <svg width="64" height="64" viewBox="0 0 64 64">
        <circle cx="32" cy="32" r={r} stroke="#2a2a2e" strokeWidth="4" fill="none" />
        <circle cx="32" cy="32" r={r}
          stroke={hue} strokeWidth="4" fill="none"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 32 32)"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-lg font-bold tnum" style={{ color: hue }}>{score}</span>
      </div>
    </div>
  )
}

// ── Hunts ─────────────────────────────────────────────────────────────

function HuntsPanel({ hunts }: { hunts: NonNullable<TriageResult['hunts']> }) {
  return (
    <section className="card p-5">
      <h3 className="text-sm font-semibold text-ink mb-3 flex items-center gap-2">
        <Search className="w-3.5 h-3.5" /> Threat hunts
      </h3>
      <div className="space-y-4">
        {hunts.map((h, i) => (
          <HuntCard key={i} hunt={h} />
        ))}
      </div>
    </section>
  )
}

function HuntCard({ hunt }: { hunt: NonNullable<TriageResult['hunts']>[number] }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(hunt.query).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="border border-border rounded p-3 bg-surface">
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="text-sm text-ink leading-snug flex-1">{hunt.hypothesis}</div>
        <span className="chip !text-2xs flex-shrink-0">{hunt.siem}</span>
      </div>
      <div className="relative group">
        <pre className="text-xs font-mono bg-bg border border-border rounded p-3 overflow-x-auto whitespace-pre">
{hunt.query}
        </pre>
        <button
          className="absolute top-2 right-2 btn btn-ghost btn-xs opacity-60 hover:opacity-100"
          onClick={copy}
          title="Copy query"
        >
          {copied ? <CheckCircle2 className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      {hunt.notes && (
        <p className="text-2xs text-ink-dim mt-2 leading-relaxed">{hunt.notes}</p>
      )}
    </div>
  )
}

// ── Detections ────────────────────────────────────────────────────────

function DetectionsPanel({ detections }: { detections: NonNullable<TriageResult['detections']> }) {
  return (
    <section className="card p-5">
      <h3 className="text-sm font-semibold text-ink mb-3 flex items-center gap-2">
        <AlertCircle className="w-3.5 h-3.5" /> Detection logic
      </h3>
      <div className="space-y-3">
        {detections.map((d, i) => (
          <DetectionCard key={i} detection={d} />
        ))}
      </div>
    </section>
  )
}

function DetectionCard({ detection }: { detection: NonNullable<TriageResult['detections']>[number] }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(detection.rule).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="border border-border rounded p-3 bg-surface">
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="text-sm text-ink font-medium">{detection.title}</div>
        <span className="chip !text-2xs">{detection.format}</span>
      </div>
      <div className="relative">
        <pre className="text-xs font-mono bg-bg border border-border rounded p-3 overflow-x-auto whitespace-pre">
{detection.rule}
        </pre>
        <button
          className="absolute top-2 right-2 btn btn-ghost btn-xs opacity-60 hover:opacity-100"
          onClick={copy}
          title="Copy rule"
        >
          {copied ? <CheckCircle2 className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
    </div>
  )
}

// ── Actions ───────────────────────────────────────────────────────────

function ActionsPanel({ actions }: { actions: NonNullable<TriageResult['actions']> }) {
  return (
    <section className="card p-5">
      <h3 className="text-sm font-semibold text-ink mb-3">Recommended actions</h3>
      <ol className="space-y-2 list-none">
        {actions.map((a, i) => (
          <li key={i} className="flex items-start gap-3 p-2 rounded hover:bg-surface2">
            <span className="text-2xs font-mono text-ink-faint pt-1 w-5 flex-shrink-0">{i + 1}.</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm text-ink leading-snug">{a.title}</span>
                {a.urgency && (
                  <span className={cn('chip !text-2xs',
                    a.urgency === '24h' ? 'chip-danger' :
                    a.urgency === '72h' || a.urgency === 'today' ? 'chip-warning' : '',
                  )}>{a.urgency}</span>
                )}
                {a.category && <span className="chip !text-2xs">{a.category}</span>}
              </div>
              {a.rationale && <div className="text-2xs text-ink-dim mt-1 leading-relaxed">{a.rationale}</div>}
            </div>
          </li>
        ))}
      </ol>
    </section>
  )
}

// ── IOCs + CVEs ───────────────────────────────────────────────────────

function IocsCvesPanel({
  iocs, cves,
}: {
  iocs: NonNullable<TriageResult['iocs']>
  cves: NonNullable<TriageResult['cves']>
}) {
  return (
    <section className="card p-5 grid grid-cols-1 md:grid-cols-2 gap-6">
      {cves.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-ink mb-3">CVEs</h3>
          <ul className="space-y-1.5">
            {cves.map(c => (
              <li key={c.id} className="flex items-center gap-2 text-sm flex-wrap">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                  target="_blank" rel="noopener noreferrer"
                  className="chip chip-accent hover:bg-accent/20"
                >{c.id}</a>
                {c.cvss_base && <span className="tnum text-ink">CVSS {c.cvss_base}</span>}
                {typeof c.epss_percentile === 'number' && (
                  <span className="text-ink-dim">EPSS {Math.round(c.epss_percentile)}pct</span>
                )}
                {c.in_kev && <span className="chip chip-danger !text-2xs">KEV</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {iocs.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-ink mb-3">IOCs</h3>
          <ul className="space-y-1">
            {iocs.map((ioc, i) => (
              <li key={i} className="flex items-center gap-2 text-xs">
                <span className="chip !text-2xs">{ioc.type}</span>
                <span className="font-mono text-ink break-all">{ioc.value}</span>
                {ioc.disposition && <span className="text-2xs text-ink-faint">({ioc.disposition})</span>}
              </li>
            ))}
          </ul>
          <CopyAllButton items={iocs.map(i => i.value || '').filter(Boolean)} label="Copy all values" />
        </div>
      )}
    </section>
  )
}

function CopyAllButton({ items, label }: { items: string[]; label: string }) {
  const [copied, setCopied] = useState(false)
  if (items.length === 0) return null
  return (
    <button
      className="btn btn-ghost btn-xs mt-2"
      onClick={() => {
        navigator.clipboard.writeText(items.join('\n')).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        })
      }}
    >
      {copied ? <CheckCircle2 className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
      {copied ? 'copied' : label}
    </button>
  )
}

// ── Sources ──────────────────────────────────────────────────────────

/**
 * Sources panel. Schema drift note: the TriageResult type says
 * sources is ``string[]`` but the threat-triage agent actually emits
 * structured citation objects ``{title, publisher, url, date}`` quite
 * often. Accept both shapes defensively, normalize to {url, label}
 * before rendering, otherwise React 18 hits error #31 ("objects are
 * not valid as a React child") and blanks the whole view.
 */
type SourceShape =
  | string
  | {
      url?: string
      title?: string
      publisher?: string
      date?: string
      [k: string]: unknown
    }

function normalizeSource(s: SourceShape): { url: string; label: string; sub: string | null } {
  if (typeof s === 'string') {
    return { url: s, label: s, sub: null }
  }
  if (s && typeof s === 'object') {
    const url = (s.url as string) || ''
    const title = (s.title as string) || ''
    const publisher = (s.publisher as string) || ''
    const date = (s.date as string) || ''
    const label = title || url || '(untitled source)'
    const sub = [publisher, date].filter(Boolean).join(' · ') || null
    return { url, label, sub }
  }
  return { url: '', label: String(s ?? ''), sub: null }
}

function SourcesPanel({ sources }: { sources: SourceShape[] }) {
  return (
    <section className="card p-5">
      <h3 className="text-sm font-semibold text-ink mb-3">Sources</h3>
      <ul className="space-y-1">
        {sources.map((raw, i) => {
          const s = normalizeSource(raw)
          const content = (
            <>
              <ExternalLink className="w-2.5 h-2.5 flex-shrink-0" />
              <span className="truncate">{s.label}</span>
              {s.sub && <span className="text-ink-faint ml-2 flex-shrink-0">{s.sub}</span>}
            </>
          )
          return (
            <li key={i} className="text-xs">
              {s.url ? (
                <a
                  href={s.url}
                  target="_blank" rel="noopener noreferrer"
                  className="text-accent hover:text-accent-hot inline-flex items-center gap-1 max-w-full"
                >
                  {content}
                </a>
              ) : (
                <span className="text-ink-dim inline-flex items-center gap-1 max-w-full">{content}</span>
              )}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

// ── Live run rail ─────────────────────────────────────────────────────

function LiveRun({ stream, compact = false }: {
  stream: ReturnType<typeof useTriageStream>
  compact?: boolean
}) {
  const events = stream.liveEvents
  return (
    <div className={cn('flex flex-col', compact ? 'h-full' : 'h-full')}>
      <div className="px-3 py-2 border-b border-border text-2xs uppercase tracking-[0.1em] text-ink-faint flex items-center gap-2">
        {stream.status === 'running' && <Loader2 className="w-3 h-3 animate-spin text-info" />}
        Live stream · {stream.status}
      </div>
      <ul className="flex-1 overflow-y-auto px-3 py-2 space-y-1 text-xs">
        {events.length === 0 && (
          <li className="text-ink-faint italic">waiting for agent output…</li>
        )}
        {events.map((ev, i) => <EventLine key={i} ev={ev as unknown as EventShape} />)}
      </ul>
    </div>
  )
}

interface EventShape {
  kind?: string
  text?: string
  tool_name?: string
  input_preview?: string
  message?: string
  status?: string
}

function EventLine({ ev }: { ev: EventShape }) {
  const k = ev.kind
  if (k === 'text') {
    return <li className="text-ink leading-snug whitespace-pre-wrap">{String(ev.text || '')}</li>
  }
  if (k === 'thinking') {
    return <li className="text-ink-faint italic">thinking…</li>
  }
  if (k === 'tool_call') {
    return (
      <li className="text-ink-dim">
        <span className="chip !text-2xs">{String(ev.tool_name || 'tool')}</span>{' '}
        <span className="font-mono text-2xs break-all">{String(ev.input_preview || '').slice(0, 160)}</span>
      </li>
    )
  }
  if (k === 'tool_result') {
    return null  // paired into tool_call; skip separate line
  }
  if (k === 'triage_status') {
    return <li className="text-ink-dim">status → <span className="font-mono">{String(ev.status || '')}</span></li>
  }
  if (k === 'session_started') {
    return <li className="text-ink-faint">session started</li>
  }
  if (k === 'session_complete') {
    return <li className="text-ink-faint">session complete</li>
  }
  if (k === 'error') {
    return <li className="text-danger">error: {String(ev.message || '')}</li>
  }
  return null
}
