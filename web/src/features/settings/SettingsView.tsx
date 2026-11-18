import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Save, CheckCheck, Zap, Upload, Download, Database, Loader2 } from 'lucide-react'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/cn'
import { api, type RuntimeSettings } from '@/api/client'
import { ContextStrip } from '@/kit/ContextStrip'
import { AISettingsPanel } from '@/features/settings/AISettingsPanel'
import { ServiceKeysCard } from './ServiceKeysCard'

// ThreatDesk Settings: the org inventory (tech-stack doc) that Vulns and
// Triage share, the environment profile the triage agent reads, the
// triage model, threat-intel keys, and AI providers.
export function SettingsView() {
  return (
    <div className="h-full flex flex-col">
      <ContextStrip title="SETTINGS" />
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-6 py-6 space-y-8">
          <InventoryCard />
          <EnvironmentCard />
          <TriageModelCard />
          <ServiceKeysCard />
          <AISettingsPanel />
        </div>
      </div>
    </div>
  )
}

function InventoryCard() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const fileRef = useRef<HTMLInputElement>(null)
  const q = useQuery({ queryKey: ['inventory-sources'], queryFn: () => api.inventorySources() })
  const upload = useMutation({
    mutationFn: (f: File) => api.uploadInventoryCsv(f),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['inventory-sources'] })
      qc.invalidateQueries({ queryKey: ['vulns'] })
      qc.invalidateQueries({ queryKey: ['environment'] })
      toast('success', 'Inventory updated', `${r.count} assets loaded${r.errors.length ? `, ${r.errors.length} rows skipped` : ''}.`)
    },
    onError: (e: Error) => toast('error', 'Upload rejected', e.message.slice(0, 240)),
  })

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <div>
          <h2 className="text-sm font-semibold text-ink flex items-center gap-2">
            <Database className="w-3.5 h-3.5 text-accent" /> Technology inventory
          </h2>
          <div className="text-2xs text-ink-faint mt-0.5">
            The one list of what the org runs. Vulns matches exploited CVEs against it; Triage reads it when
            "cross-reference with our environment" is ticked. {q.data ? `${q.data.asset_count} assets loaded.` : ''}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a className="btn btn-ghost" href="/api/inventory/template.csv" download>
            <Download className="w-3 h-3" /> Template
          </a>
          <button className="btn btn-primary" disabled={upload.isPending} onClick={() => fileRef.current?.click()}>
            {upload.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Upload className="w-3 h-3" />}
            Upload tech-stack CSV
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".csv,text/csv"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) upload.mutate(f)
              e.target.value = ''
            }}
          />
        </div>
      </div>
      <div className="border border-border rounded-md divide-y divide-border">
        {(q.data?.sources || []).map((s) => (
          <div key={s.name} className="flex items-start gap-3 px-3 py-2 text-sm">
            <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5', s.configured ? 'bg-success' : 'bg-ink-faint/40')} />
            <span className="text-ink w-44 flex-shrink-0">{s.label}</span>
            <div className="flex-1 min-w-0 text-xs text-ink-dim">
              {s.configured ? `${s.count} assets` : s.note || 'not configured'}
              {s.path && <span className="font-mono text-ink-faint"> · {s.path}</span>}
              {s.errors.length > 0 && (
                <div className="text-warning mt-0.5">
                  {s.errors.slice(0, 3).join(' · ')}{s.errors.length > 3 ? ` · +${s.errors.length - 3} more` : ''}
                </div>
              )}
            </div>
          </div>
        ))}
        {!q.data && <div className="px-3 py-3 text-xs text-ink-faint">loading…</div>}
      </div>
      <p className="text-2xs text-ink-faint mt-2">
        Precedence on duplicates: CSV, then inventory JSON, then the <code className="font-mono">THREATDESK_TECH_STACK</code> list.
        Columns: <code className="font-mono text-ink-dim">{(q.data?.columns || []).join(', ')}</code>. <code className="font-mono">match</code> is a
        semicolon-separated list of the names CISA KEV uses for the product.
      </p>
    </section>
  )
}

function EnvironmentCard() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data: envData, isLoading } = useQuery({ queryKey: ['environment'], queryFn: () => api.getEnvironment() })
  const [body, setBody] = useState('')
  const [dirty, setDirty] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    if (!dirty && envData?.environment) setBody(JSON.stringify(envData.environment, null, 2))
  }, [envData, dirty])

  const save = useMutation({
    mutationFn: async () => {
      let parsed: Record<string, unknown>
      try {
        parsed = JSON.parse(body)
      } catch (e) {
        setErr(`invalid JSON: ${(e as Error).message}`)
        throw e
      }
      setErr('')
      return api.saveEnvironment(parsed)
    },
    onSuccess: () => {
      setDirty(false)
      qc.invalidateQueries({ queryKey: ['environment'] })
      toast('success', 'Saved', 'Environment profile persisted.')
    },
    onError: (e: Error) => { if (!err) toast('error', 'Save failed', e.message.slice(0, 200)) },
  })

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <div>
          <h2 className="text-sm font-semibold text-ink">Environment profile</h2>
          <div className="text-2xs text-ink-faint mt-0.5">
            Org, SIEM, EDR, crown jewels and intel feeds. Read by the threat-triage agent alongside the inventory.
            Source: <span className="font-mono">{envData?.source || '?'}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {envData?.source === 'example' && (
            <span className="chip chip-warning"><AlertTriangle className="w-3 h-3" /> using example data</span>
          )}
          <button className="btn btn-primary" onClick={() => save.mutate()} disabled={!dirty || save.isPending}>
            {save.isPending ? <>saving…</> : dirty ? <><Save className="w-3 h-3" /> Save</> : <><CheckCheck className="w-3 h-3" /> Saved</>}
          </button>
        </div>
      </div>
      {isLoading ? (
        <div className="py-8 text-center text-sm text-ink-faint">loading…</div>
      ) : (
        <>
          <textarea
            value={body}
            onChange={(e) => { setBody(e.target.value); setDirty(true); setErr('') }}
            className="textarea !min-h-[40vh] !text-xs leading-relaxed"
            spellCheck={false}
          />
          {err && <div className="mt-2 text-xs text-danger font-mono">{err}</div>}
          <p className="text-2xs text-ink-faint mt-2">
            Loose schema; the agent reads what is there. Common fields:
            <code className="font-mono text-ink-dim ml-1">org.{'{name,industry,regulatory_scope,crown_jewels}'}</code>,
            <code className="font-mono text-ink-dim ml-1">edr</code>,
            <code className="font-mono text-ink-dim ml-1">network</code>,
            <code className="font-mono text-ink-dim ml-1">intel_feeds</code>. Assets belong in the inventory above.
          </p>
        </>
      )}
    </section>
  )
}

function TriageModelCard() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const q = useQuery({ queryKey: ['runtime-settings'], queryFn: () => api.getRuntimeSettings() })
  const [form, setForm] = useState<RuntimeSettings | null>(null)
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (q.data) { setForm({ ...q.data.settings }); setDirty(false) }
  }, [q.data?.settings])

  const saveMut = useMutation({
    mutationFn: (patch: RuntimeSettings) => api.saveRuntimeSettings(patch),
    onSuccess: (res) => {
      qc.setQueryData(['runtime-settings'], { ...q.data!, settings: res.settings })
      setDirty(false)
      toast('success', 'Saved', 'The next triage uses these settings.')
    },
    onError: (e) => toast('error', 'Save failed', String(e)),
  })

  if (!form || !q.data) {
    return (
      <section>
        <h2 className="text-sm font-semibold text-ink mb-2 flex items-center gap-2"><Zap className="w-3.5 h-3.5 text-accent" /> Triage agent</h2>
        <div className="border border-border rounded-md px-3 py-3 text-xs text-ink-faint">loading…</div>
      </section>
    )
  }
  const models = q.data.supported_models
  const set = (patch: Partial<RuntimeSettings>) => { setForm({ ...form, ...patch }); setDirty(true) }

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-sm font-semibold text-ink flex items-center gap-2"><Zap className="w-3.5 h-3.5 text-accent" /> Triage agent</h2>
        <button className="btn btn-primary" disabled={!dirty || saveMut.isPending} onClick={() => saveMut.mutate(form)}>
          {dirty ? <><Save className="w-3 h-3" /> Save</> : <><CheckCheck className="w-3 h-3" /> Saved</>}
        </button>
      </div>
      <div className="border border-border rounded-md p-4 space-y-4">
        <div>
          <label className="label">Model</label>
          <select value={form.triage_model} onChange={(e) => set({ triage_model: e.target.value })} className="input max-w-md">
            {models.map((m) => <option key={m.id} value={m.id}>{m.label} ({m.tag})</option>)}
          </select>
          <div className="text-2xs text-ink-faint mt-1">A route set under AI providers → agent routing overrides this.</div>
        </div>
        <label className="flex items-start gap-2 text-sm text-ink cursor-pointer select-none">
          <input type="checkbox" className="accent-accent mt-1" checked={form.use_subscription}
            onChange={(e) => set({ use_subscription: e.target.checked })} />
          <span>
            Run on the logged-in Claude subscription
            <span className="block text-2xs text-ink-faint">Off (default): the agent bills to the API key (or Bedrock/Vertex env). On: the key is withheld from the agent.</span>
          </span>
        </label>
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex items-start gap-2 text-sm text-ink cursor-pointer select-none">
            <input type="checkbox" className="accent-accent mt-1" checked={form.cyber_fallback_enabled}
              onChange={(e) => set({ cyber_fallback_enabled: e.target.checked })} />
            <span>
              Retry refused turns on a fallback model
              <span className="block text-2xs text-ink-faint">Only useful if your account holds a cyber-use exemption for that model.</span>
            </span>
          </label>
          {form.cyber_fallback_enabled && (
            <select value={form.cyber_fallback_model} onChange={(e) => set({ cyber_fallback_model: e.target.value })} className="input max-w-xs">
              {models.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
            </select>
          )}
        </div>
      </div>
    </section>
  )
}
