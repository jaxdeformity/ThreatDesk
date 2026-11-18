import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, ExternalLink, Plus, Trash2, Download, Check } from 'lucide-react'
import { api, type ServiceKey } from '@/api/client'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/cn'

/**
 * Threat-intel / OSINT API keys. Keys are DPAPI-encrypted on this
 * machine, never shown again after saving (last 4 only), and exported
 * as env vars so the TIP enrichers and the agents can use them.
 */
const CATEGORY_ORDER = ['reputation', 'malware', 'exposure', 'web', 'dns', 'osint', 'vuln', 'custom']
const CATEGORY_LABEL: Record<string, string> = {
  reputation: 'Reputation', malware: 'Malware', exposure: 'Internet exposure', web: 'Web / URL',
  dns: 'DNS / IP', osint: 'OSINT', vuln: 'Vulnerabilities', custom: 'Custom',
}

export function ServiceKeysCard() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data } = useQuery({ queryKey: ['service-keys'], queryFn: api.listServiceKeys })
  const keys = data?.keys || []
  const configured = keys.filter(k => k.configured).length
  const [importPath, setImportPath] = useState('')
  const [adding, setAdding] = useState(false)

  const refresh = () => qc.invalidateQueries({ queryKey: ['service-keys'] })
  const importM = useMutation({
    mutationFn: () => api.importServiceKeys(importPath),
    onSuccess: r => {
      toast('success', 'Imported', r.imported.length ? r.imported.join(', ') : 'Nothing new: those slots were already set.')
      setImportPath('')
      refresh()
    },
    onError: (e: Error) => toast('error', 'Import failed', e.message.slice(0, 200)),
  })

  const grouped = useMemo(() => {
    const m = new Map<string, ServiceKey[]>()
    for (const k of keys) m.set(k.category, [...(m.get(k.category) || []), k])
    return CATEGORY_ORDER.filter(c => m.has(c)).map(c => [c, m.get(c)!] as const)
  }, [keys])

  return (
    <section>
      <div className="flex items-end justify-between mb-2">
        <div>
          <h2 className="text-sm font-semibold text-ink flex items-center gap-1.5">
            <KeyRound className="w-3.5 h-3.5" /> Threat intel &amp; OSINT keys
          </h2>
          <div className="text-2xs text-ink-faint mt-0.5">
            {configured} of {keys.length} configured. Encrypted on this machine (Windows DPAPI), never shown again after saving.
            Agents and enrichers read them as environment variables.
          </div>
        </div>
        <button className="btn btn-sm btn-ghost" onClick={() => setAdding(v => !v)}>
          <Plus className="w-3 h-3" /> Custom service
        </button>
      </div>

      <div className="flex items-center gap-2 mb-3">
        <input className="input !text-xs flex-1" value={importPath} onChange={e => setImportPath(e.target.value)}
               placeholder="Import from a file: HoneyHive data\secrets.json or a 'Name: key' notes file" />
        <button className="btn btn-sm" disabled={!importPath.trim() || importM.isPending} onClick={() => importM.mutate()}>
          <Download className="w-3 h-3" /> Import
        </button>
      </div>

      {adding && <AddCustom onDone={() => { setAdding(false); refresh() }} />}

      <div className="border border-border rounded-md divide-y divide-border">
        {grouped.map(([cat, list]) => (
          <div key={cat}>
            <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-[0.14em] text-ink-faint">{CATEGORY_LABEL[cat] || cat}</div>
            {list.map(k => <KeyRow key={k.id} k={k} onChanged={refresh} />)}
          </div>
        ))}
        {!keys.length && <div className="px-3 py-3 text-xs text-ink-faint">loading…</div>}
      </div>
    </section>
  )
}

function KeyRow({ k, onChanged }: { k: ServiceKey; onChanged: () => void }) {
  const { toast } = useToast()
  const [val, setVal] = useState('')
  const [editing, setEditing] = useState(false)
  const save = useMutation({
    mutationFn: (v: string) => api.setServiceKey(k.id, v),
    onSuccess: (_r, v) => {
      toast('success', v ? `${k.label} key saved` : `${k.label} key removed`, v ? `Available as $${k.env}` : '')
      setVal(''); setEditing(false); onChanged()
    },
    onError: (e: Error) => toast('error', 'Save failed', e.message.slice(0, 200)),
  })
  const del = useMutation({
    mutationFn: () => api.deleteCustomServiceKey(k.id),
    onSuccess: onChanged,
  })
  return (
    <div className="px-3 py-2 flex items-center gap-3 text-sm">
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', k.configured ? 'bg-success' : 'bg-text-faint opacity-50')} />
      <div className="w-56 flex-shrink-0 min-w-0">
        <div className="text-ink truncate flex items-center gap-1">
          {k.label}
          {k.signup && (
            <a href={k.signup} target="_blank" rel="noreferrer noopener" className="text-ink-faint hover:text-accent" title="Get a key">
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
        <div className="text-2xs text-ink-faint font-mono truncate" title={k.use}>${k.env}</div>
      </div>
      {editing || !k.configured ? (
        <>
          <input type="password" autoComplete="off" spellCheck={false} className="input !text-xs flex-1"
                 value={val} onChange={e => setVal(e.target.value)} placeholder={k.use}
                 onKeyDown={e => { if (e.key === 'Enter' && val.trim()) save.mutate(val.trim()) }} />
          <button className="btn btn-sm btn-primary" disabled={!val.trim() || save.isPending} onClick={() => save.mutate(val.trim())}>
            Save
          </button>
          {editing && <button className="btn btn-sm btn-ghost" onClick={() => { setEditing(false); setVal('') }}>Cancel</button>}
        </>
      ) : (
        <>
          <span className="flex-1 text-xs text-ink-dim flex items-center gap-1.5">
            <Check className="w-3 h-3 text-success" />
            {k.source === 'env' ? 'set in the server environment' : `saved ····${k.last4 || ''}`}
          </span>
          {k.source !== 'env' && (
            <>
              <button className="btn btn-sm btn-ghost" onClick={() => setEditing(true)}>Replace</button>
              <button className="btn btn-sm btn-ghost" disabled={save.isPending} onClick={() => save.mutate('')}>Remove</button>
            </>
          )}
        </>
      )}
      {k.custom && (
        <button className="btn btn-xs btn-ghost" title="Delete custom service" onClick={() => del.mutate()}>
          <Trash2 className="w-3 h-3" />
        </button>
      )}
    </div>
  )
}

function AddCustom({ onDone }: { onDone: () => void }) {
  const { toast } = useToast()
  const [f, setF] = useState({ label: '', env: '', value: '', signup: '' })
  const m = useMutation({
    mutationFn: () => api.addCustomServiceKey({
      id: f.label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
      label: f.label, env: f.env.toUpperCase(), value: f.value, signup: f.signup,
    }),
    onSuccess: () => { toast('success', 'Service added', `Available as $${f.env.toUpperCase()}`); onDone() },
    onError: (e: Error) => toast('error', 'Could not add', e.message.slice(0, 200)),
  })
  return (
    <div className="mb-3 border border-border rounded-md p-3 grid grid-cols-2 gap-2">
      <input className="input !text-xs" placeholder="Service name (e.g. Spur)" value={f.label} onChange={e => setF({ ...f, label: e.target.value })} />
      <input className="input !text-xs font-mono" placeholder="ENV_VAR_NAME" value={f.env} onChange={e => setF({ ...f, env: e.target.value })} />
      <input type="password" autoComplete="off" className="input !text-xs" placeholder="API key" value={f.value} onChange={e => setF({ ...f, value: e.target.value })} />
      <input className="input !text-xs" placeholder="Key page URL (optional)" value={f.signup} onChange={e => setF({ ...f, signup: e.target.value })} />
      <div className="col-span-2 flex justify-end">
        <button className="btn btn-sm btn-primary" disabled={!f.label || !f.env || m.isPending} onClick={() => m.mutate()}>Add service</button>
      </div>
    </div>
  )
}
