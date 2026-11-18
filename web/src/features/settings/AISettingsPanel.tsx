import { useEffect, useMemo, useState } from 'react'
import {
  aiConfigClient,
  type AIConfig,
  type AgentRoute,
  type CanonicalAgent,
  type McpEnvWrite as McpEnvWriteValue,
  type McpRegistryEntry,
  type McpServerStatus,
  type ProviderKind,
  type ProviderStatus,
} from '@/lib/aiConfig'

// Power-user AI surface in Settings. Three stacked panels:
//   1. Providers     — what model APIs are configured
//   2. MCP servers   — what tools agents can reach for
//   3. Agent routing — per-agent provider+model overrides

export function AISettingsPanel() {
  const [cfg, setCfg] = useState<AIConfig | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const reload = async () => {
    setBusy(true); setErr(null)
    try { setCfg(await aiConfigClient.get()) }
    catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }

  useEffect(() => { reload() }, [])

  if (!cfg) {
    return (
      <section className="border border-hairline p-4 font-mono">
        <div className="text-[11px] tracking-[0.12em] text-text-faint uppercase mb-2">AI</div>
        <div className="text-text-dim text-[12px]">{err || 'loading…'}</div>
      </section>
    )
  }

  return (
    <section className="border border-hairline p-4 font-mono flex flex-col gap-6">
      <div>
        <div className="text-[11px] tracking-[0.12em] text-text-faint uppercase">AI</div>
        <div className="text-text-dim text-[11.5px] mt-1">
          Connect your own model providers, wire MCP tools, and route specific agents at specific models. All credentials stored encrypted via Windows DPAPI.
        </div>
      </div>

      <ProvidersPanel cfg={cfg} onChange={reload} disabled={busy} />
      <McpPanel cfg={cfg} onChange={reload} disabled={busy} />
      <AgentRoutingPanel cfg={cfg} onChange={reload} disabled={busy} />

      {err && <div className="text-crit text-[11.5px]">{err}</div>}
    </section>
  )
}

/* ────────────────────────────────────────────────────────────────── */
/* Providers                                                         */
/* ────────────────────────────────────────────────────────────────── */

function ProvidersPanel({ cfg, onChange, disabled }: {
  cfg: AIConfig
  onChange: () => void
  disabled: boolean
}) {
  const [adding, setAdding] = useState(false)
  const entries = Object.entries(cfg.providers)

  return (
    <div className="flex flex-col gap-3">
      <PanelHeader
        title="Providers"
        sub="Each provider is a model API: cloud (Anthropic, OpenAI), local (Ollama), or any OpenAI/Anthropic-compatible endpoint."
        action={!adding && (
          <button
            type="button"
            onClick={() => setAdding(true)}
            className="text-accent text-[11px] tracking-[0.1em] uppercase hover:text-accent-hot border border-accent px-3 py-1"
          >+ add provider</button>
        )}
      />

      {adding && (
        <ProviderForm
          existing={null}
          onCancel={() => setAdding(false)}
          onSaved={() => { setAdding(false); onChange() }}
        />
      )}

      {entries.length === 0 && !adding && (
        <div className="text-text-faint text-[11.5px] italic">No providers configured. Add one to enable live agents.</div>
      )}

      <div className="flex flex-col gap-2">
        {entries.map(([id, p]) => (
          <ProviderRow key={id} id={id} p={p} disabled={disabled} onChange={onChange} />
        ))}
      </div>
    </div>
  )
}

function ProviderRow({ id, p, disabled, onChange }: {
  id: string
  p: ProviderStatus
  disabled: boolean
  onChange: () => void
}) {
  const [editing, setEditing] = useState(false)
  const [validating, setValidating] = useState(false)
  const [validationMsg, setValidationMsg] = useState<string | null>(null)

  const validate = async () => {
    setValidating(true); setValidationMsg(null)
    try {
      const r = await aiConfigClient.validateProvider(id)
      setValidationMsg(r.ok ? '✓ validated just now' : `✗ ${r.error || 'failed'}`)
      onChange()
    } catch (e) {
      setValidationMsg(`✗ ${(e as Error).message}`)
    } finally {
      setValidating(false)
    }
  }

  const remove = async () => {
    if (!confirm(`Remove provider "${p.label}"? Any agent routes using it will be cleared.`)) return
    await aiConfigClient.deleteProvider(id)
    onChange()
  }

  if (editing) {
    return (
      <ProviderForm
        existing={{ id, status: p }}
        onCancel={() => setEditing(false)}
        onSaved={() => { setEditing(false); onChange() }}
      />
    )
  }

  const statusDot = p.validated_at ? 'bg-ok' : p.configured ? 'bg-warn' : 'bg-text-faint'

  return (
    <div className="border border-hairline-strong p-3 grid grid-cols-[12px_1fr_auto] gap-3 items-center">
      <span className={`w-2 h-2 rounded-full inline-block ${statusDot}`} />
      <div className="flex flex-col gap-0.5 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-text font-semibold text-[13px]">{p.label}</span>
          <span className="text-text-faint text-[10.5px] tracking-[0.08em] uppercase">{p.kind}</span>
          {p.fingerprint && (
            <span className="text-text-dim text-[11px] font-mono">{p.fingerprint}</span>
          )}
        </div>
        <div className="text-text-faint text-[10.5px] truncate">
          {p.endpoint}
          {p.validated_at && <> · validated {timeAgo(p.validated_at)}</>}
          {!p.validated_at && p.configured && <> · not yet validated</>}
        </div>
        {validationMsg && (
          <div className={`text-[11px] mt-1 ${validationMsg.startsWith('✓') ? 'text-ok' : 'text-crit'}`}>
            {validationMsg}
          </div>
        )}
      </div>
      <div className="flex items-center gap-2">
        <button type="button" onClick={validate} disabled={validating || disabled}
          className="text-text-dim hover:text-text text-[10.5px] tracking-[0.08em] uppercase border border-hairline-strong px-2 py-0.5">
          {validating ? '…' : 'validate'}
        </button>
        <button type="button" onClick={() => setEditing(true)} disabled={disabled}
          className="text-text-dim hover:text-text text-[10.5px] tracking-[0.08em] uppercase border border-hairline-strong px-2 py-0.5">
          edit
        </button>
        <button type="button" onClick={remove} disabled={disabled}
          className="text-crit hover:bg-crit hover:text-bg text-[10.5px] tracking-[0.08em] uppercase border border-crit px-2 py-0.5">
          delete
        </button>
      </div>
    </div>
  )
}

function ProviderForm({ existing, onCancel, onSaved }: {
  existing: { id: string; status: ProviderStatus } | null
  onCancel: () => void
  onSaved: () => void
}) {
  const isEdit = existing !== null
  const [id, setId] = useState(existing?.id || '')
  const [kind, setKind] = useState<ProviderKind>(existing?.status.kind || 'anthropic')
  const [label, setLabel] = useState(existing?.status.label || '')
  const [endpoint, setEndpoint] = useState(existing?.status.endpoint || '')
  const [secret, setSecret] = useState('')
  const [defaultModel, setDefaultModel] = useState(existing?.status.default_model || '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const submit = async (validate: boolean) => {
    setBusy(true); setErr(null)
    try {
      const finalId = id || (kind.startsWith('custom-') ? `custom-${Date.now()}` : kind)
      const r = await aiConfigClient.upsertProvider({
        id: finalId,
        kind, label: label || undefined,
        endpoint: endpoint || undefined,
        secret: secret || undefined,
        default_model: defaultModel || undefined,
        validate,
      })
      if (validate && r.validated === false) {
        setErr(r.validation_error || 'validation failed — saved anyway, fix the key')
      }
      onSaved()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="border border-accent p-3 flex flex-col gap-2">
      <FormRow label="kind">
        <select value={kind} onChange={(e) => setKind(e.target.value as ProviderKind)}
          disabled={isEdit}
          className="bg-bg border border-hairline-strong text-text font-mono text-[12px] px-2 py-1 outline-none focus:border-accent">
          <option value="anthropic">Anthropic</option>
          <option value="openai">OpenAI</option>
          <option value="ollama">Ollama (local)</option>
          <option value="custom-openai">Custom — OpenAI-compatible</option>
          <option value="custom-anthropic">Custom — Anthropic-compatible</option>
        </select>
      </FormRow>

      {!isEdit && (
        <FormRow label="id">
          <input value={id} onChange={(e) => setId(e.target.value)}
            placeholder={kind.startsWith('custom-') ? 'my-provider' : kind}
            className="bg-transparent border-0 border-b border-hairline-strong text-text font-mono text-[12px] py-1 outline-none w-full focus:border-accent" />
        </FormRow>
      )}

      <FormRow label="label">
        <input value={label} onChange={(e) => setLabel(e.target.value)}
          placeholder={kind === 'anthropic' ? 'Anthropic' : 'display name'}
          className="bg-transparent border-0 border-b border-hairline-strong text-text font-mono text-[12px] py-1 outline-none w-full focus:border-accent" />
      </FormRow>

      <FormRow label="endpoint">
        <input value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
          placeholder={defaultEndpointFor(kind)}
          className="bg-transparent border-0 border-b border-hairline-strong text-text font-mono text-[12px] py-1 outline-none w-full focus:border-accent" />
      </FormRow>

      {kind !== 'ollama' && (
        <FormRow label="api key">
          <input type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)}
            placeholder={isEdit ? '(leave blank to keep current)' : 'sk-…'}
            className="bg-transparent border-0 border-b border-hairline-strong text-text font-mono text-[12px] py-1 outline-none w-full focus:border-accent" />
        </FormRow>
      )}

      <FormRow label="default model">
        <input value={defaultModel} onChange={(e) => setDefaultModel(e.target.value)}
          placeholder={kind === 'anthropic' ? 'claude-sonnet-4-6' : kind === 'openai' ? 'gpt-5' : 'optional'}
          className="bg-transparent border-0 border-b border-hairline-strong text-text font-mono text-[12px] py-1 outline-none w-full focus:border-accent" />
      </FormRow>

      {err && <div className="text-crit text-[11px]">{err}</div>}

      <div className="flex items-center justify-end gap-2 pt-2 border-t border-hairline mt-1">
        <button type="button" onClick={onCancel} disabled={busy}
          className="text-text-dim hover:text-text text-[10.5px] tracking-[0.1em] uppercase px-3 py-1">cancel</button>
        <button type="button" onClick={() => submit(false)} disabled={busy}
          className="text-text-dim hover:text-text text-[10.5px] tracking-[0.1em] uppercase border border-hairline-strong px-3 py-1">save</button>
        <button type="button" onClick={() => submit(true)} disabled={busy}
          className="bg-accent text-bg text-[10.5px] tracking-[0.1em] uppercase font-bold px-3 py-1 hover:bg-accent-hot disabled:opacity-50">
          {busy ? '…' : 'save & validate'}
        </button>
      </div>
    </div>
  )
}

function defaultEndpointFor(kind: ProviderKind): string {
  if (kind === 'anthropic') return 'https://api.anthropic.com'
  if (kind === 'openai') return 'https://api.openai.com'
  if (kind === 'ollama') return 'http://localhost:11434'
  return 'https://'
}

/* ────────────────────────────────────────────────────────────────── */
/* MCP servers                                                       */
/* ────────────────────────────────────────────────────────────────── */

function McpPanel({ cfg, onChange, disabled }: {
  cfg: AIConfig
  onChange: () => void
  disabled: boolean
}) {
  const [installing, setInstalling] = useState<McpRegistryEntry | null>(null)
  const installedIds = new Set(cfg.mcp_servers.map((s) => s.id))
  const available = cfg.mcp_registry.filter((r) => !installedIds.has(r.id))

  return (
    <div className="flex flex-col gap-3">
      <PanelHeader
        title="MCP servers"
        sub="Tools your agents can reach for. Pick from the safe-default registry, or wire any MCP server with a custom command."
      />

      {/* Installed servers */}
      {cfg.mcp_servers.length > 0 && (
        <div className="flex flex-col gap-2">
          {cfg.mcp_servers.map((s) => (
            <McpServerRow key={s.id} s={s} disabled={disabled} onChange={onChange} />
          ))}
        </div>
      )}

      {/* Registry — quick installs */}
      {available.length > 0 && (
        <div>
          <div className="text-[10.5px] tracking-[0.1em] text-text-faint uppercase mb-2">add from registry</div>
          <div className="grid grid-cols-2 gap-2">
            {available.map((r) => (
              <button
                key={r.id}
                type="button"
                onClick={() => setInstalling(r)}
                className="text-left border border-hairline-strong hover:border-accent p-2.5"
              >
                <div className="text-[12.5px] font-semibold text-text">{r.label}</div>
                <div className="text-[11px] text-text-dim mt-0.5 leading-tight">{r.summary}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {installing && (
        <McpRegistryInstallForm
          entry={installing}
          onCancel={() => setInstalling(null)}
          onSaved={() => { setInstalling(null); onChange() }}
        />
      )}

      {cfg.mcp_servers.length === 0 && !installing && (
        <div className="text-text-faint text-[11.5px] italic">No MCP servers wired. Pick one above to install.</div>
      )}
    </div>
  )
}

function McpServerRow({ s, disabled, onChange }: {
  s: McpServerStatus
  disabled: boolean
  onChange: () => void
}) {
  const remove = async () => {
    if (!confirm(`Remove MCP server "${s.label}"?`)) return
    await aiConfigClient.deleteMcp(s.id)
    onChange()
  }

  const toggleEnabled = async () => {
    await aiConfigClient.upsertMcp({
      id: s.id, label: s.label, command: s.command, args: s.args,
      env: Object.fromEntries(Object.entries(s.env).map(([k, v]) =>
        v.type === 'plain' ? [k, { type: 'plain', value: v.value } as const]
                            : [k, { type: 'secret' } as const],   // preserve existing blob
      )),
      enabled: !s.enabled,
      from_registry: s.from_registry,
    })
    onChange()
  }

  return (
    <div className="border border-hairline-strong p-3 grid grid-cols-[12px_1fr_auto] gap-3 items-center">
      <span className={`w-2 h-2 rounded-full inline-block ${s.enabled ? 'bg-ok' : 'bg-text-faint'}`} />
      <div className="flex flex-col min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-text font-semibold text-[13px]">{s.label}</span>
          {s.from_registry && <span className="text-text-faint text-[10px] tracking-[0.08em] uppercase">registry</span>}
        </div>
        <div className="text-text-faint text-[10.5px] truncate font-mono">
          {s.command} {s.args.join(' ')}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" onClick={toggleEnabled} disabled={disabled}
          className="text-text-dim hover:text-text text-[10.5px] tracking-[0.08em] uppercase border border-hairline-strong px-2 py-0.5">
          {s.enabled ? 'disable' : 'enable'}
        </button>
        <button type="button" onClick={remove} disabled={disabled}
          className="text-crit hover:bg-crit hover:text-bg text-[10.5px] tracking-[0.08em] uppercase border border-crit px-2 py-0.5">
          delete
        </button>
      </div>
    </div>
  )
}

function McpRegistryInstallForm({ entry, onCancel, onSaved }: {
  entry: McpRegistryEntry
  onCancel: () => void
  onSaved: () => void
}) {
  const envTpl = entry.env_template
  const [values, setValues] = useState<Record<string, string>>(() => {
    const out: Record<string, string> = {}
    Object.keys(envTpl).forEach((k) => { out[k] = '' })
    return out
  })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const submit = async () => {
    setBusy(true); setErr(null)
    try {
      // Substitute {{KEY}} tokens in args with plain values from the
      // form; secret values flow into env (DPAPI-encrypted server-side).
      const args = entry.args.map((a) => {
        const m = a.match(/^\{\{(\w+)\}\}$/)
        if (m && envTpl[m[1]]?.type === 'plain') {
          return values[m[1]] || ''
        }
        return a
      })
      const env: Record<string, McpEnvWriteValue> = {}
      Object.entries(envTpl).forEach(([k, t]) => {
        const v = values[k] || ''
        if (!v && t.required) throw new Error(`${t.label} is required`)
        if (v) env[k] = t.type === 'secret'
          ? ({ type: 'secret', value: v } as const)
          : ({ type: 'plain', value: v } as const)
      })
      await aiConfigClient.upsertMcp({
        id: entry.id, label: entry.label,
        command: entry.command, args, env,
        enabled: true, from_registry: true,
      })
      onSaved()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="border border-accent p-3 flex flex-col gap-2">
      <div className="text-[12.5px] font-semibold text-text">{entry.label}</div>
      <div className="text-[11px] text-text-dim">{entry.summary}</div>

      {Object.entries(envTpl).map(([k, t]) => (
        <FormRow key={k} label={t.label.toLowerCase()}>
          <input
            type={t.type === 'secret' ? 'password' : 'text'}
            autoComplete="off"
            value={values[k] || ''}
            onChange={(e) => setValues({ ...values, [k]: e.target.value })}
            placeholder={t.placeholder}
            className="bg-transparent border-0 border-b border-hairline-strong text-text font-mono text-[12px] py-1 outline-none w-full focus:border-accent" />
        </FormRow>
      ))}

      {err && <div className="text-crit text-[11px]">{err}</div>}

      <div className="flex items-center justify-end gap-2 pt-2 border-t border-hairline mt-1">
        <button type="button" onClick={onCancel} disabled={busy}
          className="text-text-dim hover:text-text text-[10.5px] tracking-[0.1em] uppercase px-3 py-1">cancel</button>
        <button type="button" onClick={submit} disabled={busy}
          className="bg-accent text-bg text-[10.5px] tracking-[0.1em] uppercase font-bold px-3 py-1 hover:bg-accent-hot disabled:opacity-50">
          {busy ? '…' : 'install'}
        </button>
      </div>
    </div>
  )
}

/* ────────────────────────────────────────────────────────────────── */
/* Agent routing                                                     */
/* ────────────────────────────────────────────────────────────────── */

function AgentRoutingPanel({ cfg, onChange, disabled }: {
  cfg: AIConfig
  onChange: () => void
  disabled: boolean
}) {
  // Editable copy of the routes, flushed on Save.
  const [draft, setDraft] = useState<Record<string, AgentRoute>>(cfg.agent_routes)
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => { setDraft(cfg.agent_routes); setDirty(false) }, [cfg.agent_routes])

  const providerIds = useMemo(() => Object.keys(cfg.providers), [cfg.providers])
  const providerLabels = useMemo(() => Object.fromEntries(
    Object.entries(cfg.providers).map(([id, p]) => [id, p.label]),
  ), [cfg.providers])

  const setRoute = (slug: string, patch: Partial<AgentRoute>) => {
    const cur = draft[slug] || { provider: providerIds[0] || '', model: '' }
    const next = { ...cur, ...patch }
    if (!next.provider || !next.model) {
      const { [slug]: _, ...rest } = draft
      setDraft(rest)
    } else {
      setDraft({ ...draft, [slug]: next })
    }
    setDirty(true)
  }

  const clearRoute = (slug: string) => {
    const { [slug]: _, ...rest } = draft
    setDraft(rest)
    setDirty(true)
  }

  const save = async () => {
    setBusy(true); setErr(null)
    try {
      await aiConfigClient.setRoutes(draft)
      onChange()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (providerIds.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <PanelHeader title="Agent routing" sub="Per-agent provider + model overrides." />
        <div className="text-text-faint text-[11.5px] italic">Add at least one provider above to start routing agents.</div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <PanelHeader
        title="Agent routing"
        sub="Pick a provider + model per agent. Anything left blank falls back to the default route, then to the first configured provider."
        action={dirty && (
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => { setDraft(cfg.agent_routes); setDirty(false) }}
              className="text-text-dim hover:text-text text-[10.5px] tracking-[0.1em] uppercase px-3 py-1">revert</button>
            <button type="button" onClick={save} disabled={busy || disabled}
              className="bg-accent text-bg text-[10.5px] tracking-[0.1em] uppercase font-bold px-3 py-1 hover:bg-accent-hot disabled:opacity-50">
              {busy ? '…' : 'save routes'}
            </button>
          </div>
        )}
      />

      <div className="border border-hairline-strong">
        <div className="grid grid-cols-[1fr_180px_220px_60px] gap-2 px-3 py-2 border-b border-hairline-strong text-[10px] tracking-[0.1em] text-text-faint uppercase">
          <div>agent</div><div>provider</div><div>model</div><div></div>
        </div>
        {cfg.canonical_agents.map((a) => (
          <AgentRoutingRow
            key={a.slug}
            a={a}
            route={draft[a.slug]}
            providerIds={providerIds}
            providerLabels={providerLabels}
            supportedModels={cfg.supported_models.map((m) => m.id)}
            onSet={(patch) => setRoute(a.slug, patch)}
            onClear={() => clearRoute(a.slug)}
          />
        ))}
      </div>

      {err && <div className="text-crit text-[11.5px]">{err}</div>}
    </div>
  )
}

function AgentRoutingRow({ a, route, providerIds, providerLabels, supportedModels, onSet, onClear }: {
  a: CanonicalAgent
  route: AgentRoute | undefined
  providerIds: string[]
  providerLabels: Record<string, string>
  supportedModels: string[]
  onSet: (patch: Partial<AgentRoute>) => void
  onClear: () => void
}) {
  const isSystem = a.kind === 'system'
  return (
    <div className={`grid grid-cols-[1fr_180px_220px_60px] gap-2 px-3 py-1.5 border-b border-hairline last:border-b-0 items-center ${isSystem ? 'bg-bg-elev' : ''}`}>
      <div>
        <span className="text-text text-[12.5px]">{a.label}</span>
        {isSystem && <span className="text-text-faint text-[10px] ml-2 uppercase tracking-[0.08em]">system</span>}
      </div>
      <select
        value={route?.provider || ''}
        onChange={(e) => onSet({ provider: e.target.value })}
        className="bg-bg border border-hairline-strong text-text font-mono text-[11.5px] px-2 py-0.5 outline-none focus:border-accent"
      >
        <option value="">— inherit —</option>
        {providerIds.map((id) => (
          <option key={id} value={id}>{providerLabels[id] || id}</option>
        ))}
      </select>
      <input
        type="text"
        list={`models-${a.slug}`}
        value={route?.model || ''}
        onChange={(e) => onSet({ model: e.target.value })}
        placeholder="claude-sonnet-4-6 / gpt-5 / llama3 …"
        className="bg-bg border border-hairline-strong text-text font-mono text-[11.5px] px-2 py-0.5 outline-none focus:border-accent w-full"
      />
      <datalist id={`models-${a.slug}`}>
        {supportedModels.map((m) => <option key={m} value={m} />)}
      </datalist>
      <button type="button" onClick={onClear}
        className="text-text-faint hover:text-crit text-[10px] tracking-[0.1em] uppercase">
        clear
      </button>
    </div>
  )
}

/* ────────────────────────────────────────────────────────────────── */
/* Helpers                                                           */
/* ────────────────────────────────────────────────────────────────── */

function PanelHeader({ title, sub, action }: { title: string; sub: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-end justify-between gap-3 border-b border-hairline pb-2">
      <div>
        <div className="text-text font-semibold text-[14px] tracking-[0.02em]">{title}</div>
        <div className="text-text-faint text-[11px] mt-0.5 leading-tight">{sub}</div>
      </div>
      {action}
    </div>
  )
}

function FormRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3 items-center">
      <div className="text-[10.5px] tracking-[0.1em] text-text-faint uppercase">{label}</div>
      <div>{children}</div>
    </div>
  )
}

function timeAgo(iso: string): string {
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return iso
  const s = Math.round((Date.now() - t) / 1000)
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}
