import { useMemo, useState } from 'react'
import { ContextStrip } from '@/kit/ContextStrip'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Database, Search, RefreshCw, Download, ExternalLink, Zap,
  AlertCircle, CheckCircle2, Globe, FileDigit, AtSign, Link as LinkIcon,
  Binary, Hash, Info, X, Copy, CheckCheck, Loader2,
} from 'lucide-react'
import { api, type TipIoc, type TipEnrichment, type TipEnricherStatus } from '@/api/client'
import { cn } from '@/lib/cn'
import { formatDistanceToNowStrict, parseISO } from 'date-fns'

/**
 * Threat Intelligence, the local TIP.
 *
 * Aggregates every IOC observed across triages into a
 * single searchable catalog. Click any IOC to see where it was seen +
 * run external enrichment (VirusTotal / URLhaus / ThreatFox /
 * AbuseIPDB). Export the whole corpus as a MISP Event JSON document.
 *
 * No database, the catalog is rebuilt on each request by walking
 * triages/ on disk. Enrichment results are disk-cached
 * for 24h.
 */
export function ThreatIntelView() {
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string | null>(null)
  const [selected, setSelected] = useState<{ type: string; value: string } | null>(null)

  const catalogQ = useQuery({
    queryKey: ['tip', 'iocs', typeFilter, query],
    queryFn: () => api.tipListIocs({
      q: query || undefined,
      ioc_type: typeFilter || undefined,
      limit: 1000,
    }),
    refetchInterval: 30_000,
  })

  const enrichersQ = useQuery({
    queryKey: ['tip', 'enrichers'],
    queryFn: () => api.tipEnrichers(),
  })

  const iocs = catalogQ.data?.iocs || []
  const summary = catalogQ.data?.summary
  const enrichers = enrichersQ.data?.enrichers || []

  function downloadMispExport() {
    // Opens a new tab. FastAPI returns JSON inline. The user can
    // save-as from there. (Simpler than blob-ing on the client.)
    window.open('/api/tip/misp-export', '_blank')
  }

  return (
    <div className="h-full flex flex-col">
      <ContextStrip
        title="THREAT INTEL"
        subtitle={summary ? `${summary.total_iocs} IOCs · ${summary.total_observations} observations` : undefined}
        actions={[
          { label: 'MISP EXPORT', onClick: downloadMispExport },
          { label: catalogQ.isFetching ? 'REBUILDING…' : 'REBUILD', onClick: () => catalogQ.refetch() },
        ]}
      />
      <div className="px-4 py-2 border-b border-hairline flex items-center gap-2 bg-bg flex-shrink-0">
        <EnricherStatusBar enrichers={enrichers} />
      </div>

      {/* Filter row */}
      <div className="px-6 py-3 border-b border-border flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-faint pointer-events-none" />
          <input
            className="input pl-7 !py-1 text-sm"
            placeholder="Search IOC value or substring…"
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
        </div>
        <TypeFilterChips
          summary={summary}
          active={typeFilter}
          onChange={setTypeFilter}
        />
      </div>

      <div className="flex-1 flex overflow-hidden min-h-0">
        <section className="flex-1 overflow-y-auto min-w-0">
          {catalogQ.isLoading ? (
            <div className="p-8 text-center text-sm text-ink-faint">Scanning triages…</div>
          ) : iocs.length === 0 ? (
            <EmptyState />
          ) : (
            <IocTable
              iocs={iocs}
              onSelect={(ioc) => setSelected({ type: ioc.type, value: ioc.value })}
              selected={selected}
            />
          )}
        </section>

        {selected && (
          <IocDetailDrawer
            iocType={selected.type}
            iocValue={selected.value}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}

// ── Type filter ──────────────────────────────────────────────────────

function TypeFilterChips({
  summary, active, onChange,
}: {
  summary: { by_type: Record<string, number> } | undefined
  active: string | null
  onChange: (t: string | null) => void
}) {
  if (!summary?.by_type || Object.keys(summary.by_type).length === 0) return null
  const types = Object.entries(summary.by_type).sort((a, b) => b[1] - a[1])

  return (
    <div className="flex items-center gap-1 flex-wrap">
      <span className="text-2xs uppercase tracking-[0.1em] text-ink-faint mr-1">Type:</span>
      <button
        onClick={() => onChange(null)}
        className={cn(
          'px-1.5 py-0.5 rounded text-2xs font-mono uppercase tracking-wider border transition-colors',
          active === null
            ? 'bg-accent/15 text-accent border-accent/40'
            : 'text-ink-faint border-border hover:text-ink hover:border-border-strong',
        )}
      >
        all
      </button>
      {types.map(([t, count]) => (
        <button
          key={t}
          onClick={() => onChange(active === t ? null : t)}
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-2xs font-mono uppercase tracking-wider border transition-colors',
            active === t
              ? 'bg-accent/15 text-accent border-accent/40'
              : 'text-ink-faint border-border hover:text-ink hover:border-border-strong',
          )}
        >
          {t}
          <span className="tnum opacity-70">{count}</span>
        </button>
      ))}
    </div>
  )
}

// ── Enricher status bar ──────────────────────────────────────────────

function EnricherStatusBar({ enrichers }: { enrichers: TipEnricherStatus[] }) {
  if (enrichers.length === 0) return null
  const active = enrichers.filter(e => e.configured).length
  return (
    <div
      className="flex items-center gap-1.5 px-2 py-1 rounded border border-border bg-surface/60 text-2xs"
      title={enrichers.map(e => `${e.name}: ${e.configured ? 'ok' : 'not configured (' + e.env_var + ')'}`).join('\n')}
    >
      <Info className="w-3 h-3 text-ink-faint" />
      <span className="text-ink-dim">{active}/{enrichers.length} enrichers</span>
    </div>
  )
}

// ── Table ────────────────────────────────────────────────────────────

function IocTable({
  iocs, onSelect, selected,
}: {
  iocs: TipIoc[]
  onSelect: (ioc: TipIoc) => void
  selected: { type: string; value: string } | null
}) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th className="w-[90px]">Type</th>
          <th>Value</th>
          <th className="w-[90px]">Obs</th>
          <th className="w-[150px]">First seen</th>
          <th className="w-[150px]">Last seen</th>
          <th className="w-[140px]">Disposition</th>
        </tr>
      </thead>
      <tbody>
        {iocs.map(ioc => {
          const isSel = selected?.type === ioc.type && selected?.value === ioc.value
          return (
            <tr
              key={`${ioc.type}:${ioc.normalized_value}`}
              className={cn('clickable', isSel && 'selected')}
              onClick={() => onSelect(ioc)}
            >
              <td>
                <span className="inline-flex items-center gap-1.5">
                  <IocTypeIcon type={ioc.type} />
                  <span className="text-2xs font-mono uppercase tracking-wider text-ink-dim">{ioc.type}</span>
                </span>
              </td>
              <td>
                <span className="font-mono text-sm text-ink break-all">{ioc.value}</span>
              </td>
              <td>
                <span className="chip !text-2xs">{ioc.observation_count}×</span>
              </td>
              <td className="text-xs text-ink-dim">
                {ioc.first_seen ? formatDistanceToNowStrict(parseISO(ioc.first_seen), { addSuffix: true }) : ', '}
              </td>
              <td className="text-xs text-ink-dim">
                {ioc.last_seen ? formatDistanceToNowStrict(parseISO(ioc.last_seen), { addSuffix: true }) : ', '}
              </td>
              <td>
                <div className="flex items-center gap-1 flex-wrap">
                  {ioc.dispositions.slice(0, 3).map(d => (
                    <span
                      key={d}
                      className={cn('chip !text-2xs',
                        d === 'c2' || d === 'attacker' ? 'chip-danger' :
                        d === 'delivery' || d === 'payload' ? 'chip-warning' : '',
                      )}
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function IocTypeIcon({ type }: { type: string }) {
  const cls = 'w-3 h-3 text-ink-faint flex-shrink-0'
  if (type === 'ipv4' || type === 'ipv6') return <Globe className={cls} />
  if (type === 'domain') return <Globe className={cls} />
  if (type === 'url') return <LinkIcon className={cls} />
  if (type === 'email') return <AtSign className={cls} />
  if (type === 'sha256' || type === 'sha1' || type === 'md5') return <Hash className={cls} />
  if (type === 'filename') return <FileDigit className={cls} />
  return <Binary className={cls} />
}

// ── Empty state ──────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="h-full flex items-center justify-center">
      <div className="text-center max-w-lg px-6">
        <Database className="w-6 h-6 text-accent mx-auto mb-3" />
        <h2 className="section-title mb-2">No IOCs yet</h2>
        <p className="text-sm text-ink-dim">
          Once the threat-triage agent pulls IOCs from a URL, file or threat
          name, they roll up here, searchable,
          enrichable, exportable to MISP. Nothing to do until then.
        </p>
      </div>
    </div>
  )
}

// ── Detail drawer ────────────────────────────────────────────────────

function IocDetailDrawer({
  iocType, iocValue, onClose,
}: {
  iocType: string
  iocValue: string
  onClose: () => void
}) {
  const qc = useQueryClient()

  const detailQ = useQuery({
    queryKey: ['tip', 'ioc', iocType, iocValue],
    queryFn: () => api.tipGetIoc(iocType, iocValue),
  })

  const enrichM = useMutation({
    mutationFn: (force: boolean) => api.tipEnrichIoc(iocType, iocValue, force),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tip', 'ioc', iocType, iocValue] }),
  })

  const ioc = detailQ.data?.ioc
  const enrichment = enrichM.data || detailQ.data?.enrichment

  const [copied, setCopied] = useState(false)
  function copyValue() {
    navigator.clipboard.writeText(iocValue).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <aside className="w-[480px] flex-shrink-0 border-l border-border bg-surface overflow-y-auto">
      <header className="sticky top-0 z-10 bg-surface border-b border-border px-4 py-3 flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <IocTypeIcon type={iocType} />
            <span className="text-2xs font-mono uppercase tracking-wider text-ink-faint">{iocType}</span>
            <button
              onClick={copyValue}
              className="btn btn-ghost btn-xs !p-0.5 ml-auto"
              title="Copy value"
            >
              {copied ? <CheckCheck className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
          <div className="font-mono text-sm text-ink break-all leading-snug">{iocValue}</div>
        </div>
        <button onClick={onClose} className="btn btn-ghost !p-1" title="Close">
          <X className="w-3.5 h-3.5" />
        </button>
      </header>

      {detailQ.isLoading ? (
        <div className="p-6 text-xs text-ink-faint">loading…</div>
      ) : !ioc ? (
        <div className="p-6 text-xs text-danger">IOC not found in catalog (it may have been deleted).</div>
      ) : (
        <div className="p-4 space-y-5">
          {/* Observations */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-faint mb-2">
              Observed in ({ioc.observation_count})
            </h3>
            <ul className="space-y-1.5">
              {ioc.observations.map((obs, i) => (
                <li key={i} className="border border-border rounded p-2 bg-bg/40">
                  <div className="flex items-center gap-2 text-2xs text-ink-faint mb-0.5">
                    <span className={cn('chip !text-2xs !py-0 !px-1',
                      'chip-info',
                    )}>
                      {obs.source}
                    </span>
                    <code className="font-mono truncate text-ink-dim">{obs.id}</code>
                    {obs.seen_at && (
                      <span className="ml-auto">{formatDistanceToNowStrict(parseISO(obs.seen_at), { addSuffix: true })}</span>
                    )}
                  </div>
                  <div className="text-sm text-ink leading-snug">{obs.summary}</div>
                  {obs.disposition && (
                    <div className="mt-1 text-2xs">
                      <span className="text-ink-faint">disposition: </span>
                      <span className={cn(
                        obs.disposition === 'c2' || obs.disposition === 'attacker' ? 'text-danger' :
                        obs.disposition === 'delivery' || obs.disposition === 'payload' ? 'text-warning' :
                        'text-ink-dim',
                      )}>{obs.disposition}</span>
                    </div>
                  )}
                  {obs.notes && (
                    <div className="mt-1 text-2xs text-ink-dim italic">"{obs.notes}"</div>
                  )}
                </li>
              ))}
            </ul>
          </section>

          {/* Enrichment */}
          <section>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-faint">
                External enrichment
              </h3>
              <div className="flex items-center gap-1">
                <button
                  className="btn btn-primary btn-xs"
                  disabled={enrichM.isPending}
                  onClick={() => enrichM.mutate(false)}
                >
                  {enrichM.isPending ? (
                    <><Loader2 className="w-2.5 h-2.5 animate-spin" /> running…</>
                  ) : enrichment ? (
                    <><Zap className="w-2.5 h-2.5" /> refresh</>
                  ) : (
                    <><Zap className="w-2.5 h-2.5" /> run enrichment</>
                  )}
                </button>
                {enrichment && (
                  <button
                    className="btn btn-ghost btn-xs"
                    disabled={enrichM.isPending}
                    onClick={() => enrichM.mutate(true)}
                    title="Force-refresh, bypassing cache"
                  >
                    force
                  </button>
                )}
              </div>
            </div>

            {enrichment ? (
              <EnrichmentPanels enrichment={enrichment} />
            ) : (
              <div className="text-xs text-ink-faint border border-dashed border-border rounded p-4 text-center">
                No cached enrichment, click "Run enrichment" to hit external sources.
              </div>
            )}
          </section>
        </div>
      )}
    </aside>
  )
}

// ── Enrichment rendering ─────────────────────────────────────────────

function EnrichmentPanels({ enrichment }: { enrichment: TipEnrichment }) {
  // Panel order = "free sources first, premium with key last". Each
  // adapter's data is stashed under a key matching its Python name.
  const panelDefs: Array<[string, string]> = [
    ['URLhaus',            'urlhaus'],
    ['ThreatFox',          'threatfox'],
    ['MalwareBazaar',      'malwarebazaar'],
    ['Feodo Tracker',      'feodotracker'],
    ['Shodan InternetDB',  'shodan_internetdb'],
    ['CIRCL Hash Lookup',  'circl_hashlookup'],
    ['VirusTotal',         'virustotal'],
    ['AbuseIPDB',          'abuseipdb'],
  ]
  const panels = panelDefs
    .map(([name, key]) => ({ name, data: enrichment[key] as Record<string, unknown> | undefined }))
    .filter(p => p.data)

  return (
    <div className="space-y-3">
      {enrichment.from_cache && (
        <div className="text-2xs text-ink-faint flex items-center gap-1">
          <Info className="w-2.5 h-2.5" />
          cached {formatDistanceToNowStrict(new Date(enrichment.cached_at * 1000), { addSuffix: true })}
          {enrichment.enrichers_skipped.length > 0 && (
            <span className="ml-2">· skipped: {enrichment.enrichers_skipped.join(', ')}</span>
          )}
        </div>
      )}
      {panels.length === 0 && (
        <div className="text-xs text-ink-faint border border-dashed border-border rounded p-4 text-center">
          No enricher data, check enricher config (top-right badge).
        </div>
      )}
      {panels.map(p => <EnrichmentCard key={p.name} name={p.name} data={p.data!} />)}
    </div>
  )
}

function EnrichmentCard({ name, data }: { name: string; data: Record<string, unknown> }) {
  const error = (data.error as string | undefined) || null
  const found = (data.found as boolean | undefined)
  return (
    <div className="border border-border rounded bg-bg/40">
      <header className="px-3 py-1.5 flex items-center gap-2 border-b border-border">
        <span className="text-xs font-semibold text-ink">{name}</span>
        {error ? (
          <span className="chip chip-danger !text-2xs"><AlertCircle className="w-2.5 h-2.5" /> error</span>
        ) : found === false ? (
          <span className="chip !text-2xs">no hit</span>
        ) : (
          <span className="chip chip-success !text-2xs"><CheckCircle2 className="w-2.5 h-2.5" /> hit</span>
        )}
        {typeof data.link === 'string' && (
          <a
            href={data.link as string}
            target="_blank" rel="noopener noreferrer"
            className="ml-auto text-accent hover:text-accent-hot"
            title="Open in source"
          >
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </header>
      <div className="p-3">
        {error ? (
          <div className="text-xs text-danger font-mono break-all">{error}</div>
        ) : found === false ? (
          <div className="text-xs text-ink-faint">Not found in {name}.</div>
        ) : (
          <EnrichmentKvGrid data={data} />
        )}
      </div>
    </div>
  )
}

function EnrichmentKvGrid({ data }: { data: Record<string, unknown> }) {
  const SKIP = new Set(['found', 'link', 'error'])
  const entries = Object.entries(data).filter(([k, v]) =>
    !SKIP.has(k) && v !== null && v !== undefined && v !== '',
  )
  if (entries.length === 0) return <div className="text-xs text-ink-faint">(no fields)</div>
  return (
    <dl className="text-xs grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
      {entries.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-ink-faint tnum">{k}</dt>
          <dd className="text-ink break-all font-mono">{formatValue(v)}</dd>
        </Fragment>
      ))}
    </dl>
  )
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return ', '
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  if (Array.isArray(v)) return v.length === 0 ? '[]' : v.map(String).join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

// Minimal Fragment import
function Fragment({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
