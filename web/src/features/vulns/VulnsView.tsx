// Vulnerabilities tab.
//
// Three questions, in this order:
//   1. Which actively exploited vulnerabilities are still open somewhere in
//      our estate, on what, owned by whom? (org inventory: tech-stack CSV,
//      inventory JSON or THREATDESK_TECH_STACK; see Settings -> Inventory)
//   2. What is new and loud right now? (KEV additions, exploitation news)
//   3. Anything else: search by technology, CVE id or ATT&CK technique.
// Every card opens a drawer with what to do, where we run it, the scores,
// news coverage and the remediation record (local now; ServiceNow later).

import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, Boxes, CalendarX, Crown, ExternalLink, Flame, Globe, Newspaper, Radio, Search, ShieldCheck, Skull, Wrench,
} from 'lucide-react'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/cn'

type Scope = 'org' | 'hot' | 'all'

export interface Asset {
  id: string; category: string; subcategory: string; vendor: string; product: string; version: string
  environment: string; count: number | null; owner: string; criticality: string; internet_facing: boolean
  patched_through?: string | null
}

export interface Exposure {
  label: string
  assets: Asset[]
  products: number
  asset_count: number | null
  crown_jewel: boolean
  internet_facing: boolean
  owners: string[]
  covered: boolean
}

export interface VulnCard {
  cve: string
  title: string
  vendor: string
  product: string
  summary: string
  kev: boolean
  date_added: string | null
  due_date: string | null
  published?: string | null
  ransomware: boolean
  org_match: string | null
  exposure?: Exposure | null
  news_mentions: number
  tracking: string | null
  epss?: { score: number; percentile: number } | null
  cvss?: { score: number; severity: string } | null
}

interface SearchResult {
  mode: string
  query: string
  scope: Scope
  note: string
  total: number
  items: VulnCard[]
  stack: string[]
  inventory?: { products: number; exposed: number; categories: Array<{ name: string; products: number; exposed: number }> }
  counts: {
    kev_total: number; org_affected: number; org_open: number; hot: number; ransomware: number
    covered_by_version?: number; crown_jewel?: number; internet_facing?: number; overdue?: number
  }
}

interface Detail {
  cve: string
  title: string
  kev: null | { vendor: string; product: string; date_added: string; due_date: string; required_action: string;
                description: string; ransomware: boolean; notes: string; cwes: string[] }
  nvd: null | { description: string; published: string; cvss: null | { score: number; severity: string; vector: string; version: string };
                cwes: string[]; products: string[]; references: string[] }
  epss: null | { score: number; percentile: number }
  org_match: string | null
  exposure?: Exposure | null
  news: Array<{ title: string; url: string; source: string; published: string }>
  tracking: null | Tracking
  links: { nvd: string; kev: string | null; mitre: string }
}

interface Tracking {
  status: string; owner: string; ticket: string; updated_at: string; provider: string
  history: Array<{ at: string; by: string; status: string; note: string }>
}

export interface NewsItem {
  title: string; link: string; source: string; published: string; ts: number; summary: string
  cves: Array<{ cve: string; kev: boolean; in_stack: boolean; open: boolean; product: string | null }>
  exploited: boolean; kev_addition?: boolean; in_stack: boolean; open_in_stack: boolean; mentions: string[]
}

export const TRACK: Record<string, { label: string; tone: string; done: boolean }> = {
  not_started:   { label: 'Not started', tone: 'chip-danger', done: false },
  investigating: { label: 'Investigating', tone: 'chip-warning', done: false },
  in_progress:   { label: 'Patching', tone: 'chip-warning', done: false },
  mitigated:     { label: 'Mitigated', tone: 'chip-info', done: true },
  patched:       { label: 'Patched', tone: 'chip-success', done: true },
  not_affected:  { label: 'Not affected', tone: 'chip-success', done: true },
  risk_accepted: { label: 'Risk accepted', tone: 'chip-info', done: true },
}

const CRIT_LABEL: Record<string, string> = { crown_jewel: 'Crown jewel', high: 'High', medium: 'Medium', low: 'Low' }

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url)
  if (!r.ok) {
    let msg = `${r.status}`
    try { msg = (await r.json()).detail || msg } catch { /* not json */ }
    throw new Error(msg)
  }
  return r.json()
}

function fmtCount(n: number | null | undefined): string {
  if (n == null) return ''
  return n >= 10000 ? `${Math.round(n / 1000)}k` : n.toLocaleString()
}

export function VulnsView() {
  const [scope, setScope] = useState<Scope>('org')
  const [input, setInput] = useState('')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const [invOpen, setInvOpen] = useState(false)

  useEffect(() => {
    const id = window.setTimeout(() => setQ(input.trim()), 350)
    return () => window.clearTimeout(id)
  }, [input])

  const res = useQuery({
    queryKey: ['vulns', q, scope],
    queryFn: () => getJson<SearchResult>(`/api/vulns?${new URLSearchParams({ q, scope, limit: '90' })}`),
    staleTime: 60_000,
    placeholderData: prev => prev,
  })
  const d = res.data
  const inv = d?.inventory
  const noStack = !!d && !inv?.products && d.stack.length === 0
  const c = d?.counts

  return (
    <div className="mx-auto w-full max-w-[1500px] px-4 py-6 font-sans sm:px-6" data-testid="vulns-view">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-semibold text-ink">Vulnerabilities</h1>
          <p className="mt-0.5 text-sm text-ink-dim">Actively exploited vulnerabilities, matched to the technology you run.</p>
        </div>
        {inv && inv.products > 0 && (
          <button className="btn btn-sm" onClick={() => setInvOpen(true)}>
            <Boxes className="h-3.5 w-3.5" /> Inventory: {inv.products} products
          </button>
        )}
      </div>

      {c && (
        <div className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-3 xl:grid-cols-6">
          <Stat icon={Wrench} label="Open in your estate" value={noStack ? '—' : c.org_open}
                tone={c.org_open ? 'text-danger' : 'text-success'}
                sub={noStack ? undefined : `${c.org_affected.toLocaleString()} matched · ${(c.covered_by_version || 0).toLocaleString()} fixed by deployed versions`}
                bar={noStack || !c.org_affected ? undefined : [c.org_affected - c.org_open, c.org_affected]} />
          <Stat icon={Crown} label="On crown-jewel systems" value={noStack ? '—' : c.crown_jewel ?? 0} tone={c.crown_jewel ? 'text-danger' : undefined} />
          <Stat icon={Globe} label="Internet-facing" value={noStack ? '—' : c.internet_facing ?? 0} tone={c.internet_facing ? 'text-warning' : undefined} />
          <Stat icon={CalendarX} label="Past CISA fix-by date" value={noStack ? '—' : c.overdue ?? 0} tone={c.overdue ? 'text-warning' : undefined} />
          <Stat icon={Skull} label="Ransomware-linked, open" value={noStack ? '—' : c.ransomware} tone={c.ransomware ? 'text-danger' : undefined} />
          <Stat icon={Flame} label="Added to KEV, last 14 days" value={c.hot} sub={`${c.kev_total.toLocaleString()} known exploited in total`} />
        </div>
      )}

      {d && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
          {noStack ? (
            <span className="text-warning">No inventory. Upload a tech-stack CSV in <a href="/settings" className="underline">Settings → Inventory</a>, or set <code className="rounded bg-surface2 px-1">THREATDESK_INVENTORY</code> / <code className="rounded bg-surface2 px-1">THREATDESK_TECH_STACK</code> in .env.</span>
          ) : inv ? (
            <>
              <span className="mr-1 text-ink-faint">{inv.exposed} of {inv.products} products have known-exploited history:</span>
              {inv.categories.filter(x => x.exposed).slice(0, 14).map(x => (
                <span key={x.name} className="chip !text-[10.5px]" title={`${x.exposed} of ${x.products} ${x.name} products`}>
                  {x.name} <span className="ml-1 text-ink-faint">{x.exposed}/{x.products}</span>
                </span>
              ))}
            </>
          ) : null}
        </div>
      )}

      <div className="mt-5 grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0">
          <div className="flex flex-col gap-3 md:flex-row md:items-center">
            <label className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
              <input
                className="input w-full !py-2.5 !pl-9 !text-[15px]"
                placeholder="Search a technology, CVE or ATT&CK technique: Fortinet, CVE-2024-3400, T1190"
                value={input}
                onChange={e => setInput(e.target.value)}
                aria-label="Search vulnerabilities"
              />
            </label>
            <div className="flex overflow-hidden rounded-md border border-border text-sm" role="tablist">
              {([['org', 'Open in your estate'], ['hot', 'Hot now'], ['all', 'All known exploited']] as const).map(([k, label]) => (
                <button key={k} role="tab" aria-selected={scope === k} onClick={() => setScope(k)}
                        className={cn('whitespace-nowrap px-3.5 py-2', scope === k ? 'bg-accent/15 font-semibold text-accent' : 'text-ink-dim hover:text-ink')}>
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-3 min-h-[20px] text-xs text-ink-faint">
            {res.isFetching ? 'Searching…'
              : d ? <>{d.total.toLocaleString()} result{d.total === 1 ? '' : 's'}{d.total > d.items.length ? `, showing ${d.items.length}` : ''}
                  {scope === 'org' && !q && ' · sorted by crown-jewel and internet-facing exposure, then newest'}{d.note && <> · {d.note}</>}</>
              : null}
          </div>

          {res.isError && (
            <div className="mt-2 rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
              Could not load the vulnerability catalog: {(res.error as Error).message}
            </div>
          )}

          {d && d.items.length === 0 && !res.isFetching && (
            <div className="mt-2 rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-ink-faint">
              {scope === 'org' && noStack ? 'Set your inventory in .env to see what affects you.'
                : scope === 'org' ? 'Nothing open in your estate for this search.'
                : 'No matches.'}
            </div>
          )}

          <div className="mt-2 grid gap-3 sm:grid-cols-2 2xl:grid-cols-3">
            {d?.items.map(card => <Card key={card.cve} c={card} onOpen={() => setOpen(card.cve)} />)}
          </div>
        </div>

        <NewsRail onOpenCve={setOpen} />
      </div>

      <Dialog open={!!open} onOpenChange={o => !o && setOpen(null)}>
        <DialogContent size="drawer" className="overflow-y-auto font-sans" aria-describedby={undefined}>
          {open && <DetailPanel cve={open} />}
        </DialogContent>
      </Dialog>

      <Dialog open={invOpen} onOpenChange={setInvOpen}>
        <DialogContent size="drawer" className="overflow-y-auto font-sans" aria-describedby={undefined}>
          {invOpen && <InventoryPanel onSearch={t => { setInput(t); setScope('all'); setInvOpen(false) }} />}
        </DialogContent>
      </Dialog>
    </div>
  )
}

function Stat({ icon: Icon, label, value, sub, tone, bar }: {
  icon: typeof Flame; label: string; value: number | string; sub?: string; tone?: string; bar?: [number, number]
}) {
  return (
    <div className="bg-surface px-4 py-3.5">
      <div className="flex items-center gap-1.5 text-xs text-ink-dim"><Icon className="h-3.5 w-3.5" /> {label}</div>
      <div className={cn('mt-1 font-mono text-2xl font-bold', tone || 'text-ink')}>{typeof value === 'number' ? value.toLocaleString() : value}</div>
      {bar && bar[1] > 0 && (
        <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface3" title={`${bar[0]} of ${bar[1]} remediated or fixed by version`}>
          <div className="h-full bg-success" style={{ width: `${(bar[0] / bar[1]) * 100}%` }} />
        </div>
      )}
      {sub && <div className="mt-1 text-[11px] leading-snug text-ink-faint">{sub}</div>}
    </div>
  )
}

function daysUntil(d: string | null): number | null {
  if (!d) return null
  const t = Date.parse(d + 'T00:00:00Z')
  return Number.isNaN(t) ? null : Math.ceil((t - Date.now()) / 86400000)
}

function ago(ts: number | string | null | undefined): string {
  const t = typeof ts === 'number' ? ts * 1000 : ts ? Date.parse(ts) : NaN
  if (!t || Number.isNaN(t)) return ''
  const m = Math.round((Date.now() - t) / 60000)
  if (m < 60) return `${Math.max(1, m)} min ago`
  if (m < 48 * 60) return `${Math.round(m / 60)} h ago`
  return `${Math.round(m / 1440)} d ago`
}

export function Card({ c, onOpen }: { c: VulnCard; onOpen: () => void }) {
  const tr = c.tracking ? TRACK[c.tracking] : null
  const e = c.exposure
  const covered = !!e?.covered
  const open = !!c.org_match && !covered && !tr?.done
  const due = daysUntil(c.due_date)
  const recent = c.date_added && (Date.now() - Date.parse(c.date_added)) < 14 * 86400000
  return (
    <button onClick={onOpen} data-testid="vuln-card"
            className={cn('card flex flex-col gap-2 p-4 text-left transition hover:border-accent/60',
              open && (e?.crown_jewel ? 'border-danger/50' : 'border-warning/40'))}>
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs font-semibold text-accent">{c.cve}</span>
        {recent && <span className="chip chip-danger !text-[10px]">New</span>}
        <span className="flex-1" />
        {tr ? <span className={cn('chip !text-[10px]', tr.tone)}>{tr.label}</span>
          : covered ? <span className="chip chip-success !text-[10px]">Fixed in deployed version</span>
          : c.org_match ? <span className="chip chip-danger !text-[10px]">Not started</span> : null}
      </div>
      <div className="line-clamp-2 text-[15px] font-medium leading-snug text-ink">{c.title}</div>
      {e ? (
        <div className="rounded border border-border bg-bg/40 px-2.5 py-1.5 text-xs">
          <div className="truncate text-ink" title={e.label}>{e.label}</div>
          <div className="mt-0.5 truncate text-ink-faint">
            {e.asset_count ? `${fmtCount(e.asset_count)} assets` : ''}
            {e.products > 1 ? ` · ${e.products} products` : ''}
            {e.owners.length ? ` · ${e.owners[0]}${e.owners.length > 1 ? ` +${e.owners.length - 1}` : ''}` : ''}
          </div>
        </div>
      ) : (
        <div className="truncate text-xs text-ink-dim">{[c.vendor, c.product].filter(Boolean).join(' · ')}</div>
      )}
      <div className="mt-auto flex flex-wrap items-center gap-1.5 pt-1">
        {open && e?.crown_jewel && <span className="chip chip-danger !text-[10px]">Crown jewel</span>}
        {open && e?.internet_facing && <span className="chip chip-warning !text-[10px]">Internet-facing</span>}
        {c.kev ? <span className="chip chip-accent !text-[10px]">Exploited in the wild</span>
          : <span className="chip !text-[10px]">Not on KEV</span>}
        {c.ransomware && <span className="chip chip-danger !text-[10px]">Ransomware</span>}
        {c.news_mentions > 0 && <span className="chip !text-[10px]"><Newspaper className="mr-1 inline h-3 w-3" />{c.news_mentions} in the news</span>}
        {c.epss && <span className="chip !text-[10px]" title="EPSS: probability of exploitation in the next 30 days">EPSS {(c.epss.score * 100).toFixed(c.epss.score < 0.1 ? 1 : 0)}%</span>}
        {c.cvss && <span className="chip !text-[10px]">CVSS {c.cvss.score}</span>}
      </div>
      {c.kev && due != null && open && (
        <div className={cn('text-[11px]', due < 0 ? 'text-danger' : 'text-ink-faint')}>
          {due < 0 ? `CISA fix-by date passed ${-due} days ago` : `CISA fix-by date in ${due} days`}
        </div>
      )}
    </button>
  )
}

function NewsRail({ onOpenCve }: { onOpenCve: (cve: string) => void }) {
  const [filter, setFilter] = useState<'all' | 'exploited' | 'mine'>('all')
  const q = useQuery({
    queryKey: ['vuln-news'],
    queryFn: () => getJson<{ items: NewsItem[]; total: number; sources: string[]; counts: { exploited: number; open_in_stack: number } }>('/api/vulns/news?limit=120'),
    refetchInterval: 10 * 60_000,
    staleTime: 5 * 60_000,
  })
  const items = useMemo(() => (q.data?.items || []).filter(i =>
    filter === 'all' ? true : filter === 'exploited' ? i.exploited : i.in_stack), [q.data, filter])
  return (
    <aside className="min-w-0 xl:sticky xl:top-4 xl:self-start" data-testid="vuln-news">
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <div className="border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-accent" />
            <h2 className="text-sm font-semibold text-ink">Vulnerability news</h2>
            <span className="flex-1" />
            {q.data && <span className="text-[11px] text-ink-faint">{q.data.counts.exploited} exploitation reports</span>}
          </div>
          <div className="mt-2.5 flex gap-1 text-xs">
            {([['all', 'All'], ['exploited', 'Exploited'], ['mine', 'Your stack']] as const).map(([k, l]) => (
              <button key={k} onClick={() => setFilter(k)}
                      className={cn('rounded-full border px-2.5 py-0.5', filter === k ? 'border-accent/50 bg-accent/15 text-accent' : 'border-border text-ink-dim hover:text-ink')}>
                {l}
              </button>
            ))}
          </div>
        </div>
        <ol className="max-h-[calc(100vh-220px)] divide-y divide-border overflow-y-auto">
          {q.isLoading && <li className="px-4 py-6 text-center text-xs text-ink-faint">Loading feeds…</li>}
          {q.isError && <li className="px-4 py-6 text-center text-xs text-danger">News feeds unavailable.</li>}
          {q.data && items.length === 0 && <li className="px-4 py-6 text-center text-xs text-ink-faint">Nothing for this filter.</li>}
          {items.map((n, k) => (
            <li key={k} className="px-4 py-3">
              <div className="flex items-center gap-1.5 text-[11px] text-ink-faint">
                <span className={cn('font-semibold', n.kev_addition ? 'text-danger' : 'text-ink-dim')}>{n.source}</span>
                <span>· {ago(n.ts || n.published)}</span>
                <span className="flex-1" />
                {n.exploited && <span className="chip chip-danger !py-0 !text-[9.5px]">Exploited</span>}
                {n.open_in_stack ? <span className="chip chip-warning !py-0 !text-[9.5px]">Open in your estate</span>
                  : n.in_stack ? <span className="chip !py-0 !text-[9.5px]">Your stack</span> : null}
              </div>
              <a href={n.link} target="_blank" rel="noreferrer" className="mt-1 block text-[13.5px] font-medium leading-snug text-ink hover:text-accent">
                {n.title}
              </a>
              {(n.cves.length > 0 || n.mentions.length > 0) && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {n.cves.slice(0, 4).map(t => (
                    <button key={t.cve} onClick={() => onOpenCve(t.cve)} title={t.product ? `Runs on ${t.product}` : 'Open details'}
                            className={cn('chip !text-[10px] font-mono hover:border-accent hover:text-accent',
                              t.open ? 'chip-warning' : t.kev ? 'chip-accent' : '')}>
                      {t.cve}
                    </button>
                  ))}
                  {n.cves.length > 4 && <span className="chip !text-[10px]">+{n.cves.length - 4}</span>}
                  {n.mentions.map(m => <span key={m} className="chip !text-[10px]" title="Mentioned product you run">{m}</span>)}
                </div>
              )}
            </li>
          ))}
        </ol>
        {q.data && (
          <div className="border-t border-border px-4 py-2 text-[10.5px] leading-snug text-ink-faint">
            Sources: {q.data.sources.join(', ')}, plus Triage feed stories that name a CVE.
          </div>
        )}
      </div>
    </aside>
  )
}

function InventoryPanel({ onSearch }: { onSearch: (term: string) => void }) {
  const q = useQuery({ queryKey: ['vuln-inventory'], queryFn: () => getJson<{ source: string | null; assets: Array<Asset & { kev: number; open: number }> }>('/api/vulns/inventory') })
  const [filter, setFilter] = useState('')
  const groups = useMemo(() => {
    const f = filter.toLowerCase()
    const m = new Map<string, Array<Asset & { kev: number; open: number }>>()
    for (const a of q.data?.assets || []) {
      if (f && !`${a.vendor} ${a.product} ${a.version} ${a.owner} ${a.category} ${a.subcategory}`.toLowerCase().includes(f)) continue
      m.set(a.category, [...(m.get(a.category) || []), a])
    }
    return [...m.entries()]
  }, [q.data, filter])
  return (
    <div className="flex flex-col">
      <div className="border-b border-border px-6 py-5 pr-12">
        <h2 className="text-lg font-semibold text-ink">Technology inventory</h2>
        <p className="mt-0.5 text-xs text-ink-faint">{q.data?.source || 'from .env'} · {q.data?.assets.length ?? 0} products · click a row to search its vulnerabilities</p>
        <input className="input mt-3 w-full !text-sm" placeholder="Filter by product, owner, category…" value={filter} onChange={e => setFilter(e.target.value)} />
      </div>
      <div className="px-6 py-4">
        {q.isLoading && <div className="text-sm text-ink-faint">Loading…</div>}
        {groups.map(([cat, rows]) => (
          <section key={cat} className="mb-5">
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink-faint">{cat} <span className="font-normal">({rows.length})</span></h3>
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full min-w-[720px] text-xs">
                <thead><tr className="bg-surface2 text-left text-[10.5px] uppercase tracking-wider text-ink-faint">
                  <th className="px-3 py-2">Product</th><th className="px-3 py-2">Version</th><th className="px-3 py-2">Where</th>
                  <th className="px-3 py-2 text-right">Assets</th><th className="px-3 py-2">Owner</th><th className="px-3 py-2">Tier</th>
                  <th className="px-3 py-2 text-right">KEV</th><th className="px-3 py-2 text-right">Open</th>
                </tr></thead>
                <tbody>
                  {rows.map(a => (
                    <tr key={a.id} className="cursor-pointer border-t border-border hover:bg-surface2" onClick={() => onSearch(`${a.vendor} ${a.product}`.split('(')[0].trim())}>
                      <td className="px-3 py-2"><div className="text-ink">{a.product}</div><div className="text-ink-faint">{a.vendor}{a.internet_facing ? ' · internet-facing' : ''}</div></td>
                      <td className="px-3 py-2 font-mono text-ink-dim">{a.version}</td>
                      <td className="px-3 py-2 text-ink-dim">{a.environment}</td>
                      <td className="px-3 py-2 text-right font-mono text-ink-dim">{fmtCount(a.count)}</td>
                      <td className="px-3 py-2 text-ink-dim">{a.owner}</td>
                      <td className="px-3 py-2"><span className={cn('chip !text-[10px]', a.criticality === 'crown_jewel' && 'chip-danger')}>{CRIT_LABEL[a.criticality] || a.criticality}</span></td>
                      <td className="px-3 py-2 text-right font-mono text-ink-dim">{a.kev || ''}</td>
                      <td className={cn('px-3 py-2 text-right font-mono', a.open ? 'font-semibold text-danger' : 'text-ink-faint')}>{a.open || ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))}
      </div>
    </div>
  )
}

function DetailPanel({ cve }: { cve: string }) {
  const q = useQuery({ queryKey: ['vuln', cve], queryFn: () => getJson<Detail>(`/api/vulns/${cve}`) })
  const navigate = useNavigate()
  const d = q.data
  if (q.isLoading) return <div className="p-8 text-sm text-ink-faint">Loading {cve}…</div>
  if (q.isError || !d) return <div className="p-8 text-sm text-danger">Could not load {cve}: {(q.error as Error)?.message}</div>
  const desc = d.kev?.description || d.nvd?.description || ''
  const cvss = d.nvd?.cvss
  const e = d.exposure
  return (
    <div className="flex flex-col">
      <div className="border-b border-border px-6 py-5 pr-12">
        <div className="font-mono text-sm font-semibold text-accent">{d.cve}</div>
        <h2 className="mt-1 text-lg font-semibold leading-snug text-ink">{d.title}</h2>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {e && (e.covered ? <span className="chip chip-success">In your estate, fixed in deployed version</span>
                           : <span className="chip chip-warning">Open in your estate</span>)}
          {e && !e.covered && e.crown_jewel && <span className="chip chip-danger">Crown jewel</span>}
          {e && !e.covered && e.internet_facing && <span className="chip chip-warning">Internet-facing</span>}
          {d.kev ? <span className="chip chip-accent">Exploited in the wild (CISA KEV)</span> : <span className="chip">Not on KEV</span>}
          {d.kev?.ransomware && <span className="chip chip-danger">Used by ransomware</span>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-px border-b border-border bg-border sm:grid-cols-4">
        <Fact label="CVSS" value={cvss ? `${cvss.score} ${cvss.severity || ''}` : 'n/a'} />
        <Fact label="Chance of exploitation (30 d)" value={d.epss ? `${(d.epss.score * 100).toFixed(1)}%` : 'n/a'}
              sub={d.epss ? `higher than ${Math.round(d.epss.percentile * 100)}% of CVEs` : undefined} />
        <Fact label="Added to KEV" value={d.kev?.date_added || '—'} />
        <Fact label="CISA fix-by date" value={d.kev?.due_date || '—'} />
      </div>

      <div className="space-y-6 px-6 py-5">
        {d.kev?.required_action && (
          <section className="rounded-lg border border-warning/40 bg-warning/10 p-4">
            <h3 className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-warning">
              <AlertTriangle className="h-3.5 w-3.5" /> What to do
            </h3>
            <p className="text-sm text-ink">{d.kev.required_action}</p>
          </section>
        )}

        {e && (
          <Block title={`Where you run it (${e.products} product${e.products > 1 ? 's' : ''}${e.asset_count ? `, ${e.asset_count.toLocaleString()} assets` : ''})`}>
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full min-w-[640px] text-xs">
                <thead><tr className="bg-surface2 text-left text-[10.5px] uppercase tracking-wider text-ink-faint">
                  <th className="px-3 py-2">Product</th><th className="px-3 py-2">Where</th><th className="px-3 py-2 text-right">Assets</th>
                  <th className="px-3 py-2">Owner</th><th className="px-3 py-2">Tier</th><th className="px-3 py-2">Status</th>
                </tr></thead>
                <tbody>
                  {e.assets.map(a => {
                    const isOpen = !a.patched_through || !d.kev?.date_added || d.kev.date_added > a.patched_through
                    return (
                      <tr key={a.id} className="border-t border-border align-top">
                        <td className="px-3 py-2"><div className="text-ink">{a.product}</div><div className="font-mono text-ink-faint">{a.version}</div></td>
                        <td className="px-3 py-2 text-ink-dim">{a.environment}{a.internet_facing && <div className="text-warning">internet-facing</div>}</td>
                        <td className="px-3 py-2 text-right font-mono text-ink-dim">{fmtCount(a.count)}</td>
                        <td className="px-3 py-2 text-ink-dim">{a.owner}</td>
                        <td className="px-3 py-2"><span className={cn('chip !text-[10px]', a.criticality === 'crown_jewel' && 'chip-danger')}>{CRIT_LABEL[a.criticality] || a.criticality}</span></td>
                        <td className="px-3 py-2">
                          {isOpen ? <span className="text-danger">Exposed</span>
                            : <span className="text-success" title={`Deployed version includes fixes through ${a.patched_through}`}>Fixed in version</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <p className="mt-1.5 text-[11px] text-ink-faint">Exposure is estimated from the deployed version's fix level, not a scan of each host.</p>
          </Block>
        )}

        {desc && <Block title="What it is"><p className="text-sm leading-relaxed text-ink">{desc}</p></Block>}

        <Tracker cve={d.cve} t={d.tracking} inStack={!!d.org_match} defaultOwner={e?.owners[0] || ''} />

        {d.news.length > 0 && (
          <Block title={`In the news (${d.news.length})`}>
            <ul className="space-y-2">
              {d.news.map((n, k) => (
                <li key={k} className="text-sm">
                  <a href={n.url} target="_blank" rel="noreferrer" className="text-ink hover:text-accent">{n.title}</a>
                  <div className="text-xs text-ink-faint">{n.source}{n.published ? ` · ${n.published}` : ''}</div>
                </li>
              ))}
            </ul>
          </Block>
        )}

        {(d.nvd?.products?.length || 0) > 0 && (
          <Block title="Affected products (NVD)">
            <div className="flex flex-wrap gap-1.5">{d.nvd!.products.map(p => <span key={p} className="chip">{p}</span>)}</div>
          </Block>
        )}

        <Block title="Sources">
          <div className="flex flex-wrap gap-2 text-sm">
            <a className="btn btn-sm" href={d.links.nvd} target="_blank" rel="noreferrer">NVD <ExternalLink className="h-3 w-3" /></a>
            {d.links.kev && <a className="btn btn-sm" href={d.links.kev} target="_blank" rel="noreferrer">CISA KEV <ExternalLink className="h-3 w-3" /></a>}
            <a className="btn btn-sm" href={d.links.mitre} target="_blank" rel="noreferrer">CVE.org <ExternalLink className="h-3 w-3" /></a>
            <button className="btn btn-sm btn-primary" onClick={() => navigate(`/triage?threat=${encodeURIComponent(d.cve)}`)}>
              Triage this: hunt queries and detections
            </button>
          </div>
          {(d.nvd?.references?.length || 0) > 0 && (
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer text-ink-dim">{d.nvd!.references.length} vendor and research references</summary>
              <ul className="mt-2 space-y-1">
                {d.nvd!.references.map(r => <li key={r} className="truncate"><a className="text-info hover:underline" href={r} target="_blank" rel="noreferrer">{r}</a></li>)}
              </ul>
            </details>
          )}
        </Block>
      </div>
    </div>
  )
}

function Fact({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-surface px-4 py-3">
      <div className="text-[11px] text-ink-faint">{label}</div>
      <div className="mt-0.5 font-mono text-[15px] font-semibold text-ink">{value}</div>
      {sub && <div className="text-[11px] text-ink-faint">{sub}</div>}
    </div>
  )
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-faint">{title}</h3>
      {children}
    </section>
  )
}

function Tracker({ cve, t, inStack, defaultOwner }: { cve: string; t: Tracking | null; inStack: boolean; defaultOwner: string }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [f, setF] = useState({ status: t?.status || 'not_started', owner: t?.owner || defaultOwner, ticket: t?.ticket || '', note: '' })
  const save = useMutation({
    mutationFn: async () => {
      const r = await fetch(`/api/vulns/${cve}/tracking`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f),
      })
      if (!r.ok) throw new Error((await r.json()).detail || r.status)
      return r.json()
    },
    onSuccess: () => {
      toast('success', 'Remediation updated', `${cve}: ${TRACK[f.status].label}`)
      setF(x => ({ ...x, note: '' }))
      qc.invalidateQueries({ queryKey: ['vuln', cve] })
      qc.invalidateQueries({ queryKey: ['vulns'] })
      qc.invalidateQueries({ queryKey: ['vuln-news'] })
      qc.invalidateQueries({ queryKey: ['vuln-inventory'] })
    },
    onError: (e: Error) => toast('error', 'Could not save', e.message),
  })
  const history = useMemo(() => [...(t?.history || [])].reverse(), [t])
  return (
    <section className="rounded-lg border border-border p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-ink-dim" />
        <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-dim">Remediation</h3>
        {t && <span className={cn('chip !text-[10px]', TRACK[t.status]?.tone)}>{TRACK[t.status]?.label}</span>}
        <span className="flex-1" />
        <span className="text-[11px] text-ink-faint" title="Jira, ServiceNow and Glean sync are not connected yet. Status is tracked locally.">
          Tracked locally · Jira / ServiceNow not connected
        </span>
      </div>
      {!t && !inStack && <p className="mb-3 text-xs text-ink-faint">Not in your inventory. Track it here if you run it anyway.</p>}
      <div className="grid gap-2 sm:grid-cols-3">
        <select className="input !text-sm" value={f.status} onChange={e => setF({ ...f, status: e.target.value })} aria-label="Status">
          {Object.entries(TRACK).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <input className="input !text-sm" placeholder="Owner (team or person)" value={f.owner} onChange={e => setF({ ...f, owner: e.target.value })} />
        <input className="input !text-sm" placeholder="Ticket (e.g. CHG-1042)" value={f.ticket} onChange={e => setF({ ...f, ticket: e.target.value })} />
        <input className="input !text-sm sm:col-span-2" placeholder="What was done (optional)" value={f.note} onChange={e => setF({ ...f, note: e.target.value })} />
        <button className="btn btn-sm btn-primary justify-center" disabled={save.isPending} onClick={() => save.mutate()}>Save</button>
      </div>
      {history.length > 0 && (
        <ol className="mt-4 space-y-1.5 border-t border-border pt-3">
          {history.map((h, k) => (
            <li key={k} className="flex gap-3 text-xs">
              <span className="w-32 flex-shrink-0 font-mono text-ink-faint">{h.at.slice(0, 16).replace('T', ' ')}</span>
              <span className="text-ink-dim">{TRACK[h.status]?.label || h.status}{h.note ? `: ${h.note}` : ''}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}
