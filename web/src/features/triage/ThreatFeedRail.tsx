import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Flame, ExternalLink, RefreshCw, Filter, Zap, Shield,
  Newspaper, Building2, AlertCircle, Rss,
} from 'lucide-react'
import { cn } from '@/lib/cn'
import { formatDistanceToNowStrict } from 'date-fns'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
  DialogBody, DialogFooter,
} from '@/components/ui/dialog'

/** Tier → icon, shared by the feed card and the article modal. */
function tierIcon(tier: string, className = 'w-2.5 h-2.5') {
  if (tier === 'gov') return <Building2 className={className} />
  if (tier === 'analysis') return <Shield className={className} />
  return <Newspaper className={className} />
}

/**
 * The right-rail threat feed in Triage. Pulls /api/threats/feed and
 * renders an always-on scrollable list of top industry threats with
 * cross-source correlation, KEV flagging, and one-click "triage this"
 * shortcuts.
 *
 * Click behavior:
 *  - clicking an item's title/card → opens URL in a new tab
 *  - clicking the small "triage" button → fires `onTriageUrl(url)` so
 *    the parent can pre-fill the composer and kick off a run
 */

export interface ThreatFeedItem {
  id: string
  source_id: string
  source_name: string
  source_tier: 'gov' | 'news' | 'analysis' | string
  title: string
  link: string
  summary: string
  published: string
  published_ts: number | null
  cves: string[]
  malware_families: string[]
  actor_groups: string[]
  topics: string[]
  hubbub_score: number
  correlated_sources: string[]
  kev_cves: string[]
  is_kev: boolean
  cluster_size?: number
  cluster_sources?: Array<{
    source_id: string
    source_name: string
    source_tier: string
    title: string
    link: string
    published_ts: number | null
    published: string
  }>
}

interface FeedResponse {
  items: ThreatFeedItem[]
  sources: Array<{ id: string; name: string; tier: string; url: string }>
  source_status: Record<string, { ok: boolean; error: string | null; count: number }>
  kev_cve_count: number
  last_refreshed_at: number
  ttl_seconds: number
  topics: string[]
}

export function ThreatFeedRail({
  onTriageUrl,
  onTriageThreatName,
}: {
  onTriageUrl: (url: string, headline?: string) => void
  onTriageThreatName: (name: string) => void
}) {
  const [forceRefreshing, setForceRefreshing] = useState(false)
  const q = useQuery({
    queryKey: ['threat-feed'],
    queryFn: async () => {
      // When the user clicks Refresh, we set forceRefreshing=true so
      // this fetch bypasses the server's 30-min TTL too. Otherwise
      // the button would re-pull cached data (feels "broken").
      const url = forceRefreshing ? '/api/threats/feed?force=1' : '/api/threats/feed'
      const r = await fetch(url)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      return (await r.json()) as FeedResponse
    },
    // On the client, hit the API every 5min, the server's own cache
    // is 30min, so this is cheap.
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  })

  async function forceRefresh() {
    setForceRefreshing(true)
    try { await q.refetch() } finally { setForceRefreshing(false) }
  }

  const [signalFilter, setSignalFilter] = useState<'all' | 'kev' | 'correlated' | 'cve'>('all')
  const [topicFilter, setTopicFilter] = useState<Set<string>>(new Set())
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(new Set())
  const [showSummaries, setShowSummaries] = useState(false)
  const [sortMode, setSortMode] = useState<'relevance' | 'newest'>('relevance')
  // Article opened in the in-app reader modal (null = closed).
  const [article, setArticle] = useState<ThreatFeedItem | null>(null)

  const toggleTopic = (t: string) => {
    const next = new Set(topicFilter)
    next.has(t) ? next.delete(t) : next.add(t)
    setTopicFilter(next)
  }
  const toggleSource = (id: string) => {
    const next = new Set(sourceFilter)
    next.has(id) ? next.delete(id) : next.add(id)
    setSourceFilter(next)
  }

  // The set of source ids an item represents: its own source plus every
  // source that contributed to its cluster. Used by both the source
  // filter and the per-source counts so a clustered row counts toward
  // each contributing source.
  const itemSourceIds = (it: ThreatFeedItem): string[] => {
    const ids = new Set<string>([it.source_id])
    for (const s of it.cluster_sources || []) ids.add(s.source_id)
    return [...ids]
  }

  const items = useMemo(() => {
    let base = q.data?.items || []
    if (signalFilter === 'kev') base = base.filter(i => i.is_kev)
    else if (signalFilter === 'correlated') base = base.filter(i => i.hubbub_score > 0)
    else if (signalFilter === 'cve') base = base.filter(i => i.cves.length > 0)
    if (topicFilter.size > 0) {
      base = base.filter(i => (i.topics || []).some(t => topicFilter.has(t)))
    }
    if (sourceFilter.size > 0) {
      base = base.filter(i => itemSourceIds(i).some(id => sourceFilter.has(id)))
    }
    if (sortMode === 'newest') {
      base = [...base].sort((a, b) => (b.published_ts || 0) - (a.published_ts || 0))
    }
    // "relevance" leaves the server's KEV-first-then-hubbub-then-
    // recency sort alone.
    return base
  }, [q.data, signalFilter, topicFilter, sourceFilter, sortMode])

  // Per-source item counts (across clusters) for the source-filter chips.
  const sourceCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const it of q.data?.items || []) {
      for (const id of itemSourceIds(it)) counts[id] = (counts[id] || 0) + 1
    }
    return counts
  }, [q.data])

  // Topic counts for the chip labels (so the user can see at a glance
  // how many items each topic has).
  const topicCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const it of q.data?.items || []) {
      for (const t of it.topics || []) {
        counts[t] = (counts[t] || 0) + 1
      }
    }
    return counts
  }, [q.data])

  return (
    <div className="h-full flex flex-col bg-surface/60">
      <header className="px-3 py-2 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Flame className="w-3.5 h-3.5 text-accent" />
          <span className="text-2xs uppercase tracking-[0.1em] text-ink-faint">Top threats</span>
          {q.data && (
            <span className="text-2xs text-ink-faint" title={`KEV catalog: ${q.data.kev_cve_count} CVEs`}>
              · {q.data.items.length}
            </span>
          )}
        </div>
        <button
          onClick={forceRefresh}
          className="btn btn-ghost btn-xs"
          title="Refresh feed (bypasses 30-min server cache)"
          disabled={q.isFetching || forceRefreshing}
        >
          <RefreshCw className={cn('w-3 h-3', (q.isFetching || forceRefreshing) && 'animate-spin')} />
        </button>
      </header>

      {/* Signal filter + sort + density toggle. */}
      <div className="px-3 py-1.5 border-b border-border flex items-center gap-1 flex-wrap">
        <Filter className="w-3 h-3 text-ink-faint mr-1" />
        <FilterChip active={signalFilter === 'all'} onClick={() => setSignalFilter('all')}>All</FilterChip>
        <FilterChip active={signalFilter === 'kev'} onClick={() => setSignalFilter('kev')} danger>KEV</FilterChip>
        <FilterChip active={signalFilter === 'correlated'} onClick={() => setSignalFilter('correlated')}>Hubbub</FilterChip>
        <FilterChip active={signalFilter === 'cve'} onClick={() => setSignalFilter('cve')}>CVE</FilterChip>
        <span className="text-2xs text-ink-faint ml-1 mr-0.5">·</span>
        <button
          onClick={() => setSortMode(m => m === 'relevance' ? 'newest' : 'relevance')}
          className="text-2xs text-accent hover:text-accent-hot"
          title={sortMode === 'relevance'
            ? 'Sorted by KEV → hubbub → recency (click to sort by published date)'
            : 'Sorted by published date (click to switch back to relevance)'}
        >
          sort: {sortMode === 'relevance' ? 'relevance' : 'newest'}
        </button>
        <button
          onClick={() => setShowSummaries(v => !v)}
          className="ml-auto text-2xs text-ink-faint hover:text-ink-dim"
          title={showSummaries ? 'Hide summaries for a compact view' : 'Show summary text'}
        >
          {showSummaries ? 'compact' : 'expanded'}
        </button>
      </div>

      {/* Topic filter, multi-select, horizontal scrollable. */}
      {q.data?.topics && q.data.topics.length > 0 && (
        <div className="px-3 py-1.5 border-b border-border overflow-x-auto">
          <div className="flex items-center gap-1 whitespace-nowrap">
            {q.data.topics
              .filter(t => (topicCounts[t] || 0) > 0 || topicFilter.has(t))
              .map(t => (
                <TopicChip
                  key={t}
                  label={t}
                  count={topicCounts[t] || 0}
                  active={topicFilter.has(t)}
                  onClick={() => toggleTopic(t)}
                />
              ))}
            {topicFilter.size > 0 && (
              <button
                onClick={() => setTopicFilter(new Set())}
                className="ml-1 text-2xs text-accent hover:text-accent-hot"
              >
                clear
              </button>
            )}
          </div>
        </div>
      )}

      {/* Source filter, multi-select, horizontal scrollable. */}
      {q.data?.sources && q.data.sources.length > 0 && (
        <div className="px-3 py-1.5 border-b border-border overflow-x-auto">
          <div className="flex items-center gap-1 whitespace-nowrap">
            <Rss className="w-3 h-3 text-ink-faint mr-0.5 flex-shrink-0" />
            {q.data.sources
              .filter(s => (sourceCounts[s.id] || 0) > 0 || sourceFilter.has(s.id))
              .map(s => (
                <FilterChip
                  key={s.id}
                  active={sourceFilter.has(s.id)}
                  onClick={() => toggleSource(s.id)}
                >
                  {s.name}
                  <span className="ml-1 text-[9px] opacity-70 tnum">{sourceCounts[s.id] || 0}</span>
                </FilterChip>
              ))}
            {sourceFilter.size > 0 && (
              <button
                onClick={() => setSourceFilter(new Set())}
                className="ml-1 text-2xs text-accent hover:text-accent-hot"
              >
                clear
              </button>
            )}
          </div>
        </div>
      )}

      {q.isLoading ? (
        <div className="flex-1 flex items-center justify-center text-xs text-ink-faint">loading feed…</div>
      ) : q.isError ? (
        <div className="flex-1 flex items-center justify-center p-4 text-xs text-danger text-center">
          <div>
            <AlertCircle className="w-4 h-4 mx-auto mb-2" />
            Feed unavailable
            <div className="text-2xs text-ink-faint mt-1">{String(q.error)}</div>
          </div>
        </div>
      ) : items.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-xs text-ink-faint p-4 text-center">
          No items match this filter.
        </div>
      ) : (
        <ul className="flex-1 overflow-y-auto divide-y divide-border">
          {items.map(item => (
            <FeedItemCard
              key={item.id}
              item={item}
              showSummary={showSummaries}
              onTriageUrl={onTriageUrl}
              onTriageThreatName={onTriageThreatName}
              onOpenArticle={setArticle}
            />
          ))}
        </ul>
      )}

      {/* In-app article reader. Opens on top of Triage instead of
          pushing the analyst out into a browser tab. */}
      <ArticleModal
        item={article}
        onClose={() => setArticle(null)}
        onTriageUrl={onTriageUrl}
        onTriageThreatName={onTriageThreatName}
      />

      {q.data && (
        <footer className="px-3 py-1.5 border-t border-border text-2xs text-ink-faint flex items-center justify-between">
          <span title={new Date(q.data.last_refreshed_at * 1000).toLocaleString()}>
            refreshed {formatDistanceToNowStrict(new Date(q.data.last_refreshed_at * 1000), { addSuffix: true })}
          </span>
          <span>{Object.values(q.data.source_status).filter(s => s.ok).length}/{Object.keys(q.data.source_status).length} src</span>
        </footer>
      )}
    </div>
  )
}

function FilterChip({
  active, onClick, children, danger,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
  danger?: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'px-1.5 py-0.5 rounded text-2xs transition-colors',
        active
          ? (danger ? 'bg-danger/15 text-danger border border-danger/40' : 'bg-accent/15 text-accent border border-accent/40')
          : 'text-ink-faint hover:text-ink-dim border border-transparent hover:border-border',
      )}
    >
      {children}
    </button>
  )
}

// Source monogram tile — a zero-network "avatar" that gives each card a
// visual anchor (the rhythm of a thumbnail) without fetching remote
// images from news/ad CDNs. Tinted by tier so gov/analysis/news read
// apart at a glance, and it reinforces the source filter.
const _TILE_STOP = new Set(['the', 'on', 'of', 'and', 'a'])
function sourceInitials(name: string): string {
  const words = name.replace(/[^A-Za-z0-9 ]/g, ' ').split(/\s+/).filter(Boolean)
  const sig = words.filter(w => !_TILE_STOP.has(w.toLowerCase()))
  const pick = sig.length ? sig : words
  if (pick.length >= 2) return (pick[0][0] + pick[1][0]).toUpperCase()
  return (pick[0] || '?').slice(0, 2).toUpperCase()
}

function SourceTile({ name, tier }: { name: string; tier: string }) {
  const tint =
    tier === 'gov' ? 'bg-info/10 text-info border-info/30' :
    tier === 'analysis' ? 'bg-accent/10 text-accent-hot border-accent/30' :
    'bg-surface3 text-ink-dim border-border'
  return (
    <div
      className={cn('flex-shrink-0 w-8 h-8 rounded-md border flex items-center justify-center text-[10px] font-semibold font-mono select-none', tint)}
      title={name}
      aria-hidden
    >
      {sourceInitials(name)}
    </div>
  )
}

function FeedItemCard({
  item, showSummary, onTriageUrl, onTriageThreatName, onOpenArticle,
}: {
  item: ThreatFeedItem
  showSummary: boolean
  onTriageUrl: (url: string, headline?: string) => void
  onTriageThreatName: (name: string) => void
  onOpenArticle: (item: ThreatFeedItem) => void
}) {
  const when = item.published_ts
    ? formatDistanceToNowStrict(new Date(item.published_ts * 1000), { addSuffix: true })
    : null

  // Cap summary at a readable length when the user opts in.
  const summary = showSummary && item.summary
    ? (item.summary.length > 180 ? item.summary.slice(0, 180) + '…' : item.summary)
    : null

  return (
    <li className="px-3 py-2 hover:bg-surface2/60 transition-colors group">
     <div className="flex items-start gap-2.5">
      <SourceTile name={item.source_name} tier={item.source_tier} />
      <div className="min-w-0 flex-1">
      {/* Row 1: title + KEV flame + hubbub count */}
      <div className="flex items-start gap-1.5">
        {item.is_kev && (
          <Flame className="w-3 h-3 text-danger flex-shrink-0 mt-0.5" aria-label="KEV" />
        )}
        <button
          onClick={() => onOpenArticle(item)}
          className="flex-1 min-w-0 text-left text-[12px] text-ink hover:text-accent leading-snug line-clamp-2"
          title={`${item.title}\n\n(opens in-app reader)`}
        >
          {item.title}
        </button>
        {(item.cluster_size || 1) > 1 && (
          <span
            className="flex-shrink-0 chip chip-accent !text-[9px] !py-0 !px-1 mt-0.5"
            title={`Same story covered by ${item.cluster_size} sources, click below to see them all`}
          >
            {item.cluster_size}×
          </span>
        )}
        {(item.cluster_size || 1) <= 1 && item.hubbub_score > 0 && (
          <span
            className="flex-shrink-0 chip chip-accent !text-[9px] !py-0 !px-1 mt-0.5"
            title={`Also discussed by: ${item.correlated_sources.join(', ')}`}
          >
            ×{item.hubbub_score + 1}
          </span>
        )}
      </div>

      {/* Row 2: source + time, single compact line. When a story is
          covered by multiple sources, they collapse into a summary
          like "CISA · +2 more" with a tooltip listing them all. */}
      <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-ink-faint">
        <span className="inline-flex items-center gap-0.5 font-mono">
          {tierIcon(item.source_tier)}
          {item.source_name}
        </span>
        {(item.cluster_size || 1) > 1 && item.cluster_sources && (
          <span
            className="text-accent/80 hover:text-accent-hot cursor-help"
            title={item.cluster_sources
              .map(s => `• ${s.source_name}: ${s.title}`)
              .join('\n')}
          >
            + {(item.cluster_size || 1) - 1} more source{item.cluster_size === 2 ? '' : 's'}
          </span>
        )}
        {when && <span>· {when}</span>}
      </div>

      {/* Row 3: topic chips, always show, tight sizing */}
      {item.topics.length > 0 && (
        <div className="mt-1 flex items-center gap-0.5 flex-wrap">
          {item.topics.slice(0, 4).map(t => (
            <span
              key={t}
              className="inline-flex items-center px-1 py-px rounded text-[9px] font-medium
                         bg-surface2 border border-border text-ink-dim"
            >
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Row 4: summary, hidden by default */}
      {summary && (
        <p className="mt-1 text-[10px] text-ink-dim leading-relaxed line-clamp-3">
          {summary}
        </p>
      )}

      {/* Row 5: technical chips (CVE / family / actor) */}
      {(item.cves.length > 0 || item.malware_families.length > 0 || item.actor_groups.length > 0) && (
        <div className="mt-1 flex items-center gap-0.5 flex-wrap">
          {item.cves.slice(0, 2).map(c => (
            <span
              key={c}
              className={cn('chip !text-[9px] !py-0 !px-1 font-mono',
                item.kev_cves.includes(c) ? 'chip-danger' : 'chip-accent',
              )}
              title={item.kev_cves.includes(c) ? 'KEV-listed' : 'CVE'}
            >
              {c}
            </span>
          ))}
          {item.cves.length > 2 && (
            <span className="text-[9px] text-ink-faint">+{item.cves.length - 2}</span>
          )}
          {item.malware_families.slice(0, 1).map(f => (
            <span key={f} className="chip chip-warning !text-[9px] !py-0 !px-1">{f}</span>
          ))}
          {item.actor_groups.slice(0, 1).map(a => (
            <span key={a} className="chip !text-[9px] !py-0 !px-1">{a}</span>
          ))}
        </div>
      )}

      {/* Action row, visible on hover */}
      <div className="mt-1 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          className="btn btn-ghost btn-xs !py-0 !text-[10px]"
          onClick={() => onTriageUrl(item.link, item.title)}
          title="Triage this URL"
        >
          <Zap className="w-2.5 h-2.5" />
          triage
        </button>
        {item.malware_families[0] && (
          <button
            className="btn btn-ghost btn-xs !py-0 !text-[10px]"
            onClick={() => onTriageThreatName(item.malware_families[0])}
            title={`Triage by name: ${item.malware_families[0]}`}
          >
            → {item.malware_families[0]}
          </button>
        )}
        <a
          href={item.link}
          target="_blank" rel="noopener noreferrer"
          className="btn btn-ghost btn-xs !py-0 ml-auto"
          title="Open source"
        >
          <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>
      </div>
     </div>
    </li>
  )
}

function TopicChip({
  label, count, active, onClick,
}: {
  label: string
  count: number
  active: boolean
  onClick: () => void
}) {
  // Fixed semantic colors per topic, makes the rail scannable at
  // a glance without needing to read labels.
  const hue: Record<string, string> = {
    'Zero-day':        'text-danger-hot border-danger/60 bg-danger/10',
    'Ransomware':      'text-danger border-danger/40 bg-danger/10',
    'Supply Chain':    'text-warning border-warning/40 bg-warning/10',
    'Nation-State':    'text-info border-info/40 bg-info/10',
    'Phishing':        'text-warning border-warning/40 bg-warning/10',
    'Cloud':           'text-info border-info/40 bg-info/10',
    'Critical Infra':  'text-danger border-danger/40 bg-danger/10',
    'Data Breach':     'text-warning border-warning/40 bg-warning/10',
    'Vulnerability':   'text-accent border-accent/40 bg-accent/10',
    'Law Enforcement': 'text-success border-success/40 bg-success/10',
    'Malware':         'text-ink-dim border-border bg-surface2',
  }
  const inactive = 'text-ink-faint border-border/60 bg-transparent'
  return (
    <button
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border transition-colors whitespace-nowrap',
        active ? (hue[label] || 'text-accent border-accent/40 bg-accent/10') : inactive,
      )}
    >
      {label}
      <span className="text-[9px] opacity-70 tnum">{count}</span>
    </button>
  )
}

/**
 * In-app article reader. RSS only gives us a title, a short summary, and
 * the correlated metadata we've already extracted (CVEs, families,
 * actors, topics, KEV, the cluster of sources covering the same story) —
 * so the modal surfaces all of that in a scannable layout and keeps an
 * explicit "Open original ↗" escape hatch rather than silently throwing
 * the analyst out into a browser tab.
 */
function ArticleModal({
  item, onClose, onTriageUrl, onTriageThreatName,
}: {
  item: ThreatFeedItem | null
  onClose: () => void
  onTriageUrl: (url: string, headline?: string) => void
  onTriageThreatName: (name: string) => void
}) {
  if (!item) return null
  const when = item.published_ts
    ? formatDistanceToNowStrict(new Date(item.published_ts * 1000), { addSuffix: true })
    : null
  // Distinct sources covering this story (cluster), newest-first already.
  const sources = item.cluster_sources && item.cluster_sources.length > 0
    ? item.cluster_sources
    : [{
        source_id: item.source_id, source_name: item.source_name,
        source_tier: item.source_tier, title: item.title, link: item.link,
        published_ts: item.published_ts, published: item.published,
      }]

  return (
    <Dialog open={!!item} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent size="lg" className="max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-start gap-2 pr-6">
            {item.is_kev && <Flame className="w-4 h-4 text-danger flex-shrink-0 mt-1" aria-label="KEV" />}
            <span className="leading-snug">{item.title}</span>
          </DialogTitle>
          <DialogDescription className="flex items-center gap-2 flex-wrap">
            <span className="inline-flex items-center gap-1 font-mono text-ink-dim">
              {tierIcon(item.source_tier, 'w-3 h-3')}
              {item.source_name}
            </span>
            {(item.cluster_size || 1) > 1 && (
              <span className="chip chip-accent !text-[10px] !py-0 !px-1.5">{item.cluster_size} sources</span>
            )}
            {when && <span>· {when}</span>}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="overflow-y-auto space-y-4">
          {/* Summary (RSS excerpt). */}
          {item.summary && (
            <p className="text-sm text-ink-dim leading-relaxed">{item.summary}</p>
          )}

          {/* Topics. */}
          {item.topics.length > 0 && (
            <div className="flex items-center gap-1 flex-wrap">
              {item.topics.map(t => (
                <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-surface2 border border-border text-ink-dim">
                  {t}
                </span>
              ))}
            </div>
          )}

          {/* Technical indicators. */}
          {(item.cves.length > 0 || item.malware_families.length > 0 || item.actor_groups.length > 0) && (
            <div className="space-y-2">
              {item.cves.length > 0 && (
                <IndicatorRow label="CVEs">
                  {item.cves.map(c => (
                    <span key={c} className={cn('chip !text-[10px] !py-0 !px-1.5 font-mono', item.kev_cves.includes(c) ? 'chip-danger' : 'chip-accent')} title={item.kev_cves.includes(c) ? 'KEV-listed' : 'CVE'}>
                      {c}{item.kev_cves.includes(c) && ' · KEV'}
                    </span>
                  ))}
                </IndicatorRow>
              )}
              {item.malware_families.length > 0 && (
                <IndicatorRow label="Malware">
                  {item.malware_families.map(f => (
                    <button key={f} className="chip chip-warning !text-[10px] !py-0 !px-1.5 hover:brightness-125"
                      onClick={() => { onTriageThreatName(f); onClose() }} title={`Triage by name: ${f}`}>
                      {f}
                    </button>
                  ))}
                </IndicatorRow>
              )}
              {item.actor_groups.length > 0 && (
                <IndicatorRow label="Actors">
                  {item.actor_groups.map(a => (
                    <button key={a} className="chip !text-[10px] !py-0 !px-1.5 hover:brightness-125"
                      onClick={() => { onTriageThreatName(a); onClose() }} title={`Triage by name: ${a}`}>
                      {a}
                    </button>
                  ))}
                </IndicatorRow>
              )}
            </div>
          )}

          {/* Sources covering this story. */}
          <div>
            <div className="text-2xs uppercase tracking-[0.1em] text-ink-faint mb-1.5">
              {sources.length > 1 ? `${sources.length} sources` : 'Source'}
            </div>
            <ul className="divide-y divide-border border border-border rounded-md">
              {sources.map((s, i) => (
                <li key={`${s.source_id}-${i}`} className="px-2.5 py-2 flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 font-mono text-[10px] text-ink-faint w-36 flex-shrink-0">
                    {tierIcon(s.source_tier, 'w-2.5 h-2.5')}
                    {s.source_name}
                  </span>
                  <a href={s.link} target="_blank" rel="noopener noreferrer"
                    className="flex-1 min-w-0 text-xs text-ink hover:text-accent leading-snug line-clamp-2">
                    {s.title}
                  </a>
                  <a href={s.link} target="_blank" rel="noopener noreferrer"
                    className="btn btn-ghost btn-xs !py-0 flex-shrink-0" title="Open this source in a new tab">
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </DialogBody>

        <DialogFooter>
          <a href={item.link} target="_blank" rel="noopener noreferrer" className="btn btn-ghost btn-sm mr-auto">
            <ExternalLink className="w-3.5 h-3.5" /> Open original
          </a>
          <button className="btn btn-primary btn-sm" onClick={() => { onTriageUrl(item.link, item.title); onClose() }}>
            <Zap className="w-3.5 h-3.5" /> Triage this
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function IndicatorRow({ label, children }: React.PropsWithChildren<{ label: string }>) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-[10px] text-ink-faint w-14 flex-shrink-0 pt-0.5">{label}</span>
      <div className="flex items-center gap-1 flex-wrap">{children}</div>
    </div>
  )
}
