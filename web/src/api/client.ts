// ThreatDesk API client. Dev: Vite proxies /api -> :8444. Prod: same origin.
const BASE = ''

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`HTTP ${res.status} ${path}: ${body.slice(0, 200)}`)
  }
  if (res.status === 204) return null as T
  return res.json() as Promise<T>
}

export const api = {
  health: () => req<{ status: string }>('/api/health'),
  getRuntimeSettings: () =>
    req<{
      settings: RuntimeSettings
      supported_models: Array<{ id: string; label: string; tag: string; notes: string }>
    }>(`/api/settings/runtime`),
  saveRuntimeSettings: (patch: Partial<RuntimeSettings>) =>
    req<{ ok: boolean; settings: RuntimeSettings }>(`/api/settings/runtime`, {
      method: 'POST',
      body: JSON.stringify(patch),
    }),
  getAgentModels: () =>
    req<{
      agents: Array<{ name: string; model: string | null }>
      supported_models: Array<{ id: string; label: string; tag: string; notes: string }>
    }>(`/api/settings/agents`),
  saveAgentModels: (patch: { all?: string; models?: Record<string, string> }) =>
    req<{
      ok: boolean
      agents: Array<{ name: string; model: string | null }>
    }>(`/api/settings/agents`, {
      method: 'POST',
      body: JSON.stringify(patch),
    }),
  listServiceKeys: () => req<{ keys: ServiceKey[] }>('/api/settings/service-keys'),
  setServiceKey: (sid: string, value: string) =>
    req<{ ok: boolean; key: ServiceKey }>(`/api/settings/service-keys/${encodeURIComponent(sid)}`,
      { method: 'PUT', body: JSON.stringify({ value }) }),
  addCustomServiceKey: (body: { id: string; label: string; env: string; value?: string; use?: string; signup?: string }) =>
    req<{ ok: boolean; key: ServiceKey }>('/api/settings/service-keys/custom',
      { method: 'POST', body: JSON.stringify(body) }),
  deleteCustomServiceKey: (sid: string) =>
    req<{ ok: boolean }>(`/api/settings/service-keys/custom/${encodeURIComponent(sid)}`, { method: 'DELETE' }),
  importServiceKeys: (path: string) =>
    req<{ ok: boolean; imported: string[] }>('/api/settings/service-keys/import',
      { method: 'POST', body: JSON.stringify({ path }) }),
  listTriages: () =>
    req<{ triages: TriageSummary[] }>('/api/triages'),
  getTriage: (id: string) =>
    req<TriageDetail>(`/api/triage/${encodeURIComponent(id)}`),
  deleteTriage: (id: string) =>
    req<{ ok: boolean; deleted: string }>(
      `/api/triage/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    ),
  createTriage: async (form: FormData) => {
    const res = await fetch('/api/triage', { method: 'POST', body: form })
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ ok: boolean; triage_id: string }>
  },
  renameTriage: (id: string, custom_name: string | null) =>
    req<{ ok: boolean; triage_id: string; custom_name: string | null }>(
      `/api/triage/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: JSON.stringify({ custom_name }) },
    ),
  tipListIocs: (params?: { q?: string; ioc_type?: string; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.q) qs.set('q', params.q)
    if (params?.ioc_type) qs.set('ioc_type', params.ioc_type)
    if (params?.limit) qs.set('limit', String(params.limit))
    const suffix = qs.toString() ? `?${qs.toString()}` : ''
    return req<{ iocs: TipIoc[]; total: number; summary: TipSummary }>(`/api/tip/iocs${suffix}`)
  },
  tipGetIoc: (ioc_type: string, value: string) =>
    req<{ ioc: TipIoc; enrichment: TipEnrichment | null }>(
      `/api/tip/ioc/${encodeURIComponent(ioc_type)}/${encodeURIComponent(value)}`,
    ),
  tipEnrichIoc: (ioc_type: string, value: string, force = false) =>
    req<TipEnrichment>(
      `/api/tip/ioc/${encodeURIComponent(ioc_type)}/${encodeURIComponent(value)}/enrich${force ? '?force=1' : ''}`,
      { method: 'POST', body: '{}' },
    ),
  tipEnrichers: () =>
    req<{ enrichers: TipEnricherStatus[] }>('/api/tip/enrichers'),
  tipMispExportAll: () =>
    req<{ response: unknown[]; meta: { generator: string; generated_at: string; event_count: number } }>(
      '/api/tip/misp-export',
    ),

  // ─── Environment profile + inventory ───────────────────────────────
  getEnvironment: () =>
    req<{ environment: Record<string, unknown> | null; source: string; path?: string; inventory: InventoryAsset[] }>('/api/environment'),
  saveEnvironment: (environment: Record<string, unknown>) =>
    req<{ ok: boolean }>('/api/environment', { method: 'POST', body: JSON.stringify({ environment }) }),
  inventorySources: () =>
    req<{ sources: InventorySource[]; columns: string[]; asset_count: number }>('/api/inventory/sources'),
  uploadInventoryCsv: async (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    const res = await fetch('/api/inventory/csv', { method: 'PUT', body: fd })
    if (!res.ok) throw new Error((await res.text().catch(() => '')).slice(0, 300) || `HTTP ${res.status}`)
    return res.json() as Promise<{ ok: boolean; count: number; errors: string[]; path: string }>
  },
}

export interface InventoryAsset {
  id: string; category: string; subcategory: string; vendor: string; product: string; version: string
  patched_through: string | null; environment: string; count: number | null; owner: string
  criticality: 'crown_jewel' | 'high' | 'medium' | 'low'; internet_facing: boolean; match: string[]
}

export interface InventorySource {
  name: 'csv' | 'json' | 'env' | 'servicenow'; label: string; configured: boolean
  path: string | null; count: number; errors: string[]; note?: string
}

export interface TipIoc {
  type: string
  value: string
  normalized_value: string
  observations: Array<{
    source: 'triage'
    id: string
    summary: string
    ioc_id: string | null
    disposition: string | null
    notes: string | null
    evidence_refs: string[]
    seen_at: string | null
  }>
  observation_count: number
  first_seen: string | null
  last_seen: string | null
  dispositions: string[]
  related_triages: string[]
}

export interface TipSummary {
  total_iocs: number
  total_observations: number
  by_type: Record<string, number>
}

export interface TipEnrichment {
  type: string
  value: string
  cached_at: number
  from_cache: boolean
  enrichers_run: string[]
  enrichers_skipped: string[]
  timings?: Record<string, number>
  total_duration_s?: number
  // Each enricher's payload lives under its name as a key. Free/no-auth:
  urlhaus?: Record<string, unknown>
  threatfox?: Record<string, unknown>
  malwarebazaar?: Record<string, unknown>
  feodotracker?: Record<string, unknown>
  shodan_internetdb?: Record<string, unknown>
  circl_hashlookup?: Record<string, unknown>
  // Optional premium (need env API keys):
  virustotal?: Record<string, unknown>
  abuseipdb?: Record<string, unknown>
  [key: string]: unknown
}

export interface TipEnricherStatus {
  name: string
  configured: boolean
  requires_key: boolean
  env_var: string | null
  supports: string[]
  notes: string
}

export interface TriageSummary {
  triage_id: string
  input_type: 'url' | 'threat_name' | 'text' | 'file'
  input_ref: string | null
  question: string
  siem_preference: string
  use_environment: boolean
  created_at: string
  custom_name: string | null
  status: 'pending' | 'running' | 'done' | 'error'
  started_at: string | null
  completed_at: string | null
  error: string | null
  headline: string | null
  severity: string | null
  prioritization_score: number | null
  exploitation_status: string | null
}

export interface RuntimeSettings {
  triage_model: string
  cyber_fallback_enabled: boolean
  cyber_fallback_model: string
  use_subscription: boolean
  runner_backend: 'sdk' | 'cli'
}

export interface TriageResult {
  headline?: string
  short_answer?: string
  // Atomic, dispositioned findings — the scannable lead of the analysis.
  // Each is one plain-English line; evidence expands on demand. Optional
  // so older triages still render.
  key_findings?: Array<{
    disposition?: 'malicious' | 'suspicious' | 'benign' | 'info' | string
    statement: string
    evidence?: string
  }>
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  prioritization_score?: number
  exploitation_status?: string
  cves?: Array<{ id: string; cvss_base?: number; epss_percentile?: number; in_kev?: boolean }>
  iocs?: Array<{ type?: string; value?: string; disposition?: string }>
  ttps?: Array<{ tactic?: string; technique_id?: string; name?: string }>
  affected_platforms?: string[]
  malware_family?: string
  actor_group?: string
  our_exposure?: { applicable_to_env?: boolean; hosts_potentially_affected?: number; confidence?: number; notes?: string }
  hunts?: Array<{ hypothesis: string; siem: string; query: string; notes?: string }>
  detections?: Array<{ format: string; title: string; rule: string }>
  actions?: Array<{ title: string; urgency?: string; category?: string; rationale?: string }>
  // Agents sometimes emit citation objects here instead of URL strings.
  // Accept both shapes and normalize in the UI.
  sources?: Array<string | { url?: string; title?: string; publisher?: string; date?: string }>
  confidence?: number
}

export interface TriageDetail {
  triage_id: string
  input: {
    triage_id: string
    input_type: 'url' | 'threat_name' | 'text' | 'file'
    input_ref: string | null
    input_text: string | null
    attached_files?: string[]
    question: string
    siem_preference: string
    use_environment: boolean
    created_at: string
    custom_name?: string | null
  }
  status: {
    status: 'pending' | 'running' | 'done' | 'error'
    started_at: string | null
    completed_at: string | null
    error: string | null
  }
  result: TriageResult | null
  report_md: string | null
  events: Array<Record<string, unknown>>
}

export interface ServiceKey {
  id: string
  label: string
  env: string
  category: string
  use: string
  signup: string
  custom: boolean
  configured: boolean
  source: 'env' | 'settings' | null
  last4?: string | null
  updated_at?: string | null
}
