// Typed client for /api/ai/* — providers, MCP servers, agent routing.
//
// All shapes mirror the backend ai_config.py. Secrets never travel
// in either direction except for write-only fields on POST.

export type ProviderKind =
  | 'anthropic'
  | 'openai'
  | 'ollama'
  | 'custom-openai'
  | 'custom-anthropic'

export type ProviderStatus = {
  kind: ProviderKind
  label: string
  endpoint: string | null
  configured: boolean
  fingerprint: string | null
  validated_at: string | null
  last_modified: string | null
  default_model: string | null
}

export type McpEnvDisplay =
  | { type: 'plain'; value: string }
  | { type: 'secret'; configured: boolean }

export type McpServerStatus = {
  id: string
  label: string
  command: string
  args: string[]
  env: Record<string, McpEnvDisplay>
  enabled: boolean
  from_registry: boolean
}

export type McpRegistryEntry = {
  id: string
  label: string
  summary: string
  command: string
  args: string[]
  env_template: Record<string, {
    type: 'plain' | 'secret'
    label: string
    placeholder?: string
    required?: boolean
  }>
}

export type AgentRoute = { provider: string; model: string }

export type CanonicalAgent = {
  slug: string
  label: string
  kind: 'system' | 'agent'
}

export type SupportedModel = {
  id: string
  label: string
  tag: string
  notes: string
}

export type AIConfig = {
  providers: Record<string, ProviderStatus>
  mcp_servers: McpServerStatus[]
  agent_routes: Record<string, AgentRoute>
  mcp_registry: McpRegistryEntry[]
  canonical_agents: CanonicalAgent[]
  supported_models: SupportedModel[]
}

export type ProviderUpsert = {
  id: string
  kind: ProviderKind
  label?: string
  endpoint?: string
  secret?: string
  default_model?: string
  validate?: boolean
}

export type McpEnvWrite =
  | { type: 'plain'; value: string }
  | { type: 'secret'; value?: string }   // omit value to preserve existing blob

export type McpUpsert = {
  id: string
  label?: string
  command: string
  args?: string[]
  env?: Record<string, McpEnvWrite>
  enabled?: boolean
  from_registry?: boolean
}

async function jsonFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const r = await fetch(input, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers || {}),
    },
  })
  if (!r.ok) {
    let detail = ''
    try { detail = JSON.stringify(await r.json()) } catch {}
    throw new Error(`${r.status} ${r.statusText}${detail ? ` — ${detail}` : ''}`)
  }
  return r.json() as Promise<T>
}

export const aiConfigClient = {
  get: () => jsonFetch<AIConfig>('/api/ai/config'),

  upsertProvider: (req: ProviderUpsert) =>
    jsonFetch<{ ok: boolean; provider: ProviderStatus; validated?: boolean; validation_error?: string | null }>(
      '/api/ai/providers',
      { method: 'POST', body: JSON.stringify(req) },
    ),

  deleteProvider: (id: string) =>
    jsonFetch<{ ok: boolean }>(`/api/ai/providers/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  validateProvider: (id: string) =>
    jsonFetch<{ ok: boolean; error: string | null; provider: ProviderStatus }>(
      `/api/ai/providers/${encodeURIComponent(id)}/validate`,
      { method: 'POST' },
    ),

  upsertMcp: (req: McpUpsert) =>
    jsonFetch<{ ok: boolean; server: McpServerStatus }>(
      '/api/ai/mcp',
      { method: 'POST', body: JSON.stringify(req) },
    ),

  deleteMcp: (id: string) =>
    jsonFetch<{ ok: boolean }>(`/api/ai/mcp/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  setRoutes: (routes: Record<string, AgentRoute>) =>
    jsonFetch<{ ok: boolean; routes: Record<string, AgentRoute> }>(
      '/api/ai/routes',
      { method: 'PUT', body: JSON.stringify({ routes }) },
    ),
}
