import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { ToastProvider } from '@/components/ui/toast'
import { TriageView } from './TriageView'

function json(body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }))
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn((url: string) => {
    if (url.startsWith('/api/triages')) return json({ triages: [] })
    if (url.startsWith('/api/threats/feed')) return json({ items: [], sources: [], source_status: {}, topics: [], kev_cve_count: 0, last_refreshed_at: 1795000000, ttl_seconds: 1800 })
    return json({})
  }))
})

const OLD = {
  triage_id: 'TRG-2026-11-01-000000-abcdef', input_type: 'threat_name', input_ref: 'OldThreat', question: '',
  siem_preference: 'splunk', use_environment: false, created_at: '2026-11-01T00:00:00Z', status: 'done',
  headline: 'Old report', severity: 'low', prioritization_score: 10,
}

describe('Vulns → Triage deep link', () => {
  it('keeps the prefilled composer when triage history loads after mount', async () => {
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => { release = r })
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.startsWith('/api/triages')) { await gate; return json({ triages: [OLD] }) }
      if (url.startsWith('/api/threats/feed')) return json({ items: [], sources: [], source_status: {}, topics: [], kev_cve_count: 0, last_refreshed_at: 1795000000, ttl_seconds: 1800 })
      return json({})
    }))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/triage?threat=CVE-2026-0002']}>
            <Routes><Route path="/triage" element={<TriageView />} /></Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )
    await waitFor(() => expect(screen.getByDisplayValue('CVE-2026-0002')).toBeTruthy())
    release()
    await waitFor(() => expect(screen.getAllByText(/Old report|OldThreat/).length).toBeGreaterThan(0))
    expect(screen.getByDisplayValue('CVE-2026-0002')).toBeTruthy()
  })

  it('/triage?threat=CVE-… opens the composer prefilled with the CVE', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/triage?threat=CVE-2026-0001']}>
            <Routes><Route path="/triage" element={<TriageView />} /></Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )
    await waitFor(() => expect(screen.getByDisplayValue('CVE-2026-0001')).toBeTruthy())
    expect(screen.queryByText(/Create incident/i)).toBeNull()
    expect(screen.queryByText(/primus/i)).toBeNull()
  })
})
