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
    if (url.startsWith('/api/threats/feed')) return json({ items: [], sources: [], fetched_at: null })
    return json({})
  }))
})

describe('Vulns → Triage deep link', () => {
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
