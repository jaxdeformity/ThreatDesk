import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Card, type VulnCard } from './VulnsView'

vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }))

const exposure = {
  label: 'Exchange Server Subscription Edition SE RTM',
  assets: [], products: 1, asset_count: 18, crown_jewel: true, internet_facing: true,
  owners: ['Messaging Engineering'], covered: false,
}

const base: VulnCard = {
  cve: 'CVE-2026-1001', title: 'Exchange RCE', vendor: 'Microsoft', product: 'Exchange Server', summary: '',
  kev: true, date_added: new Date().toISOString().slice(0, 10),
  due_date: new Date(Date.now() - 3 * 86400000).toISOString().slice(0, 10),
  ransomware: true, org_match: exposure.label, exposure, news_mentions: 2, tracking: null,
  epss: { score: 0.42, percentile: 0.99 },
}

describe('vulnerability card', () => {
  it('shows where it runs, how exposed, exploitation and the overdue fix-by date', () => {
    const onOpen = vi.fn()
    render(<Card c={base} onOpen={onOpen} />)
    for (const t of ['Crown jewel', 'Internet-facing', 'Exploited in the wild', 'Ransomware', 'Not started', 'New', 'EPSS 42%',
                     'Exchange Server Subscription Edition SE RTM']) {
      expect(screen.getByText(t)).toBeTruthy()
    }
    expect(screen.getByText(/18 assets · Messaging Engineering/)).toBeTruthy()
    expect(screen.getByText(/2 in the news/)).toBeTruthy()
    expect(screen.getByText(/fix-by date passed 3 days ago/)).toBeTruthy()
    fireEvent.click(screen.getByTestId('vuln-card'))
    expect(onOpen).toHaveBeenCalled()
  })

  it('marks a CVE the deployed version already fixes and drops the urgency', () => {
    render(<Card c={{ ...base, exposure: { ...exposure, covered: true } }} onOpen={() => {}} />)
    expect(screen.getByText('Fixed in deployed version')).toBeTruthy()
    expect(screen.queryByText('Crown jewel')).toBeNull()
    expect(screen.queryByText(/fix-by date/)).toBeNull()
  })

  it('hides the deadline once remediated', () => {
    render(<Card c={{ ...base, tracking: 'patched' }} onOpen={() => {}} />)
    expect(screen.getByText('Patched')).toBeTruthy()
    expect(screen.queryByText(/fix-by date/)).toBeNull()
  })
})
