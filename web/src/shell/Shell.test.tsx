import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { Shell } from './Shell'

describe('ThreatDesk shell', () => {
  it('shows the four tabs and marks the active one', () => {
    render(
      <MemoryRouter initialEntries={['/vulns']}>
        <Routes><Route path="/" element={<Shell />}><Route path="vulns" element={<div>vulns body</div>} /></Route></Routes>
      </MemoryRouter>,
    )
    for (const t of ['Vulns', 'Triage', 'Intel', 'Settings']) expect(screen.getByRole('button', { name: t })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Vulns' }).getAttribute('aria-current')).toBe('page')
    expect(screen.getByText('vulns body')).toBeTruthy()
    expect(screen.queryByText(/POLARIS|SOC/)).toBeNull()
  })
})
