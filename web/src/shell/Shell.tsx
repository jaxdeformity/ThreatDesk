import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { ErrorBoundary } from '@/components/ErrorBoundary'

// ThreatDesk chrome: wordmark + four tabs. Same grid as the SOCbox shell
// (40px bar, scrolling main) so the ported views lay out unchanged.
const NAV_LINKS = [
  { path: '/vulns', label: 'Vulns' },
  { path: '/triage', label: 'Triage' },
  { path: '/intel', label: 'Intel' },
  { path: '/settings', label: 'Settings' },
] as const

export function Shell() {
  const navigate = useNavigate()
  const location = useLocation()
  const isActive = (p: string) => location.pathname === p || location.pathname.startsWith(p + '/')

  return (
    <div className="h-screen grid grid-rows-[40px_1fr] overflow-hidden bg-bg text-text">
      <header className="h-10 border-b border-hairline flex items-center px-4 gap-3">
        <span className="font-mono text-[11px] tracking-[0.12em] uppercase text-text-dim font-semibold select-none flex-shrink-0">
          <span className="text-accent">THREAT</span>DESK
        </span>
        <span className="text-hairline-strong font-light">▎</span>
        <nav className="flex items-center gap-0 flex-shrink-0" aria-label="Primary">
          {NAV_LINKS.map((link) => {
            const active = isActive(link.path)
            return (
              <button
                key={link.path}
                type="button"
                onClick={() => navigate(link.path)}
                className={`font-mono text-[10.5px] tracking-[0.1em] uppercase px-2 py-1 leading-none border-b-[2px] -mb-px transition-colors ${
                  active
                    ? 'text-accent border-accent font-semibold'
                    : 'text-text-dim border-transparent hover:text-text hover:border-hairline-strong'
                }`}
                aria-current={active ? 'page' : undefined}
              >
                {link.label}
              </button>
            )
          })}
        </nav>
        <div className="flex-1" />
        <span className="font-mono text-[9px] tracking-[0.1em] uppercase text-text-dim/60 select-none">local · single machine</span>
      </header>
      <main className="overflow-hidden flex flex-col min-w-0 min-h-0">
        <ErrorBoundary key={location.pathname.split('/')[1] || 'root'} label="ThreatDesk view">
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  )
}
