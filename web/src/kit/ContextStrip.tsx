// View-identity strip. Sits at the top of every view; reads
// "{VIEW NAME} // {QUALIFIER}  {dim subtitle}" with right-aligned actions.
// Spec: docs/superpowers/specs/2026-04-27-socbox-redesign-design.md §3.5, §5

import type { ReactNode } from 'react'

export type CtxAction = {
  key?: string
  label: string
  onClick?: () => void
}

export function ContextStrip({
  title,
  subtitle,
  actions = [],
  className = '',
}: {
  title: ReactNode
  subtitle?: ReactNode
  actions?: CtxAction[]
  className?: string
}) {
  return (
    <div
      className={`flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-bg flex-shrink-0 ${className}`}
    >
      <div className="font-mono text-[11px] tracking-[0.12em] uppercase text-text font-semibold flex items-center gap-2 truncate">
        <span>{title}</span>
        {subtitle && (
          <>
            <span className="text-hairline-strong font-normal">//</span>
            <span className="text-text-dim font-normal">{subtitle}</span>
          </>
        )}
      </div>
      <div className="flex items-center gap-3.5 text-[11px] flex-shrink-0">
        {actions.map((a, i) => (
          <button
            key={i}
            type="button"
            onClick={a.onClick}
            className="text-text-dim hover:text-accent tracking-[0.08em] uppercase font-mono inline-flex items-center"
          >
            {a.key && (
              <kbd className="text-text bg-surface2 border border-hairline px-1 py-0.5 mr-1.5 font-mono text-[10px] leading-none">
                {a.key}
              </kbd>
            )}
            {a.label}
          </button>
        ))}
      </div>
    </div>
  )
}
