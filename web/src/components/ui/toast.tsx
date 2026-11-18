import * as ToastPrimitive from '@radix-ui/react-toast'
import { createContext, useContext, useState, useCallback } from 'react'
import { CheckCircle2, XCircle, AlertTriangle, X } from 'lucide-react'
import { cn } from '@/lib/cn'

type ToastKind = 'success' | 'error' | 'warning' | 'info'

interface ToastItem {
  id: number
  kind: ToastKind
  title: string
  description?: string
}

interface ToastCtx {
  toast: (k: ToastKind, title: string, description?: string) => void
}

const Ctx = createContext<ToastCtx>({ toast: () => {} })

export function ToastProvider({ children }: React.PropsWithChildren) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const toast = useCallback((kind: ToastKind, title: string, description?: string) => {
    setToasts(ts => [...ts, { id: Date.now() + Math.random(), kind, title, description }])
  }, [])
  const dismiss = (id: number) => setToasts(ts => ts.filter(t => t.id !== id))

  return (
    <Ctx.Provider value={{ toast }}>
      <ToastPrimitive.Provider swipeDirection="right">
        {children}
        {toasts.map(t => {
          const Icon = t.kind === 'success' ? CheckCircle2 :
                       t.kind === 'error'   ? XCircle :
                       t.kind === 'warning' ? AlertTriangle : CheckCircle2
          const hue = t.kind === 'success' ? 'text-success' :
                      t.kind === 'error'   ? 'text-danger' :
                      t.kind === 'warning' ? 'text-warning' : 'text-info'
          return (
            <ToastPrimitive.Root
              key={t.id}
              onOpenChange={(open) => { if (!open) dismiss(t.id) }}
              className="data-[state=open]:animate-slide-in-right data-[state=closed]:animate-fade-in
                         bg-surface border border-border rounded-lg shadow-xl p-3 pr-8 w-[320px] flex gap-2.5"
            >
              <Icon className={cn('w-5 h-5 mt-0.5 flex-shrink-0', hue)} />
              <div className="flex-1 min-w-0">
                <ToastPrimitive.Title className="text-sm font-medium text-ink">{t.title}</ToastPrimitive.Title>
                {t.description && (
                  <ToastPrimitive.Description className="text-xs text-ink-dim mt-0.5">{t.description}</ToastPrimitive.Description>
                )}
              </div>
              <ToastPrimitive.Close className="absolute top-2 right-2 p-1 rounded text-ink-dim hover:text-ink hover:bg-surface2">
                <X className="w-3.5 h-3.5" />
              </ToastPrimitive.Close>
            </ToastPrimitive.Root>
          )
        })}
      </ToastPrimitive.Provider>
    </Ctx.Provider>
  )
}

export function ToastViewport() {
  return <ToastPrimitive.Viewport className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 outline-none" />
}

export function useToast() {
  return useContext(Ctx)
}
