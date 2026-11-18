import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import { cn } from '@/lib/cn'

export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger

export function DialogContent({
  children,
  className,
  size = 'md',
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Content> & {
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'drawer'
}) {
  const sizes = {
    sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl', xl: 'max-w-4xl',
    // The drawer hosts the VQL editor + results, the dispatch modal,
    // and other inspector surfaces. Cap at 1100px and let it fill up
    // to 60vw on wide displays, so 4K monitors don't squeeze the
    // editor into a 700px column.
    drawer: 'w-[min(60vw,1100px)] right-0 h-full left-auto translate-x-0 top-0 translate-y-0 rounded-none border-l',
  }
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm animate-fade-in" />
      <DialogPrimitive.Content
        {...props}
        className={cn(
          'fixed z-50 bg-surface border border-border rounded-lg shadow-2xl shadow-black/50',
          size === 'drawer'
            ? `${sizes.drawer} animate-slide-in-right`
            : `top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[calc(100vw-2rem)] ${sizes[size]} animate-fade-in`,
          className,
        )}
      >
        {children}
        <DialogPrimitive.Close className={cn(
          'absolute top-3 right-3 p-1.5 rounded text-ink-dim hover:text-ink hover:bg-surface2 transition',
        )}>
          <X className="w-4 h-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogHeader({ children, className }: React.PropsWithChildren<{ className?: string }>) {
  return <div className={cn('px-6 py-4 border-b border-border', className)}>{children}</div>
}
export function DialogTitle({ children, className }: React.PropsWithChildren<{ className?: string }>) {
  return <DialogPrimitive.Title className={cn('text-lg font-semibold text-ink', className)}>{children}</DialogPrimitive.Title>
}
export function DialogDescription({ children, className }: React.PropsWithChildren<{ className?: string }>) {
  return <DialogPrimitive.Description className={cn('text-sm text-ink-dim mt-1', className)}>{children}</DialogPrimitive.Description>
}
export function DialogBody({ children, className }: React.PropsWithChildren<{ className?: string }>) {
  return <div className={cn('px-6 py-4', className)}>{children}</div>
}
export function DialogFooter({ children, className }: React.PropsWithChildren<{ className?: string }>) {
  return <div className={cn('px-6 py-3 border-t border-border flex items-center justify-end gap-2 bg-bg/30', className)}>{children}</div>
}
