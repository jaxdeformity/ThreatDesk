import * as TabsPrimitive from '@radix-ui/react-tabs'
import { cn } from '@/lib/cn'

export const Tabs = TabsPrimitive.Root

export function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      {...props}
      className={cn(
        'inline-flex items-center gap-0.5 border-b border-border',
        className,
      )}
    />
  )
}

export function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      {...props}
      className={cn(
        'px-3 py-2 text-xs font-medium uppercase tracking-wider',
        'text-ink-faint hover:text-ink-dim',
        'border-b-2 border-transparent -mb-px',
        'transition-colors',
        'data-[state=active]:text-accent data-[state=active]:border-accent',
        'focus-visible:outline-none',
        className,
      )}
    />
  )
}

export function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return (
    <TabsPrimitive.Content
      {...props}
      className={cn('outline-none focus-visible:outline-none', className)}
    />
  )
}
