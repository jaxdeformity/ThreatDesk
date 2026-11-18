import { Component, type ReactNode } from 'react'
import { AlertOctagon } from 'lucide-react'

/**
 * Minimal error boundary so render crashes don't just blank the
 * screen. Shows the error + component stack trace inline so the
 * analyst (or the dev team) can paste it straight into a bug report
 * instead of opening devtools.
 *
 * Reset key: when the user navigates to a new view we bump the key
 * prop; that re-mounts the boundary and clears prior errors.
 */
interface Props {
  children: ReactNode
  label?: string   // e.g. "Triage view", included in the UI error message
}
interface State {
  error: Error | null
  info: string | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: null }

  static getDerivedStateFromError(error: Error): State {
    return { error, info: null }
  }

  componentDidCatch(error: Error, info: { componentStack?: string }) {
    this.setState({ error, info: info.componentStack || null })
    // Surface it on the console too so devtools picks it up with its
    // usual source-mapped stack, not the React-condensed one.
    // eslint-disable-next-line no-console
    console.error('[ErrorBoundary]', this.props.label || '(unlabeled)', error, info)
  }

  render() {
    if (!this.state.error) return this.props.children
    const e = this.state.error
    return (
      <div className="h-full overflow-y-auto p-6">
        <div className="max-w-3xl mx-auto border border-danger/40 rounded-md bg-danger/5 p-5">
          <div className="flex items-start gap-3">
            <AlertOctagon className="w-5 h-5 text-danger flex-shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <h2 className="text-base font-semibold text-ink mb-1">
                {this.props.label ? `${this.props.label} crashed` : 'Something crashed'}
              </h2>
              <div className="text-sm text-ink-dim mb-3">
                A render error took down this view. The rest of the app is still
                running, switch to another tab or reload. Copy the trace below
                into a bug report.
              </div>
              <pre className="text-2xs font-mono bg-bg border border-border rounded p-3 overflow-x-auto whitespace-pre-wrap break-words text-danger">
{e.name}: {e.message}
{'\n\n'}{e.stack || '(no stack)'}
{this.state.info ? `\n\n--- component stack ---\n${this.state.info}` : ''}
              </pre>
              <button
                className="btn btn-secondary mt-3"
                onClick={() => this.setState({ error: null, info: null })}
              >
                Retry render
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }
}
