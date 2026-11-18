import { useEffect, useReducer, useRef } from 'react'
import type { TriageDetail } from '@/api/client'
import type { AgentEvent } from '@/api/types'

/**
 * Subscribe to /api/triage/:id/stream as SSE. The backend replays
 * events.jsonl on connect, pushes a snapshot, then streams live runner
 * events until the agent exits with a final `triage_status` event
 * (done|error) and a `done` sentinel.
 *
 * State shape roughly mirrors the TriageDetail payload so consumers
 * can read current report_md / result with no extra fetch.
 */

export interface TriageStreamState {
  connected: boolean
  status: 'pending' | 'running' | 'done' | 'error' | 'unknown'
  error: string | null
  input: TriageDetail['input'] | null
  result: TriageDetail['result']
  reportMd: string | null
  liveEvents: AgentEvent[]
  lastEventAt: number | null
  completed: boolean
}

type Action =
  | { type: 'reset' }
  | { type: 'connected'; payload: boolean }
  | { type: 'snapshot'; payload: TriageDetail }
  | { type: 'event'; payload: AgentEvent & Record<string, unknown> }
  | { type: 'completed' }

const MAX_EVENTS = 300

const initial: TriageStreamState = {
  connected: false,
  status: 'unknown',
  error: null,
  input: null,
  result: null,
  reportMd: null,
  liveEvents: [],
  lastEventAt: null,
  completed: false,
}

function reducer(state: TriageStreamState, action: Action): TriageStreamState {
  switch (action.type) {
    case 'reset':
      return initial
    case 'connected':
      return { ...state, connected: action.payload }
    case 'snapshot': {
      const { input, status, result, report_md } = action.payload
      return {
        ...state,
        input: input || state.input,
        status: (status?.status as TriageStreamState['status']) || state.status,
        error: status?.error || null,
        result: result ?? state.result,
        reportMd: report_md ?? state.reportMd,
      }
    }
    case 'event': {
      const ev = action.payload
      const now = Date.now()
      let events = state.liveEvents
      let status = state.status
      let err = state.error

      // Handle triage_status event specially, it updates lifecycle state.
      if (ev.kind === 'triage_status') {
        status = (ev.status as TriageStreamState['status']) || status
        err = (ev.error as string | null) ?? err
      }

      // Pair tool_result with its tool_call, in place.
      if (ev.kind === 'tool_result' && (ev as { tool_id?: string }).tool_id) {
        events = events.map(e =>
          (e.kind === 'tool_call' && e.tool_id === (ev as { tool_id?: string }).tool_id)
            ? { ...e, resolved: true, result_preview: (ev as { result_preview?: string }).result_preview, is_error: !!(ev as { is_error?: boolean }).is_error }
            : e,
        )
      } else {
        events = [...events, ev as AgentEvent]
      }
      if (events.length > MAX_EVENTS) events = events.slice(-MAX_EVENTS)

      return { ...state, liveEvents: events, lastEventAt: now, status, error: err }
    }
    case 'completed':
      return { ...state, completed: true }
  }
}

export function useTriageStream(triageId?: string): TriageStreamState {
  const [state, dispatch] = useReducer(reducer, initial)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!triageId) return
    dispatch({ type: 'reset' })

    const url = `/api/triage/${encodeURIComponent(triageId)}/stream`
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => dispatch({ type: 'connected', payload: true })
    es.onerror = () => dispatch({ type: 'connected', payload: false })

    es.addEventListener('snapshot', (ev: MessageEvent) => {
      try { dispatch({ type: 'snapshot', payload: JSON.parse(ev.data) }) }
      catch { /* ignore */ }
    })
    es.addEventListener('agent_event', (ev: MessageEvent) => {
      try { dispatch({ type: 'event', payload: JSON.parse(ev.data) }) }
      catch { /* ignore */ }
    })
    es.addEventListener('done', () => {
      dispatch({ type: 'completed' })
      es.close()
    })
    es.addEventListener('ping', () => { /* keep-alive */ })

    return () => { es.close(); esRef.current = null }
  }, [triageId])

  return state
}
