// Agent stream event shapes (triage SSE).

export type AgentEventKind =
  | 'session_started' | 'session_complete'
  | 'thinking' | 'text'
  | 'tool_call' | 'tool_result'
  | 'turn_started' | 'turn_done'
  | 'error' | 'raw'
  | 'triage_status'
  | 'model_fallback' | 'refusal_unresolved' | 'refusal'

export interface AgentEvent {
  id?: string
  kind: AgentEventKind
  ts?: string
  agent?: string
  model?: string
  session_id?: string
  text?: string
  tool_name?: string
  tool_id?: string
  input_preview?: string
  result_preview?: string
  is_error?: boolean
  message?: string
  cost_usd?: number
  duration_ms?: number
  num_turns?: number
  from_model?: string
  to_model?: string
}
