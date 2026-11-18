import '@testing-library/jest-dom'

// jsdom has no ResizeObserver; cmdk (the ⌘K command palette) uses it.
if (!('ResizeObserver' in globalThis)) {
  class ResizeObserverPolyfill {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = ResizeObserverPolyfill
}

// jsdom doesn't implement scrollIntoView; cmdk calls it on the active item.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = function scrollIntoView() {}
}

// jsdom has no EventSource; useTriageStream (the per-triage SSE hook)
// constructs one on mount. A no-op shim keeps tests that mount it from
// throwing — they assert on REST/derived state, not the live tail.
if (!('EventSource' in globalThis)) {
  class EventSourceShim {
    static readonly CONNECTING = 0
    static readonly OPEN = 1
    static readonly CLOSED = 2
    readonly url: string
    readyState = EventSourceShim.CONNECTING
    onopen: ((ev: Event) => unknown) | null = null
    onmessage: ((ev: MessageEvent) => unknown) | null = null
    onerror: ((ev: Event) => unknown) | null = null
    constructor(url: string | URL) {
      this.url = String(url)
    }
    addEventListener() {}
    removeEventListener() {}
    dispatchEvent() {
      return false
    }
    close() {
      this.readyState = EventSourceShim.CLOSED
    }
  }
  ;(globalThis as { EventSource?: unknown }).EventSource = EventSourceShim
}
