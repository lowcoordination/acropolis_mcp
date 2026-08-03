import { useEffect, useRef, useState } from 'react'
import type { AuditEvent } from '../api/types'

const MAX_TAIL_EVENTS = 200

export function useAuditTail(paused: boolean) {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const sourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (paused) {
      sourceRef.current?.close()
      sourceRef.current = null
      return
    }

    const source = new EventSource('/api/v1/audit/tail')
    sourceRef.current = source

    source.onmessage = (e) => {
      try {
        const event: AuditEvent = JSON.parse(e.data)
        setEvents((prev) => [event, ...prev].slice(0, MAX_TAIL_EVENTS))
      } catch {
        // keepalive comment lines never reach onmessage; anything else malformed is ignored
      }
    }

    return () => {
      source.close()
      sourceRef.current = null
    }
  }, [paused])

  return events
}
