const BASE = '/api/v1'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  })

  if (!resp.ok) {
    let detail = resp.statusText
    try {
      const body = await resp.json()
      // FastAPI's OWN validation errors (raised by a pydantic field/model_validator, as
      // opposed to a route's explicit HTTPException(detail="string")) shape `detail` as an
      // array of {msg, loc, ...} objects, not a string. Until now every 4xx in this app came
      // from an explicit HTTPException, so `body.detail` was always already a string — the
      // webhook_url model_validator (archon/schemas.py's SettingsUpdateRequest) is the first
      // validator error that can reach a client an operator actually looks at, and rendering
      // the raw object gave a literal "[object Object]" instead of the message.
      if (Array.isArray(body.detail)) {
        detail = body.detail.map((e: { msg?: string }) => e.msg ?? JSON.stringify(e)).join('; ')
      } else {
        detail = body.detail ?? detail
      }
    } catch {
      // body wasn't JSON — keep statusText
    }
    const isRead = (init?.method ?? 'GET') === 'GET'
    if (resp.status === 401 && isRead && window.location.pathname !== '/login') {
      // Session expired or was never established (e.g. a bookmarked/shared dashboard link) —
      // send the browser to the login screen instead of leaving every page to render its own
      // "could not load" error boundary, which looks like the app is broken rather than logged
      // out. Reads only: a 401 on a write (save policy, create key, etc.) means the user was
      // mid-action with real unsaved input on the page — hard-navigating away would silently
      // discard it. Those callers already get the thrown ApiError and handle it locally
      // (e.g. ServerDetail's savePolicy.onError), same as any other failed save.
      window.location.assign('/login')
    }
    throw new ApiError(resp.status, detail)
  }

  if (resp.status === 204) {
    return undefined as T
  }
  return resp.json() as Promise<T>
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, params?: Record<string, string>) => {
    const qs = params ? `?${new URLSearchParams(params)}` : ''
    return request<T>(`${path}${qs}`, { method: 'PATCH' })
  },
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}
