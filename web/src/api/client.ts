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
      detail = body.detail ?? detail
    } catch {
      // body wasn't JSON — keep statusText
    }
    if (resp.status === 401 && window.location.pathname !== '/login') {
      // Session expired or was never established (e.g. a bookmarked/shared dashboard link) —
      // send the browser to the login screen instead of leaving every page to render its own
      // "could not load" error boundary, which looks like the app is broken rather than logged out.
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
