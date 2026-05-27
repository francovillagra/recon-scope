import type {
  AuthResponse,
  RegisterInput,
  LoginInput,
  Domain,
  DomainVerificationInstructions,
  VerificationMethod,
} from '@recon/core'

const BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3001'

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem('recon_token')
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${BASE}${path}`, { ...options, headers })

  if (res.status === 401) {
    localStorage.removeItem('recon_token')
    window.location.href = '/login'
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new ApiError(res.status, body.error ?? res.statusText)
  }

  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const auth = {
  register: (data: RegisterInput) =>
    request<AuthResponse>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  login: (data: LoginInput) =>
    request<AuthResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
}

// ── Domains ───────────────────────────────────────────────────────────────────

export const domains = {
  list: () =>
    request<{ domains: Domain[] }>('/api/v1/domains'),

  get: (id: string) =>
    request<{ domain: Domain; instructions: DomainVerificationInstructions }>(
      `/api/v1/domains/${id}`,
    ),

  create: (domain: string) =>
    request<{ domain: Domain; instructions: DomainVerificationInstructions }>(
      '/api/v1/domains',
      { method: 'POST', body: JSON.stringify({ domain }) },
    ),

  verify: (id: string, method: VerificationMethod) =>
    request<{
      domain: Domain
      already_verified?: boolean
      error?: string
      instructions?: DomainVerificationInstructions
    }>(`/api/v1/domains/${id}/verify`, {
      method: 'POST',
      body: JSON.stringify({ method }),
    }),

  remove: (id: string) =>
    request<void>(`/api/v1/domains/${id}`, { method: 'DELETE' }),
}

export { ApiError }
