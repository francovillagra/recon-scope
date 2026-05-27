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

// ── Scans ─────────────────────────────────────────────────────────────────────

export interface SubdomainRow {
  id: string
  hostname: string
  source: string
  resolved_ip: string | null
  created_at: string
}

export interface PortRow {
  id: string
  host: string
  port: number
  protocol: string
  state: string
  service: string | null
  banner: string | null
  created_at: string
}

export interface ScanJob {
  id: string
  domain_id: string
  user_id: string
  target: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  config: Record<string, unknown>
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface ScanDetail {
  job: ScanJob
  subdomains: SubdomainRow[]
  ports: PortRow[]
}

export interface ScanCreateOptions {
  modules?: string[]
  port_range?: 'top-100' | 'top-1000' | 'full'
  passive_only?: boolean
  timeout_seconds?: number
}

export const scans = {
  create: (domain_id: string, opts: ScanCreateOptions = {}) =>
    request<{ job_id: string; status: string }>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({
        domain_id,
        modules: opts.modules ?? ['subdomains'],
        port_range: opts.port_range ?? 'top-1000',
        passive_only: opts.passive_only ?? true,
        timeout_seconds: opts.timeout_seconds ?? 30,
      }),
    }),

  list: () => request<ScanJob[]>('/api/v1/scans'),

  get: (job_id: string) => request<ScanDetail>(`/api/v1/scans/${job_id}`),
}

export { ApiError }
