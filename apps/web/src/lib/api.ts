import { clearSession } from '@/lib/auth'
import type {
  AuthResponse,
  RegisterInput,
  LoginInput,
  Domain,
  DomainVerificationInstructions,
  VerificationMethod,
} from '@recon/core'

const BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** Segundos que pide esperar el motor (encabezado Retry-After de un 429 o un 503). */
    public retryAfter?: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem('recon_token')
}

function waitText(seconds: number): string {
  return seconds < 90 ? `${seconds} seconds` : `${Math.ceil(seconds / 60)} minutes`
}

/**
 * Mensaje legible a partir del cuerpo de error del motor. Puede ser `{ detail: "texto" }` o, en un 422,
 * `{ detail: [{ loc, msg }] }`. (Antes se leía `body.error`, que el motor nunca manda: todos los errores
 * aparecían como "Unauthorized", "Conflict", "Bad Request"...)
 */
export function errorMessage(body: unknown, fallback: string): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (!item || typeof item !== 'object') return ''
        const { msg, loc } = item as { msg?: unknown; loc?: unknown }
        if (typeof msg !== 'string') return ''
        const text = msg.replace(/^Value error, /, '')
        const field = Array.isArray(loc) ? loc[loc.length - 1] : undefined
        return typeof field === 'string' && !text.toLowerCase().includes(field.toLowerCase())
          ? `${field}: ${text}`
          : text
      })
      .filter(Boolean)
    if (messages.length) return messages.join(' ')
  }
  return fallback
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

  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, { ...options, headers })
  } catch {
    throw new ApiError(0, 'Could not reach the server. Check your connection and try again.')
  }

  // Una sesión que venció se detecta con un token enviado y rechazado. En /auth/* un 401 es "credenciales
  // incorrectas": ahí hay que mostrar el error, no recargar la página de login como si nada hubiera pasado.
  if (res.status === 401 && token && !path.startsWith('/api/v1/auth/')) {
    clearSession()
    window.location.href = '/login'
    throw new ApiError(401, 'Your session expired. Please sign in again.')
  }

  if (!res.ok) {
    const body = await res.json().catch(() => null)
    const retryAfter = Number(res.headers.get('Retry-After'))
    const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined
    let message = errorMessage(body, res.statusText || `Request failed (${res.status})`)
    if (wait && (res.status === 429 || res.status === 503)) message += ` Try again in ${waitText(wait)}.`
    throw new ApiError(res.status, message, wait)
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

/** Lo que devuelve POST /domains (no incluye el dominio completo: solo su id y cómo verificarlo). */
export interface CreateDomainResult {
  domain_id: string
  verification_token: string
  dns_instructions: { record_type: string; name: string; value: string }
  well_known_instructions: { url: string; value: string }
}

export const domains = {
  list: () =>
    request<{ domains: Domain[] }>('/api/v1/domains'),

  get: (id: string) =>
    request<{ domain: Domain; instructions: DomainVerificationInstructions }>(
      `/api/v1/domains/${id}`,
    ),

  create: (domain: string) =>
    request<CreateDomainResult>('/api/v1/domains', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),

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

  history: (id: string) =>
    request<ScanHistoryEntry[]>(`/api/v1/domains/${id}/history`),
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

export interface HttpFingerprintRow {
  id: string
  url: string
  status_code: number | null
  server_header: string | null
  title: string | null
  created_at: string
}

export interface TechnologyRow {
  id: string
  name: string
  category: string | null
  version: string | null
  confidence: number | null
  created_at: string
}

export interface TlsCertRow {
  id: string
  host: string
  issuer: string | null
  subject: string | null
  valid_from: string | null
  valid_to: string | null
  is_valid: boolean | null
  signature_algorithm: string | null
  san: string[]
  created_at: string
}

export interface FindingRow {
  id: string
  category: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string | null
  evidence: Record<string, unknown>
  created_at: string
}

export interface ScanDetail {
  job: ScanJob
  subdomains: SubdomainRow[]
  ports: PortRow[]
  http_fingerprints: HttpFingerprintRow[]
  technologies: TechnologyRow[]
  tls_certificates: TlsCertRow[]
  findings: FindingRow[]
}

export interface ScanCreateOptions {
  modules?: string[]          // e.g. ['subdomains','ports','fingerprint']
  port_range?: 'top-100' | 'top-1000' | 'full'
  timeout_seconds?: number    // 1–60; el motor rechaza otros valores
}

export interface FindingsBySeverity {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface ScanHistoryEntry {
  id: string
  status: string
  created_at: string
  completed_at: string | null
  config: Record<string, unknown>
  subdomains_count: number
  open_ports_count: number
  findings_by_severity: FindingsBySeverity
}

export const scans = {
  create: (domain_id: string, opts: ScanCreateOptions = {}) =>
    request<{ job_id: string; status: string }>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({
        domain_id,
        modules: opts.modules ?? ['subdomains'],
        port_range: opts.port_range ?? 'top-1000',
        timeout_seconds: opts.timeout_seconds ?? 30,
      }),
    }),

  list: () => request<ScanJob[]>('/api/v1/scans'),

  get: (job_id: string) => request<ScanDetail>(`/api/v1/scans/${job_id}`),

  exportJson: async (job_id: string): Promise<void> => {
    const token = getToken()
    const res = await fetch(`${BASE}/api/v1/scans/${job_id}/export/json`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) throw new ApiError(res.status, 'Export failed')
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const cd = res.headers.get('content-disposition') ?? ''
    const match = cd.match(/filename="([^"]+)"/)
    a.download = match ? match[1] : `recon-export-${job_id}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  },
}

export { ApiError }
