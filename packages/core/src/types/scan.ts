export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

export type AuditAction =
  | 'domain_registered'
  | 'domain_verified'
  | 'domain_verification_failed'
  | 'scan_started'
  | 'scan_completed'
  | 'scan_failed'
  | 'scan_cancelled'
  | 'report_generated'

export interface ScanJob {
  id: string
  domain_id: string
  user_id: string
  target: string
  status: ScanStatus
  progress: number
  config: Record<string, unknown>
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface AuditLog {
  id: string
  user_id: string | null
  action: AuditAction
  target: string | null
  ip_address: string | null
  metadata: Record<string, unknown>
  created_at: string
}
