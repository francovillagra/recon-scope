'use client'

import Link from 'next/link'
import type { Domain } from '@recon/core'
import type { ScanJob } from '@/lib/api'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'

interface DomainCardProps {
  domain: Domain
  lastScan?: ScanJob
  onDelete?: (id: string) => void
}

export function DomainCard({ domain, lastScan, onDelete }: DomainCardProps) {
  const badgeVariant =
    domain.verification_status === 'verified'
      ? 'verified'
      : domain.verification_status === 'failed'
        ? 'failed'
        : 'pending'

  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm hover:shadow-md transition-shadow">
      <div className="flex items-center gap-4 min-w-0">
        <span className="font-mono text-slate-400 text-sm">◎</span>
        <div className="min-w-0">
          <p className="font-medium text-slate-900 truncate">{domain.domain}</p>
          <p className="text-xs text-slate-400 mt-0.5">
            Added {new Date(domain.created_at).toLocaleDateString()}
            {lastScan && (
              <span className="ml-2">
                · Last scan: {new Date(lastScan.created_at).toLocaleDateString()}
                <span
                  className={`ml-1 ${lastScan.status === 'completed' ? 'text-emerald-500' : lastScan.status === 'failed' ? 'text-red-400' : 'text-slate-400'}`}
                >
                  {lastScan.status}
                </span>
              </span>
            )}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 ml-4 shrink-0">
        <Badge variant={badgeVariant} />

        {domain.verification_status !== 'verified' && (
          <Link href={`/dashboard/domains/${domain.id}/verify`}>
            <Button size="sm" variant="secondary">
              Verify
            </Button>
          </Link>
        )}

        {domain.verification_status === 'verified' && lastScan?.status === 'completed' && (
          <Link
            href={`/dashboard/domains/${domain.id}/scan`}
            className="text-xs text-slate-500 hover:text-brand-600 transition-colors whitespace-nowrap"
          >
            Last scan →
          </Link>
        )}

        {domain.verification_status === 'verified' && (
          <Link href={`/dashboard/domains/${domain.id}/scan`}>
            <Button size="sm" variant="primary">
              Run Recon
            </Button>
          </Link>
        )}

        {onDelete && (
          <Button
            size="sm"
            variant="ghost"
            className="text-red-500 hover:text-red-700 hover:bg-red-50"
            onClick={() => onDelete(domain.id)}
          >
            Remove
          </Button>
        )}
      </div>
    </div>
  )
}
