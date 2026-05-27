'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useAuth } from '@/providers/AuthProvider'
import { domains as domainsApi } from '@/lib/api'
import type { Domain } from '@recon/core'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'

function StatCard({
  label,
  value,
  sub,
}: {
  label: string
  value: number | string
  sub?: string
}) {
  return (
    <Card>
      <CardBody>
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
        <p className="mt-1 text-3xl font-bold text-slate-900">{value}</p>
        {sub && <p className="mt-0.5 text-xs text-slate-400">{sub}</p>}
      </CardBody>
    </Card>
  )
}

export default function DashboardOverview() {
  const { user } = useAuth()
  const [domainList, setDomainList] = useState<Domain[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    domainsApi
      .list()
      .then((res) => setDomainList(res.domains))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const verified = domainList.filter((d) => d.verification_status === 'verified').length
  const pending = domainList.filter((d) => d.verification_status === 'pending').length

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Overview</h1>
          <p className="mt-1 text-sm text-slate-500">
            Welcome back, {user?.email}
          </p>
        </div>
        <Link href="/dashboard/domains/new">
          <Button>+ Add Domain</Button>
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 mb-8">
        <StatCard
          label="Total Domains"
          value={loading ? '—' : domainList.length}
          sub="registered"
        />
        <StatCard
          label="Verified"
          value={loading ? '—' : verified}
          sub="ready to scan"
        />
        <StatCard
          label="Pending Verification"
          value={loading ? '—' : pending}
          sub="awaiting DNS / file check"
        />
      </div>

      {/* Phase notice */}
      <Card>
        <CardBody>
          <div className="flex items-start gap-4">
            <span className="text-2xl">⬡</span>
            <div>
              <h2 className="font-semibold text-slate-900">Phase 0 — Foundation</h2>
              <p className="mt-1 text-sm text-slate-600">
                Domain ownership verification is active. Scanning modules will be
                available in Phase 1 (subdomain enumeration) and beyond. All domains
                must be verified before any scan can be started.
              </p>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  )
}
