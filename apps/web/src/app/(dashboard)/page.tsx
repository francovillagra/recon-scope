'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useAuth } from '@/providers/AuthProvider'
import { domains as domainsApi, scans as scansApi } from '@/lib/api'
import type { Domain } from '@recon/core'
import type { ScanJob } from '@/lib/api'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { DomainCard } from '@/components/domains/DomainCard'

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
  const [lastScans, setLastScans] = useState<Map<string, ScanJob>>(new Map())
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([domainsApi.list(), scansApi.list()])
      .then(([domainsRes, scanJobs]) => {
        setDomainList(domainsRes.domains)
        const map = new Map<string, ScanJob>()
        for (const job of scanJobs) {
          if (!map.has(job.domain_id)) {
            map.set(job.domain_id, job)
          }
        }
        setLastScans(map)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  function handleDelete(id: string) {
    domainsApi.remove(id).then(() => {
      setDomainList((prev) => prev.filter((d) => d.id !== id))
      setLastScans((prev) => {
        const next = new Map(prev)
        next.delete(id)
        return next
      })
    })
  }

  const verified = domainList.filter((d) => d.verification_status === 'verified').length
  const pending = domainList.filter((d) => d.verification_status === 'pending').length

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">Welcome back, {user?.email}</p>
        </div>
        <Link href="/dashboard/domains/new">
          <Button>+ Add Domain</Button>
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 mb-8">
        <StatCard label="Total Domains" value={loading ? '—' : domainList.length} sub="registered" />
        <StatCard label="Verified" value={loading ? '—' : verified} sub="ready to scan" />
        <StatCard label="Pending" value={loading ? '—' : pending} sub="awaiting verification" />
      </div>

      {/* Domain list */}
      {loading && <p className="text-sm text-slate-400">Loading…</p>}

      {!loading && domainList.length === 0 && (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white px-8 py-16 text-center">
          <p className="text-slate-500">No domains registered yet.</p>
          <Link href="/dashboard/domains/new">
            <Button className="mt-4" variant="secondary">
              Register your first domain
            </Button>
          </Link>
        </div>
      )}

      {!loading && domainList.length > 0 && (
        <div className="space-y-3">
          {domainList.map((d) => (
            <DomainCard
              key={d.id}
              domain={d}
              lastScan={lastScans.get(d.id)}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}
    </div>
  )
}
