'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import type { Domain } from '@recon/core'
import { domains as domainsApi } from '@/lib/api'
import { DomainCard } from '@/components/domains/DomainCard'
import { Button } from '@/components/ui/Button'

export default function DomainsPage() {
  const [domainList, setDomainList] = useState<Domain[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function load() {
    try {
      const res = await domainsApi.list()
      setDomainList(res.domains)
    } catch {
      setError('Failed to load domains.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleDelete(id: string) {
    if (!confirm('Remove this domain?')) return
    try {
      await domainsApi.remove(id)
      setDomainList((prev) => prev.filter((d) => d.id !== id))
    } catch {
      alert('Delete failed.')
    }
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-900">Domains</h1>
        <Link href="/dashboard/domains/new">
          <Button>+ Add Domain</Button>
        </Link>
      </div>

      {loading && (
        <p className="text-sm text-slate-400">Loading…</p>
      )}

      {error && (
        <p className="text-sm text-red-600">{error}</p>
      )}

      {!loading && !error && domainList.length === 0 && (
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
            <DomainCard key={d.id} domain={d} onDelete={handleDelete} />
          ))}
        </div>
      )}
    </div>
  )
}
