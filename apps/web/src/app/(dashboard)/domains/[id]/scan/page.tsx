'use client'

import { use, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { scans, domains as domainsApi, ApiError } from '@/lib/api'
import type { ScanJob, SubdomainRow } from '@/lib/api'
import { Button } from '@/components/ui/Button'

const POLL_INTERVAL_MS = 3000
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled'])

export default function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const router = useRouter()

  const [domainName, setDomainName] = useState<string>('')
  const [job, setJob] = useState<ScanJob | null>(null)
  const [subdomains, setSubdomains] = useState<SubdomainRow[]>([])
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState<string | null>(null)
  const [fetchError, setFetchError] = useState<string | null>(null)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    domainsApi
      .get(id)
      .then((res) => setDomainName(res.domain.domain))
      .catch(() => setFetchError('Domain not found.'))
  }, [id])

  function stopPolling() {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  function startPolling(jobId: string) {
    stopPolling()
    pollRef.current = setInterval(async () => {
      try {
        const detail = await scans.get(jobId)
        setJob(detail.job)
        if (detail.job.status === 'completed') {
          setSubdomains(detail.subdomains)
        }
        if (TERMINAL_STATUSES.has(detail.job.status)) {
          stopPolling()
        }
      } catch {
        stopPolling()
      }
    }, POLL_INTERVAL_MS)
  }

  useEffect(() => () => stopPolling(), [])

  async function handleRunRecon() {
    setStartError(null)
    setStarting(true)
    try {
      const res = await scans.create(id, ['subdomains'])
      const initial: ScanJob = {
        id: res.job_id,
        domain_id: id,
        user_id: '',
        target: domainName,
        status: 'queued',
        progress: 0,
        config: { modules: ['subdomains'] },
        error_message: null,
        started_at: null,
        completed_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }
      setJob(initial)
      startPolling(res.job_id)
    } catch (err) {
      setStartError(
        err instanceof ApiError ? err.message : 'Failed to start scan.',
      )
    } finally {
      setStarting(false)
    }
  }

  const isRunning = job !== null && !TERMINAL_STATUSES.has(job.status)

  return (
    <div className="max-w-3xl">
      {/* Header */}
      <div className="mb-6 flex items-center gap-3">
        <button
          onClick={() => router.back()}
          className="text-slate-400 hover:text-slate-600 transition-colors"
        >
          ←
        </button>
        <div>
          <h1 className="text-2xl font-bold text-slate-900 font-mono">
            {domainName || id}
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">Subdomain enumeration</p>
        </div>
      </div>

      {fetchError && (
        <p className="mb-4 text-sm text-red-600">{fetchError}</p>
      )}

      {/* Run button */}
      {!job && (
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-8 text-center shadow-sm">
          <p className="text-slate-600 mb-5 text-sm">
            Passive subdomain enumeration via crt.sh. No active probing.
          </p>
          <Button
            onClick={handleRunRecon}
            loading={starting}
            disabled={starting}
          >
            Run Recon
          </Button>
          {startError && (
            <p className="mt-3 text-sm text-red-600">{startError}</p>
          )}
        </div>
      )}

      {/* Progress */}
      {job && (
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-5 shadow-sm mb-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-slate-700 capitalize">
              {job.status}
            </span>
            <span className="text-sm tabular-nums text-slate-500">
              {job.progress}%
            </span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-100 overflow-hidden">
            <div
              className="h-2 rounded-full bg-brand-500 transition-all duration-500"
              style={{ width: `${job.progress}%` }}
            />
          </div>

          {isRunning && (
            <p className="mt-3 text-xs text-slate-400 flex items-center gap-1.5">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-brand-400 animate-pulse" />
              Polling every 3 s…
            </p>
          )}

          {job.status === 'failed' && job.error_message && (
            <p className="mt-3 text-sm text-red-600">
              Error: {job.error_message}
            </p>
          )}

          {job.status === 'failed' && (
            <Button
              className="mt-4"
              variant="secondary"
              size="sm"
              onClick={() => {
                setJob(null)
                setSubdomains([])
                setStartError(null)
              }}
            >
              Retry
            </Button>
          )}
        </div>
      )}

      {/* Results table */}
      {job?.status === 'completed' && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-700">
              Subdomains found
            </h2>
            <span className="text-xs text-slate-400 tabular-nums">
              {subdomains.length} result{subdomains.length !== 1 ? 's' : ''}
            </span>
          </div>

          {subdomains.length === 0 ? (
            <p className="px-6 py-8 text-center text-sm text-slate-400">
              No subdomains found.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                    <th className="px-6 py-3">Hostname</th>
                    <th className="px-6 py-3">Resolved IP</th>
                    <th className="px-6 py-3">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {subdomains.map((s) => (
                    <tr
                      key={s.id}
                      className="hover:bg-slate-50 transition-colors"
                    >
                      <td className="px-6 py-3 font-mono text-slate-800">
                        {s.hostname}
                      </td>
                      <td className="px-6 py-3 font-mono text-slate-500">
                        {s.resolved_ip ?? (
                          <span className="text-slate-300">—</span>
                        )}
                      </td>
                      <td className="px-6 py-3 text-slate-400">{s.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
