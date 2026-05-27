'use client'

import { use, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { scans, domains as domainsApi, ApiError } from '@/lib/api'
import type {
  ScanJob,
  SubdomainRow,
  PortRow,
  HttpFingerprintRow,
  TechnologyRow,
  TlsCertRow,
  FindingRow,
  ScanCreateOptions,
} from '@/lib/api'
import { Button } from '@/components/ui/Button'

const POLL_INTERVAL_MS = 3000
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled'])

type PortRange = 'top-100' | 'top-1000' | 'full'

const PORT_RANGE_LABELS: Record<PortRange, string> = {
  'top-100': 'Top 100',
  'top-1000': 'Top 1000',
  'full': 'Full (1–65535, slow)',
}

type Severity = FindingRow['severity']

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-blue-100 text-blue-700',
  info: 'bg-slate-100 text-slate-600',
}

function ConfidenceBadge({ value }: { value: number | null }) {
  if (value === null) return <span className="text-slate-300">—</span>
  const cls =
    value >= 80
      ? 'bg-emerald-100 text-emerald-700'
      : value >= 50
        ? 'bg-yellow-100 text-yellow-700'
        : 'bg-slate-100 text-slate-500'
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {value}%
    </span>
  )
}

function ValidBadge({ value }: { value: boolean | null }) {
  if (value === null) return <span className="text-slate-300">—</span>
  return value ? (
    <span className="inline-block rounded px-1.5 py-0.5 text-xs font-medium bg-emerald-100 text-emerald-700">
      Valid
    </span>
  ) : (
    <span className="inline-block rounded px-1.5 py-0.5 text-xs font-medium bg-red-100 text-red-700">
      Invalid
    </span>
  )
}

export default function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const router = useRouter()

  const [domainName, setDomainName] = useState('')
  const [job, setJob] = useState<ScanJob | null>(null)
  const [subdomains, setSubdomains] = useState<SubdomainRow[]>([])
  const [ports, setPorts] = useState<PortRow[]>([])
  const [fingerprints, setFingerprints] = useState<HttpFingerprintRow[]>([])
  const [technologies, setTechnologies] = useState<TechnologyRow[]>([])
  const [tlsCerts, setTlsCerts] = useState<TlsCertRow[]>([])
  const [findings, setFindings] = useState<FindingRow[]>([])

  // Config options
  const [modSubdomains, setModSubdomains] = useState(true)
  const [modPorts, setModPorts] = useState(true)
  const [modFingerprint, setModFingerprint] = useState(true)
  const [portRange, setPortRange] = useState<PortRange>('top-1000')

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
          setPorts(detail.ports)
          setFingerprints(detail.http_fingerprints)
          setTechnologies(detail.technologies)
          setTlsCerts(detail.tls_certificates)
          setFindings(detail.findings)
        }
        if (TERMINAL_STATUSES.has(detail.job.status)) stopPolling()
      } catch {
        stopPolling()
      }
    }, POLL_INTERVAL_MS)
  }

  useEffect(() => () => stopPolling(), [])

  async function handleRunRecon() {
    if (!modSubdomains && !modPorts && !modFingerprint) {
      setStartError('Select at least one module.')
      return
    }
    setStartError(null)
    setStarting(true)

    const modules: string[] = []
    if (modSubdomains) modules.push('subdomains')
    if (modPorts) modules.push('ports')
    if (modFingerprint) modules.push('fingerprint')

    const opts: ScanCreateOptions = {
      modules,
      port_range: portRange,
      passive_only: true,
      timeout_seconds: 30,
    }

    try {
      const res = await scans.create(id, opts)
      const initial: ScanJob = {
        id: res.job_id,
        domain_id: id,
        user_id: '',
        target: domainName,
        status: 'queued',
        progress: 0,
        config: { modules, port_range: portRange },
        error_message: null,
        started_at: null,
        completed_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }
      setJob(initial)
      startPolling(res.job_id)
    } catch (err) {
      setStartError(err instanceof ApiError ? err.message : 'Failed to start scan.')
    } finally {
      setStarting(false)
    }
  }

  const isRunning = job !== null && !TERMINAL_STATUSES.has(job.status)
  const noModSelected = !modSubdomains && !modPorts && !modFingerprint

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
          <p className="text-sm text-slate-500 mt-0.5">Reconnaissance scan</p>
        </div>
      </div>

      {fetchError && <p className="mb-4 text-sm text-red-600">{fetchError}</p>}

      {/* Config + run button */}
      {!job && (
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-6 shadow-sm space-y-5">
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Modules
            </p>
            <div className="flex flex-col gap-2">
              <ModuleCheckbox
                checked={modSubdomains}
                onChange={setModSubdomains}
                label="Subdomain Enumeration"
                hint="passive, crt.sh"
              />
              <ModuleCheckbox
                checked={modPorts}
                onChange={setModPorts}
                label="Port Scan"
                hint="TCP connect, asyncio"
              />
              <ModuleCheckbox
                checked={modFingerprint}
                onChange={setModFingerprint}
                label="Fingerprint"
                hint="HTTP headers, tech stack, TLS"
              />
            </div>
          </div>

          {modPorts && (
            <div>
              <label
                htmlFor="port-range"
                className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2"
              >
                Port Range
              </label>
              <select
                id="port-range"
                value={portRange}
                onChange={(e) => setPortRange(e.target.value as PortRange)}
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {(Object.keys(PORT_RANGE_LABELS) as PortRange[]).map((k) => (
                  <option key={k} value={k}>
                    {PORT_RANGE_LABELS[k]}
                  </option>
                ))}
              </select>
            </div>
          )}

          <Button
            onClick={handleRunRecon}
            loading={starting}
            disabled={starting || noModSelected}
          >
            Run Recon
          </Button>

          {startError && <p className="text-sm text-red-600">{startError}</p>}
        </div>
      )}

      {/* Progress */}
      {job && (
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-5 shadow-sm mb-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-slate-700 capitalize">{job.status}</span>
            <span className="text-sm tabular-nums text-slate-500">{job.progress}%</span>
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
            <p className="mt-3 text-sm text-red-600">Error: {job.error_message}</p>
          )}
          {job.status === 'failed' && (
            <Button
              className="mt-4"
              variant="secondary"
              size="sm"
              onClick={() => {
                setJob(null)
                setSubdomains([])
                setPorts([])
                setFingerprints([])
                setTechnologies([])
                setTlsCerts([])
                setFindings([])
                setStartError(null)
              }}
            >
              Retry
            </Button>
          )}
        </div>
      )}

      {/* Results */}
      {job?.status === 'completed' && (
        <div className="space-y-6">
          {/* Subdomains */}
          <ResultTable
            title="Subdomains found"
            count={subdomains.length}
            empty="No subdomains found."
            headers={['Hostname', 'Resolved IP', 'Source']}
          >
            {subdomains.map((s) => (
              <tr key={s.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-3 font-mono text-slate-800">{s.hostname}</td>
                <td className="px-6 py-3 font-mono text-slate-500">
                  {s.resolved_ip ?? <span className="text-slate-300">—</span>}
                </td>
                <td className="px-6 py-3 text-slate-400">{s.source}</td>
              </tr>
            ))}
          </ResultTable>

          {/* Open ports */}
          <ResultTable
            title="Open ports"
            count={ports.length}
            empty="No open ports found."
            headers={['Host', 'Port', 'Service', 'Banner']}
          >
            {ports.map((p) => (
              <tr key={p.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-3 font-mono text-slate-800">{p.host}</td>
                <td className="px-6 py-3 font-mono text-slate-700">
                  {p.port}
                  <span className="ml-1 text-xs text-slate-400">/{p.protocol}</span>
                </td>
                <td className="px-6 py-3 text-slate-500">
                  {p.service ?? <span className="text-slate-300">—</span>}
                </td>
                <td className="px-6 py-3 font-mono text-xs text-slate-400 max-w-xs truncate">
                  {p.banner ?? <span className="text-slate-300">—</span>}
                </td>
              </tr>
            ))}
          </ResultTable>

          {/* Technologies */}
          <ResultTable
            title="Technologies detected"
            count={technologies.length}
            empty="No technologies detected."
            headers={['Name', 'Category', 'Version', 'Confidence']}
          >
            {technologies.map((t) => (
              <tr key={t.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-3 font-medium text-slate-800">{t.name}</td>
                <td className="px-6 py-3 text-slate-500">{t.category ?? <span className="text-slate-300">—</span>}</td>
                <td className="px-6 py-3 font-mono text-slate-500">
                  {t.version ?? <span className="text-slate-300">—</span>}
                </td>
                <td className="px-6 py-3">
                  <ConfidenceBadge value={t.confidence} />
                </td>
              </tr>
            ))}
          </ResultTable>

          {/* TLS Certificates */}
          <ResultTable
            title="TLS certificates"
            count={tlsCerts.length}
            empty="No TLS certificates captured."
            headers={['Host', 'Issuer', 'Valid From', 'Valid To', 'Status']}
          >
            {tlsCerts.map((c) => (
              <tr key={c.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-3 font-mono text-slate-800">{c.host}</td>
                <td className="px-6 py-3 text-slate-500">
                  {c.issuer ?? <span className="text-slate-300">—</span>}
                </td>
                <td className="px-6 py-3 text-xs text-slate-500">
                  {c.valid_from ? new Date(c.valid_from).toLocaleDateString() : <span className="text-slate-300">—</span>}
                </td>
                <td className="px-6 py-3 text-xs text-slate-500">
                  {c.valid_to ? new Date(c.valid_to).toLocaleDateString() : <span className="text-slate-300">—</span>}
                </td>
                <td className="px-6 py-3">
                  <ValidBadge value={c.is_valid} />
                </td>
              </tr>
            ))}
          </ResultTable>

          {/* Findings */}
          <ResultTable
            title="Findings"
            count={findings.length}
            empty="No findings."
            headers={['Severity', 'Category', 'Title', 'Description']}
          >
            {findings.map((f) => (
              <tr key={f.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-3">
                  <span
                    className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_BADGE[f.severity]}`}
                  >
                    {f.severity}
                  </span>
                </td>
                <td className="px-6 py-3 text-xs text-slate-500 whitespace-nowrap">
                  {f.category.replace(/_/g, ' ')}
                </td>
                <td className="px-6 py-3 text-sm font-medium text-slate-800">{f.title}</td>
                <td className="px-6 py-3 text-xs text-slate-500 max-w-sm">
                  {f.description ?? <span className="text-slate-300">—</span>}
                </td>
              </tr>
            ))}
          </ResultTable>
        </div>
      )}
    </div>
  )
}

// ── Shared components ─────────────────────────────────────────────────────────

function ModuleCheckbox({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  hint: string
}) {
  return (
    <label className="flex items-center gap-3 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
      />
      <span className="text-sm text-slate-700">
        {label}
        <span className="ml-2 text-xs text-slate-400">({hint})</span>
      </span>
    </label>
  )
}

function ResultTable({
  title,
  count,
  empty,
  headers,
  children,
}: {
  title: string
  count: number
  empty: string
  headers: string[]
  children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-700">{title}</h2>
        <span className="text-xs text-slate-400 tabular-nums">
          {count} result{count !== 1 ? 's' : ''}
        </span>
      </div>
      {count === 0 ? (
        <p className="px-6 py-8 text-center text-sm text-slate-400">{empty}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                {headers.map((h) => (
                  <th key={h} className="px-6 py-3">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">{children}</tbody>
          </table>
        </div>
      )}
    </div>
  )
}
