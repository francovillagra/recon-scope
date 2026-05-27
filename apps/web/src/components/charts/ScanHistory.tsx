'use client'

import { useEffect, useState } from 'react'
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { domains as domainsApi } from '@/lib/api'
import type { ScanHistoryEntry } from '@/lib/api'

const LINES: { key: keyof ScanHistoryEntry['findings_by_severity']; color: string }[] = [
  { key: 'critical', color: '#ef4444' },
  { key: 'high', color: '#f97316' },
  { key: 'medium', color: '#eab308' },
  { key: 'low', color: '#3b82f6' },
]

interface Props {
  domainId: string
}

export function ScanHistory({ domainId }: Props) {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    domainsApi
      .history(domainId)
      .then((data) => setHistory([...data].reverse()) /* chronological order */)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [domainId])

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
      </div>
    )
  }

  if (history.length < 2) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-slate-400">Run more scans to see trends.</p>
      </div>
    )
  }

  if (!mounted) return null

  const data = history
    .filter((e) => e.status === 'completed')
    .map((e) => ({
      date: new Date(e.created_at).toLocaleDateString(),
      ...e.findings_by_severity,
    }))

  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 4, right: 24, left: 0, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="date" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis
          allowDecimals={false}
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip />
        <Legend
          formatter={(value) => (
            <span className="text-xs capitalize text-slate-600">{value}</span>
          )}
        />
        {LINES.map(({ key, color }) => (
          <Line
            key={key}
            type="monotone"
            dataKey={key}
            stroke={color}
            strokeWidth={2}
            dot={{ r: 3 }}
            activeDot={{ r: 5 }}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}
