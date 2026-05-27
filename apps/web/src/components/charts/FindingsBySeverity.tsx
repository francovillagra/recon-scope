'use client'

import { useEffect, useState } from 'react'
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { FindingRow } from '@/lib/api'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

interface Props {
  findings: FindingRow[]
}

export function FindingsBySeverity({ findings }: Props) {
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])

  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, sev) => {
    acc[sev] = findings.filter((f) => f.severity === sev).length
    return acc
  }, {})

  const data = SEVERITY_ORDER.filter((sev) => counts[sev] > 0).map((sev) => ({
    name: sev,
    value: counts[sev],
  }))

  if (data.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-emerald-600 font-medium">No findings — clean scan</p>
      </div>
    )
  }

  if (!mounted) return null

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="45%"
          outerRadius={90}
          dataKey="value"
          labelLine={false}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
          ))}
        </Pie>
        <Tooltip
          formatter={(value: number, name: string) => [value, name.toUpperCase()]}
        />
        <Legend
          formatter={(value) => (
            <span className="text-xs capitalize text-slate-600">{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
