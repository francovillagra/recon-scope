'use client'

import { useEffect, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { PortRow } from '@/lib/api'

interface Props {
  ports: PortRow[]
}

interface ChartRow {
  host: string
  count: number
  portList: string
}

function buildData(ports: PortRow[]): ChartRow[] {
  const byHost = new Map<string, PortRow[]>()
  for (const p of ports) {
    const list = byHost.get(p.host) ?? []
    list.push(p)
    byHost.set(p.host, list)
  }
  return Array.from(byHost.entries())
    .map(([host, ps]) => ({
      host,
      count: ps.length,
      portList: ps.map((p) => `${p.port}/${p.protocol}`).join(', '),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: any[] }) {
  if (!active || !payload?.length) return null
  const d: ChartRow = payload[0].payload
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 shadow-md text-xs">
      <p className="font-mono font-semibold text-slate-800 mb-1">{d.host}</p>
      <p className="text-slate-500">{d.portList}</p>
    </div>
  )
}

export function OpenPortsByHost({ ports }: Props) {
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])

  const data = buildData(ports)

  if (data.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-slate-400">No open ports found.</p>
      </div>
    )
  }

  if (!mounted) return null

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart
        data={data}
        layout="vertical"
        margin={{ top: 4, right: 24, left: 8, bottom: 4 }}
      >
        <CartesianGrid strokeDasharray="3 3" horizontal={false} />
        <XAxis
          type="number"
          allowDecimals={false}
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          type="category"
          dataKey="host"
          width={140}
          tick={{ fontSize: 10, fontFamily: 'monospace' }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: '#f1f5f9' }} />
        <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} maxBarSize={24} />
      </BarChart>
    </ResponsiveContainer>
  )
}
