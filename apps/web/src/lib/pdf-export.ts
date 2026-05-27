import type { ScanDetail } from '@/lib/api'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

export async function exportScanPDF(domainName: string, detail: ScanDetail): Promise<void> {
  // Dynamic import keeps jsPDF out of the initial bundle
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import('jspdf'),
    import('jspdf-autotable'),
  ])

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const pageW = doc.internal.pageSize.getWidth()
  const pageH = doc.internal.pageSize.getHeight()
  const margin = 14

  const scanDate = detail.job.completed_at
    ? new Date(detail.job.completed_at).toLocaleDateString()
    : new Date(detail.job.created_at).toLocaleDateString()

  // ── 1. Header ───────────────────────────────────────────────────────────────
  doc.setFontSize(22)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(15, 23, 42)
  doc.text('recon-scope', margin, 20)

  doc.setFontSize(10)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(100, 116, 139)
  doc.text(`Target: ${domainName}`, margin, 30)
  doc.text(`Scan date: ${scanDate}`, margin, 36)
  doc.text(`Job: ${detail.job.id}`, margin, 42)

  doc.setDrawColor(226, 232, 240)
  doc.setLineWidth(0.4)
  doc.line(margin, 46, pageW - margin, 46)

  // ── 2. Executive summary ────────────────────────────────────────────────────
  let y = 54
  doc.setFontSize(13)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(15, 23, 42)
  doc.text('Executive Summary', margin, y)
  y += 7

  doc.setFontSize(10)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(51, 65, 85)

  const summaryRows = [
    ['Subdomains', String(detail.subdomains.length)],
    ['Open Ports', String(detail.ports.length)],
    ['Technologies', String(detail.technologies.length)],
    ['Findings', String(detail.findings.length)],
  ]
  for (const sev of SEVERITY_ORDER) {
    const cnt = detail.findings.filter((f) => f.severity === sev).length
    if (cnt > 0) summaryRows.push([`  ${sev.charAt(0).toUpperCase() + sev.slice(1)}`, String(cnt)])
  }
  for (const [label, value] of summaryRows) {
    doc.text(`${label}:`, margin + 2, y)
    doc.text(value, margin + 52, y)
    y += 6
  }

  // ── 3. Findings table ────────────────────────────────────────────────────────
  y += 4
  doc.setFontSize(13)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(15, 23, 42)
  doc.text('Findings', margin, y)
  y += 2

  autoTable(doc, {
    startY: y,
    head: [['Severity', 'Category', 'Title', 'Description']],
    body: detail.findings.map((f) => [
      f.severity.toUpperCase(),
      f.category.replace(/_/g, ' '),
      f.title,
      f.description ?? '',
    ]),
    headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 9 },
    bodyStyles: { fontSize: 8, textColor: [51, 65, 85] },
    columnStyles: { 0: { cellWidth: 18 }, 1: { cellWidth: 36 }, 3: { cellWidth: 65 } },
    alternateRowStyles: { fillColor: [248, 250, 252] },
    margin: { left: margin, right: margin },
  })

  // ── 4. Open ports table ──────────────────────────────────────────────────────
  const afterFindings: number = (doc as any).lastAutoTable.finalY + 10
  doc.setFontSize(13)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(15, 23, 42)
  doc.text('Open Ports', margin, afterFindings)

  autoTable(doc, {
    startY: afterFindings + 4,
    head: [['Host', 'Port', 'Service', 'Banner']],
    body: detail.ports.map((p) => [
      p.host,
      `${p.port}/${p.protocol}`,
      p.service ?? '',
      (p.banner ?? '').substring(0, 80),
    ]),
    headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 9 },
    bodyStyles: { fontSize: 8, textColor: [51, 65, 85], fontStyle: 'normal' },
    columnStyles: { 0: { fontStyle: 'normal' } },
    alternateRowStyles: { fillColor: [248, 250, 252] },
    margin: { left: margin, right: margin },
  })

  // ── 5. Footer on every page ──────────────────────────────────────────────────
  const pageCount: number = (doc.internal as any).getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFontSize(8)
    doc.setFont('helvetica', 'italic')
    doc.setTextColor(148, 163, 184)
    doc.text('Authorized targets only — recon-scope', margin, pageH - 8)
    doc.text(`Page ${i} of ${pageCount}`, pageW - margin, pageH - 8, { align: 'right' })
  }

  const slug = domainName.replace(/\./g, '-')
  const dateSlug = scanDate.replace(/\//g, '-')
  doc.save(`recon-scope-${slug}-${dateSlug}.pdf`)
}
