'use client'

import { useState } from 'react'
import type { DomainVerificationInstructions, VerificationMethod } from '@recon/core'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'

interface Props {
  instructions: DomainVerificationInstructions
  onVerify: (method: VerificationMethod) => Promise<void>
  verifying: boolean
  error?: string
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={copy}
      className="ml-2 rounded px-2 py-0.5 text-xs text-slate-500 border border-slate-200 hover:bg-slate-100 transition-colors"
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  )
}

function CodeBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-2">
      <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">
        {label}
      </span>
      <div className="mt-1 flex items-center rounded-md bg-slate-50 border border-slate-200 px-3 py-2">
        <code className="flex-1 font-mono text-xs text-slate-800 break-all">{value}</code>
        <CopyButton text={value} />
      </div>
    </div>
  )
}

export function VerificationInstructions({
  instructions,
  onVerify,
  verifying,
  error,
}: Props) {
  return (
    <div className="space-y-5">
      {/* Option 1: DNS TXT */}
      <Card>
        <CardHeader>
          <div>
            <h3 className="font-semibold text-slate-900 text-sm">
              Option 1 — DNS TXT Record
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Add a TXT record to your domain&apos;s DNS settings. Propagation may take
              a few minutes.
            </p>
          </div>
        </CardHeader>
        <CardBody className="space-y-2">
          <CodeBlock label="Name" value={instructions.dns_txt.record_name} />
          <CodeBlock label="Type" value={instructions.dns_txt.record_type} />
          <CodeBlock label="Value" value={instructions.dns_txt.record_value} />
          <Button
            className="mt-3 w-full"
            onClick={() => onVerify('dns_txt')}
            loading={verifying}
            disabled={verifying}
          >
            Check DNS TXT Record
          </Button>
        </CardBody>
      </Card>

      {/* Option 2: Well-known file */}
      <Card>
        <CardHeader>
          <div>
            <h3 className="font-semibold text-slate-900 text-sm">
              Option 2 — File Upload
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Host a plain-text file at the path below containing only the token.
            </p>
          </div>
        </CardHeader>
        <CardBody className="space-y-2">
          <CodeBlock label="URL" value={instructions.well_known_file.url} />
          <CodeBlock label="File path" value={instructions.well_known_file.file_path} />
          <CodeBlock label="File content" value={instructions.well_known_file.content} />
          <Button
            className="mt-3 w-full"
            variant="secondary"
            onClick={() => onVerify('well_known_file')}
            loading={verifying}
            disabled={verifying}
          >
            Check File
          </Button>
        </CardBody>
      </Card>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}
    </div>
  )
}
