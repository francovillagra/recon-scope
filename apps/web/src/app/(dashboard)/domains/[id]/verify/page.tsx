'use client'

import { use, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { Domain, DomainVerificationInstructions, VerificationMethod } from '@recon/core'
import { domains as domainsApi, ApiError } from '@/lib/api'
import { VerificationInstructions } from '@/components/domains/VerificationInstructions'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'

export default function VerifyDomainPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const router = useRouter()

  const [domain, setDomain] = useState<Domain | null>(null)
  const [instructions, setInstructions] =
    useState<DomainVerificationInstructions | null>(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [verifyError, setVerifyError] = useState<string | null>(null)
  const [fetchError, setFetchError] = useState<string | null>(null)

  useEffect(() => {
    domainsApi
      .get(id)
      .then((res) => {
        setDomain(res.domain)
        setInstructions(res.instructions)
      })
      .catch(() => setFetchError('Domain not found.'))
      .finally(() => setLoading(false))
  }, [id])

  async function handleVerify(method: VerificationMethod) {
    setVerifyError(null)
    setVerifying(true)
    try {
      const res = await domainsApi.verify(id, method)
      setDomain(res.domain)
      if (res.domain.verification_status === 'verified') {
        router.push('/dashboard/domains')
      } else if (res.error) {
        setVerifyError(res.error)
        if (res.instructions) setInstructions(res.instructions)
      }
    } catch (err) {
      setVerifyError(
        err instanceof ApiError ? err.message : 'Verification request failed',
      )
    } finally {
      setVerifying(false)
    }
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
      </div>
    )
  }

  if (fetchError || !domain || !instructions) {
    return (
      <div>
        <p className="text-red-600 text-sm">{fetchError ?? 'Unable to load domain.'}</p>
        <Button className="mt-4" variant="secondary" onClick={() => router.back()}>
          Go back
        </Button>
      </div>
    )
  }

  const badgeVariant =
    domain.verification_status === 'verified'
      ? 'verified'
      : domain.verification_status === 'failed'
        ? 'failed'
        : 'pending'

  return (
    <div className="max-w-xl">
      {/* Header */}
      <div className="mb-6 flex items-center gap-3">
        <button
          onClick={() => router.back()}
          className="text-slate-400 hover:text-slate-600 transition-colors"
        >
          ←
        </button>
        <h1 className="text-2xl font-bold text-slate-900 font-mono">
          {domain.domain}
        </h1>
        <Badge variant={badgeVariant} />
      </div>

      {domain.verification_status === 'verified' ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-6 py-5">
          <p className="font-semibold text-emerald-800">Domain verified ✓</p>
          <p className="mt-1 text-sm text-emerald-700">
            This domain is verified and ready for scanning in Phase 1.
          </p>
          <Button
            className="mt-4"
            variant="secondary"
            onClick={() => router.push('/dashboard/domains')}
          >
            Back to Domains
          </Button>
        </div>
      ) : (
        <>
          <p className="mb-5 text-sm text-slate-600">
            Publish one of the following proofs to verify you control{' '}
            <strong>{domain.domain}</strong>. Then click the corresponding
            &ldquo;Check&rdquo; button.
          </p>
          <VerificationInstructions
            instructions={instructions}
            onVerify={handleVerify}
            verifying={verifying}
            error={verifyError ?? undefined}
          />
        </>
      )}
    </div>
  )
}
