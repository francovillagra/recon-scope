'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { domains as domainsApi, ApiError } from '@/lib/api'
import { Input } from '@/components/ui/Input'
import { Button } from '@/components/ui/Button'
import { Card, CardBody } from '@/components/ui/Card'

export default function NewDomainPage() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError(null)
    setLoading(true)

    const domain = (new FormData(e.currentTarget).get('domain') as string).trim()

    try {
      const res = await domainsApi.create(domain)
      router.push(`/dashboard/domains/${res.domain.id}/verify`)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to register domain')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-lg">
      <h1 className="mb-6 text-2xl font-bold text-slate-900">Add Domain</h1>

      <Card>
        <CardBody>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              name="domain"
              label="Domain name"
              placeholder="example.com"
              autoComplete="off"
              spellCheck={false}
              required
            />

            <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              <strong>Important:</strong> You must verify ownership of this domain before
              any scan can be started. You will be shown verification instructions on the
              next screen.
            </div>

            {error && (
              <p className="rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-600">
                {error}
              </p>
            )}

            <div className="flex gap-3 pt-2">
              <Button type="submit" loading={loading}>
                Continue to Verification
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.back()}
                disabled={loading}
              >
                Cancel
              </Button>
            </div>
          </form>
        </CardBody>
      </Card>
    </div>
  )
}
