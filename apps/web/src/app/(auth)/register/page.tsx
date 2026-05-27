'use client'

import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { auth, ApiError } from '@/lib/api'
import { Input } from '@/components/ui/Input'
import { Button } from '@/components/ui/Button'

export default function RegisterPage() {
  const router = useRouter()
  const { login } = useAuth()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tosChecked, setTosChecked] = useState(false)

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError(null)

    if (!tosChecked) {
      setError('You must accept the Terms of Service to register.')
      return
    }

    setLoading(true)
    const data = new FormData(e.currentTarget)

    const password = data.get('password') as string
    const confirm = data.get('confirm') as string
    if (password !== confirm) {
      setError('Passwords do not match.')
      setLoading(false)
      return
    }

    try {
      const res = await auth.register({
        email: data.get('email') as string,
        password,
        tos_accepted: tosChecked,
      })
      login(res.token, res.user)
      router.push('/dashboard')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <span className="text-brand-500 text-4xl">⬡</span>
          <h1 className="mt-2 text-2xl font-bold text-slate-900">Create account</h1>
          <p className="mt-1 text-sm text-slate-500">
            Authorized-targets reconnaissance platform
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              name="email"
              type="email"
              label="Email address"
              autoComplete="email"
              required
            />
            <Input
              name="password"
              type="password"
              label="Password"
              autoComplete="new-password"
              minLength={8}
              required
            />
            <Input
              name="confirm"
              type="password"
              label="Confirm password"
              autoComplete="new-password"
              minLength={8}
              required
            />

            {/* ToS acceptance — stored as tos_accepted_at in DB */}
            <div className="flex items-start gap-3 pt-1">
              <input
                id="tos"
                type="checkbox"
                checked={tosChecked}
                onChange={(e) => setTosChecked(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
              />
              <label htmlFor="tos" className="text-sm text-slate-600 leading-snug">
                I confirm that I will only run scans against targets I own or have{' '}
                <strong>explicit written authorization</strong> to test.{' '}
                I accept the{' '}
                <a href="#" className="text-brand-600 hover:underline">
                  Terms of Service
                </a>
                .
              </label>
            </div>

            {error && (
              <p className="rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-600">
                {error}
              </p>
            )}

            <Button
              type="submit"
              className="w-full"
              loading={loading}
              disabled={!tosChecked}
            >
              Create account
            </Button>
          </form>
        </div>

        <p className="mt-4 text-center text-sm text-slate-500">
          Already have an account?{' '}
          <Link href="/login" className="text-brand-600 hover:underline font-medium">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}
