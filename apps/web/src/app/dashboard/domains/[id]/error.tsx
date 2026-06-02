'use client'

export default function DomainRouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 px-6 py-8 text-sm">
      <p className="font-semibold text-red-800 mb-1">Error al cargar la página</p>
      <pre className="mt-2 whitespace-pre-wrap break-all text-xs text-red-700 bg-red-100 rounded p-3">
        {error.message}
        {error.digest ? `\ndigest: ${error.digest}` : ''}
      </pre>
      <button
        onClick={reset}
        className="mt-4 rounded-md bg-red-600 px-4 py-2 text-xs text-white hover:bg-red-700"
      >
        Reintentar
      </button>
    </div>
  )
}
