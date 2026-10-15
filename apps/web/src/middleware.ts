import { NextResponse, type NextRequest } from 'next/server'
import { buildCsp } from '@/lib/csp'

// Un nonce nuevo por respuesta. Next lo lee del encabezado de la petición y se lo agrega a sus propios scripts.
export function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID())
  const csp = buildCsp(nonce, { dev: process.env.NODE_ENV === 'development' })

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('Content-Security-Policy', csp)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set('Content-Security-Policy', csp)
  return response
}

export const config = {
  matcher: [
    {
      // Páginas (no los archivos estáticos ni las precargas, que no llevan HTML propio).
      source: '/((?!_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
