/**
 * Content-Security-Policy de la web.
 *
 * - Los scripts solo corren si llevan el nonce de ESA respuesta (`'nonce-…' 'strict-dynamic'`): un script inyectado
 *   en la página no lo tiene y el navegador no lo ejecuta.
 * - `connect-src` deja hablar únicamente con la propia web y con la API. El token de sesión vive en localStorage;
 *   con esto, aun si algo lograra leerlo, el navegador no lo deja enviar a otro servidor.
 * - Los estilos admiten `'unsafe-inline'`: Tailwind, Recharts y los `style=` de React lo necesitan, y inyectar
 *   estilos es mucho menos grave que inyectar scripts.
 */
export function apiOrigin(apiUrl: string | undefined = process.env.NEXT_PUBLIC_API_URL): string {
  try {
    return new URL(apiUrl ?? 'http://localhost:8000').origin
  } catch {
    return 'http://localhost:8000'
  }
}

export function buildCsp(nonce: string, options: { dev?: boolean; apiUrl?: string } = {}): string {
  const dev = options.dev ?? false
  const api = apiOrigin(options.apiUrl)
  const directives = [
    `default-src 'self'`,
    // En desarrollo React necesita eval para el refresco en caliente; en producción no.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? ` 'unsafe-eval'` : ''}`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self'`,
    `connect-src 'self' ${api}${dev ? ' ws: wss:' : ''}`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
  ]
  // Solo si la API es https: forzar https contra http://localhost rompería el desarrollo local.
  if (!dev && api.startsWith('https://')) directives.push('upgrade-insecure-requests')
  return directives.join('; ')
}
