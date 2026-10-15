import type { Metadata } from 'next'
import './globals.css'
import { AuthProvider } from '@/providers/AuthProvider'

// El nonce de la Content-Security-Policy es distinto en cada respuesta (src/middleware.ts), así que las páginas no
// pueden generarse de antemano: se renderizan en cada pedido.
export const dynamic = 'force-dynamic'

export const metadata: Metadata = {
  title: {
    default: 'Recon Platform',
    template: '%s | Recon Platform',
  },
  description: 'Automated security reconnaissance — authorized targets only.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  )
}
