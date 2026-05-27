import type { JWTPayload } from '@recon/core'

declare module 'fastify' {
  interface FastifyRequest {
    user: JWTPayload
  }
}
