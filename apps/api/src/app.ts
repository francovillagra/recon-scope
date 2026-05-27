import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import { healthRoutes } from './routes/health.js'
import { authRoutes } from './routes/auth.js'
import { domainRoutes } from './routes/domains.js'

export async function buildApp() {
  const app = Fastify({
    logger: {
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info',
      transport:
        process.env.NODE_ENV !== 'production'
          ? { target: 'pino-pretty', options: { colorize: true } }
          : undefined,
    },
    trustProxy: true,
  })

  await app.register(helmet, {
    contentSecurityPolicy: false, // handled by the web app
  })

  await app.register(cors, {
    origin: process.env.CORS_ORIGIN ?? 'http://localhost:3000',
    credentials: true,
  })

  // All API routes live under /api/v1
  await app.register(
    async (v1) => {
      await v1.register(healthRoutes)
      await v1.register(authRoutes)
      await v1.register(domainRoutes)
    },
    { prefix: '/api/v1' },
  )

  // 404 fallback
  app.setNotFoundHandler((_req, reply) => {
    reply.status(404).send({ error: 'Not found' })
  })

  // Generic error handler
  app.setErrorHandler((err, _req, reply) => {
    app.log.error(err)
    const status = err.statusCode ?? 500
    reply.status(status).send({ error: err.message ?? 'Internal server error' })
  })

  return app
}
