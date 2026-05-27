import { Pool, type PoolClient } from 'pg'

let pool: Pool | undefined

export function getPool(): Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.NODE_ENV === 'production'
          ? { rejectUnauthorized: false }
          : false,
      max: 20,
      idleTimeoutMillis: 30_000,
    })
    pool.on('error', (err) => console.error('[db] pool error', err))
  }
  return pool
}

export async function query<T extends object>(
  sql: string,
  params?: unknown[],
): Promise<T[]> {
  const { rows } = await getPool().query<T>(sql, params)
  return rows
}

export async function queryOne<T extends object>(
  sql: string,
  params?: unknown[],
): Promise<T | null> {
  const rows = await query<T>(sql, params)
  return rows[0] ?? null
}

export async function transaction<T>(
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await getPool().connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (err) {
    await client.query('ROLLBACK')
    throw err
  } finally {
    client.release()
  }
}
