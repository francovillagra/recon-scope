![recon-scope](./assets/banner.svg)

![Python](https://img.shields.io/badge/Python-3.12-3fb950?style=flat-square&logo=python&logoColor=white&labelColor=0d1117) ![FastAPI](https://img.shields.io/badge/FastAPI-0.110-3fb950?style=flat-square&logo=fastapi&logoColor=white&labelColor=0d1117) ![Next.js](https://img.shields.io/badge/Next.js-15-3fb950?style=flat-square&logo=next.js&logoColor=white&labelColor=0d1117) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-3fb950?style=flat-square&logo=postgresql&logoColor=white&labelColor=0d1117) ![Railway](https://img.shields.io/badge/Deploy-Railway-3fb950?style=flat-square&logo=railway&logoColor=white&labelColor=0d1117)

# recon-scope

> Plataforma de reconocimiento automatizado para auditorías de seguridad autorizadas.

**Live demo:** [recon-scope.vercel.app](https://recon-scope.vercel.app) · **Engine API:** [reconapi-production.up.railway.app](https://reconapi-production.up.railway.app/api/v1/health)

---

## Funcionalidades

- **Enumeración de subdominios** — recon pasivo vía certificate transparency (crt.sh), resolución DNS asíncrona con asyncio + dnspython
- **Escaneo de puertos** — TCP connect scan en Python puro con asyncio, Semaphore(200), banner grabbing e inferencia de servicios. Sin dependencia de nmap.
- **HTTP Fingerprinting** — análisis de headers, parsing de título, detección de stack tecnológico (nginx, Cloudflare, Vercel, WordPress, Django, Laravel y más)
- **Análisis TLS** — validez del certificado, expiración, SAN, algoritmo de firma
- **Motor de findings** — hallazgos rankeados por severidad (critical/high/medium/low/info) con evidencia. Reglas: puertos DB expuestos, exposición SSH, TLS inválido, headers de seguridad faltantes, divulgación de versión de servidor.
- **Verificación de propiedad de dominio** — verificación vía DNS TXT o archivo well-known antes de cualquier scan. Sin posibilidad de escanear targets no autorizados.
- **Audit log** — cada acción registrada con usuario, target, IP y timestamp.
- **Exportación** — reporte completo como JSON (API) o PDF (client-side, jsPDF).

---

## Arquitectura

```mermaid
graph TB
    subgraph "Browser"
        WEB["Next.js 15\nApp Router"]
    end

    subgraph "apps/engine  :8000"
        API["FastAPI\n/api/v1/*"]
        AUTH["Auth\n/auth/register\n/auth/login"]
        DOMAINS["Domains\n/domains/**"]
        SCANS["Scans\n/scans/**"]
        RUNNER["scan_runner\n(BackgroundTask)"]
        FP["fingerprint.py\nhttpx · ssl"]
        FINDINGS["findings_engine.py"]
    end

    subgraph "PostgreSQL :5432"
        PG[("postgres")]
        T1[["users"]]
        T2[["domains"]]
        T3[["audit_log"]]
        T4[["scan_jobs"]]
        T5[["subdomains"]]
        T6[["ports"]]
        T7[["http_fingerprints"]]
        T8[["technologies"]]
        T9[["tls_certificates"]]
        T10[["findings"]]
    end

    WEB -->|"JWT Bearer"| API
    API --> AUTH & DOMAINS & SCANS
    SCANS --> RUNNER
    RUNNER --> FP & FINDINGS
    FP -->|"httpx"| INET[["Target hosts"]]
    DOMAINS -->|"DNS TXT / .well-known"| DNS[["Public DNS"]]
    API --> PG
    PG --> T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 & T9 & T10

    style WEB fill:#0284c7,color:#fff
    style API fill:#0369a1,color:#fff
    style PG fill:#334155,color:#fff
```

### Gate de verificación de propiedad

```mermaid
sequenceDiagram
    actor Usuario
    participant Web
    participant API
    participant DNS/Archivo as DNS / .well-known

    Usuario->>Web: Ingresar dominio
    Web->>API: POST /api/v1/domains
    API-->>Web: { domain_id, verification_token, dns_instructions, well_known_instructions }
    Web-->>Usuario: Mostrar instrucciones de verificación

    Note over Usuario,DNS/Archivo: El usuario publica el TXT en DNS o sube el archivo

    Usuario->>Web: Click "Verificar"
    Web->>API: POST /api/v1/domains/:id/verify { method }
    API->>DNS/Archivo: Resolver TXT / fetch archivo
    DNS/Archivo-->>API: Contenido del registro / archivo
    alt Token coincide
        API-->>Web: 200 { domain: { verification_status: "verified" } }
        Web-->>Usuario: Verificado — listo para escanear
    else Token faltante / no coincide
        API-->>Web: 200 { domain: { verification_status: "failed" }, error, instructions }
        Web-->>Usuario: Verificación fallida — intentar de nuevo
    end
```

---

## Stack tecnológico

| Capa | Tecnología |
|---|---|
| Frontend | Next.js 15 (App Router), TypeScript, Tailwind CSS v3, Recharts |
| Backend | FastAPI, Python 3.12, asyncio, SQLAlchemy 2 (async), Alembic |
| Base de datos | PostgreSQL 16, asyncpg |
| Infraestructura | Docker, Docker Compose |

---

## Diseño de seguridad

**Quién puede escanear qué.** La verificación de propiedad de dominio es obligatoria antes de iniciar cualquier scan: los usuarios demuestran control del dominio publicando un registro DNS TXT en `_recon-verify.<dominio>` o un archivo token en `/.well-known/recon-verification.txt` (el mismo enfoque que Google Search Console). La verificación puede vencer (`VERIFICATION_MAX_AGE_DAYS`). La autorización se aplica a nivel de aplicación: cada consulta a la base de datos filtra por `user_id`, y cada acción — registro de dominio, verificación, inicio de scan, finalización de scan, generación de reporte — se escribe en la tabla `audit_log`, que sobrevive a la eliminación del dominio o del usuario.

**El motor no es un puente hacia la red interna (SSRF).** El permiso es por *nombre* de dominio, pero el motor se conecta a *direcciones IP*, y el DNS de un dominio lo controla quien lo registró: sin más, bastaba un registro `A` apuntando a `127.0.0.1` o a `169.254.169.254` para que el motor escaneara su propia red. Por eso, antes de conectarse a cualquier host (puertos, huella HTTP, TLS, archivo de verificación) el motor resuelve el nombre una sola vez, exige que **todas** las respuestas sean direcciones públicas de Internet y se conecta a la dirección ya validada, sin volver a resolver. Loopback, redes privadas, link-local (metadatos de la nube) y demás rangos especiales — también cuando vienen embebidos en IPv6 — se omiten y se informan como hallazgo `info`. Las redirecciones HTTP solo se siguen dentro del dominio verificado. `ALLOW_PRIVATE_TARGETS=true` apaga esta protección: es solo para desarrollo o para un despliegue privado.

**Límites de uso.** Escaneos simultáneos y por usuario, duración máxima, hosts y subdominios por scan, dominios por usuario y el ritmo de `POST /scans` (10 por hora; solo cuentan los que se aceptan) están acotados (variables `SCAN_*` más abajo). Un scan que llega a un límite guarda lo que tiene y lo dice en el reporte.

**Cuentas y sesiones.** Las contraseñas se guardan con bcrypt (hasta 72 bytes, que es lo que bcrypt realmente usa). El hash corre en hilos aparte con una cola acotada: si hay demasiado trabajo, el motor responde `503` en vez de dejar de responder a todos. Hay límite de intentos de login por IP y por IP + correo (`429` con `Retry-After`) y de registros por IP; un correo inexistente y una contraseña incorrecta dan el mismo mensaje y tardan parecido. `JWT_SECRET` es obligatorio y el motor no arranca con uno débil o de ejemplo; los tokens exigen `exp`, `iat` y `sub`.

**Base de datos.** Todas las tablas tienen Row Level Security activada y sin políticas (migración `006`), y a los roles `anon` y `authenticated` de Supabase se les quitan los permisos: aunque la API de datos de Supabase estuviera expuesta, la clave pública no puede leer ni escribir nada. El motor se conecta como dueño de las tablas (el usuario `postgres` en Supabase), al que RLS no le aplica, así que `DATABASE_URL` tiene que usar ese usuario. Una migración nueva que cree una tabla tiene que habilitar RLS: `tests/test_rls.py` falla si alguna tabla queda sin ella.

**Capa HTTP.** Tope de tamaño del cuerpo (`413`), cabeceras de seguridad en todas las respuestas, CORS limitado a `CORS_ORIGINS` y sin credenciales, `/docs` solo con `DEBUG=true`, errores de validación que no repiten lo que envió el cliente (una contraseña nunca vuelve en la respuesta) y errores 500 genéricos, sin stack traces. La web envía una Content-Security-Policy con un nonce distinto en cada respuesta y `connect-src` solo permite hablar con la propia web y con la API.

**Lo que no cubre** (a propósito o por ahora):

- El permiso es por dominio: un subdominio de un dominio verificado que apunte a la IP pública de un tercero puede ser escaneado (hasta `SCAN_MAX_HOSTS` hosts por scan). Lo acotan los términos de uso que se aceptan al registrarse, los límites y el `audit_log`; además, por defecto la API solo hace reconocimiento pasivo (`subdomains`).
- Los límites de ritmo viven en la memoria de cada proceso: con más de una réplica del motor no se comparten, y repartir intentos contra una misma cuenta entre muchas IPs no se frena.
- El token de sesión dura 7 días, no se puede revocar (no hay cierre de sesión en el servidor ni cambio de contraseña) y la web lo guarda en `localStorage`. La CSP limita a dónde podría enviarse, pero un XSS seguiría siendo grave.
- Los scans corren dentro del proceso del motor: si se reinicia, los que estaban en curso quedan marcados como fallidos al volver a arrancar.
- Sin verificación de correo, recuperación de contraseña ni 2FA (ver Roadmap).

---

## Inicio rápido

### Producción (recomendado)

| Servicio | URL |
|---|---|
| Dashboard web | https://recon-scope.vercel.app |
| Engine API | https://reconapi-production.up.railway.app |
| Health check | https://reconapi-production.up.railway.app/api/v1/health |

Registrate en el dashboard, verificá la propiedad de tu dominio y lanzá el primer scan.

### Desarrollo local

#### Prerequisitos

- Docker + Docker Compose
- Archivo `.env` (copiar `.env.example`)

#### 1. Configurar entorno

```bash
cp .env.example .env
# JWT_SECRET es obligatorio (mínimo 32 caracteres): docker compose no levanta sin él. Generá uno así:
# python -c "import secrets; print(secrets.token_hex(64))"
```

#### 2. Levantar todos los servicios

```bash
docker compose -f infra/docker-compose.yml up --build
```

El contenedor del engine ejecuta `alembic upgrade head` automáticamente antes de iniciar. No se necesita ningún paso de migración manual.

| Servicio | URL |
|---|---|
| Dashboard web | http://localhost:3000 |
| Engine API | http://localhost:8000 |
| Docs API (solo DEBUG=true) | http://localhost:8000/docs |
| Health check | http://localhost:8000/api/v1/health |

### Variables de entorno

Motor (`apps/engine`):

| Variable | Requerida | Default | Descripción |
|---|---|---|---|
| `DATABASE_URL` | Sí | — | Connection string `postgresql+asyncpg://...` |
| `MIGRATION_DATABASE_URL` | No | derivada de `DATABASE_URL` | URL síncrona (`postgresql+psycopg2://...`) con la que se conecta Alembic. Las migraciones piden SSL por defecto (lo que necesita Supabase); para un Postgres sin SSL, como el de docker compose, agregá `?sslmode=disable` |
| `JWT_SECRET` | Sí | — | Clave de firma HS256. Mínimo 32 caracteres, nada repetitivo ni de ejemplo: si no, el motor no arranca |
| `JWT_EXPIRES_DAYS` | No | `7` | Duración del token en días |
| `BCRYPT_ROUNDS` | No | `12` | Factor de trabajo bcrypt |
| `BCRYPT_CONCURRENCY` | No | `4` | Hashes de contraseña que se calculan a la vez |
| `BCRYPT_MAX_PENDING` | No | `64` | Hashes en espera antes de responder `503` |
| `CORS_ORIGINS` | No | `["http://localhost:3000"]` | Array JSON de orígenes permitidos: la dirección exacta de tu web |
| `DEBUG` | No | `false` | Habilita `/docs` y `/redoc` |
| `TRUSTED_PROXY_COUNT` | No | `0` | Cuántos proxies de confianza hay delante del motor (en Railway, `1`). Con `0` se usa la IP del socket: detrás de un proxy todos los usuarios compartirían los mismos contadores de límite y el `audit_log` guardaría la IP del proxy. No pongas más que los reales: las entradas de más de `X-Forwarded-For` las escribe el cliente |
| `MAX_REQUEST_BYTES` | No | `1000000` | Tamaño máximo del cuerpo de una petición (`413` si se pasa) |
| `ALLOW_PRIVATE_TARGETS` | No | `false` | Si es `false`, el motor solo se conecta a direcciones públicas de Internet: un dominio verificado cuyo DNS apunta a `127.0.0.1`, `10.x`, `169.254.169.254`, etc. se omite y se informa. Ponelo en `true` **solo** en un despliegue privado donde escanear tu propia red sea el objetivo; nunca en un servicio compartido |
| `SCAN_MAX_CONCURRENT` | No | `3` | Scans corriendo a la vez en el proceso; el resto espera en `queued` |
| `SCAN_MAX_PER_USER` | No | `2` | Scans en cola o corriendo por usuario |
| `SCAN_MAX_SECONDS` | No | `900` | Duración máxima de un scan: al llegar, guarda lo que tiene y avisa que es parcial |
| `SCAN_MAX_HOSTS` | No | `25` | Hosts que se escanean activamente (puertos / huella) por scan |
| `SCAN_MAX_SUBDOMAINS` | No | `500` | Nombres que se resuelven por scan |
| `MAX_DOMAINS_PER_USER` | No | `25` | Dominios por usuario |
| `VERIFICATION_MAX_AGE_DAYS` | No | `0` | Días que vale la verificación de un dominio (`0` = no vence). En un servicio público se recomienda `90`; al vencer hay que volver a verificar (el registro TXT publicado sigue sirviendo) |

Web (`apps/web`):

| Variable | Requerida | Default | Descripción |
|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | Sí | `http://localhost:8000` | URL base del motor visible desde el browser. Se incorpora al compilar la web, y la Content-Security-Policy (`connect-src`) solo permite conectarse a esa dirección |

---

## Referencia de API

Todos los endpoints tienen el prefijo `/api/v1`. Los endpoints autenticados requieren `Authorization: Bearer <token>`.

### Auth

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `POST` | `/auth/register` | — | Crear cuenta. Body: `{ email, password, tos_accepted: true }` |
| `POST` | `/auth/login` | — | Obtener token. Body: `{ email, password }` |

Ambos devuelven `{ token, user }`.

### Dominios

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `GET` | `/domains` | Requerida | Listar dominios del usuario |
| `POST` | `/domains` | Requerida | Registrar un dominio. Devuelve `{ domain_id, verification_token, dns_instructions, well_known_instructions }` |
| `GET` | `/domains/:id` | Requerida | Detalle del dominio + instrucciones de verificación |
| `POST` | `/domains/:id/verify` | Requerida | Disparar verificación de propiedad. Body: `{ method: "dns_txt" \| "well_known_file" }`. Responde `200` también si falla: en ese caso trae `error` e `instructions` |
| `DELETE` | `/domains/:id` | Requerida | Eliminar dominio |
| `GET` | `/domains/:id/history` | Requerida | Historial de scans con conteos de severidad por ejecución |

### Scans

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `POST` | `/scans` | Requerida | Iniciar un scan (10/hora por usuario, además de los límites `SCAN_*`) |
| `GET` | `/scans` | Requerida | Listar todos los scan jobs del usuario |
| `GET` | `/scans/:id` | Requerida | Estado del job + resultados completos cuando finaliza |
| `GET` | `/scans/:id/export/json` | Requerida | Descargar resultados como archivo JSON |

**Body de POST /scans:**

```json
{
  "domain_id": "<uuid>",
  "modules": ["subdomains", "ports", "fingerprint"],
  "port_range": "top-1000",
  "timeout_seconds": 30
}
```

- `modules`: uno o más de `subdomains`, `ports`, `fingerprint` (por defecto, solo `subdomains`). Los dos últimos se conectan a los servidores del dominio; `subdomains` solo consulta crt.sh y DNS.
- `port_range`: `top-100`, `top-1000` o `full`. `timeout_seconds`: de 1 a 60, por conexión.
- `passive_only` es opcional y lo calcula el servidor: es `true` solo si los módulos son pasivos. Mandar `true` junto con `ports` o `fingerprint` es una contradicción y se rechaza con `422`.

**Respuesta de GET /scans/:id (completado):**

```json
{
  "job": { "id": "...", "status": "completed", "progress": 100, ... },
  "subdomains": [{ "hostname": "api.example.com", "resolved_ip": "1.2.3.4", ... }],
  "ports": [{ "host": "1.2.3.4", "port": 443, "protocol": "tcp", "service": "https", ... }],
  "technologies": [{ "name": "nginx", "category": "web-server", "confidence": 90, ... }],
  "tls_certificates": [{ "host": "example.com", "issuer": "Let's Encrypt", "is_valid": true, ... }],
  "findings": [{ "severity": "high", "category": "exposed_service", "title": "...", ... }]
}
```

### Health

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `GET` | `/health` | — | Devuelve `{ status: "ok", version: "1.0.0" }` |

### Errores

Los errores llegan como `{ "detail": "mensaje" }`; los de validación (`422`) como `{ "detail": [{ "type", "loc", "msg" }] }` y nunca repiten el valor que enviaste.

| Código | Cuándo |
|---|---|
| `401` | Token ausente, inválido o vencido; o credenciales incorrectas en `/auth/login` |
| `403` | Llegaste al máximo de dominios (`MAX_DOMAINS_PER_USER`) |
| `404` | El recurso no existe **o no es tuyo** |
| `409` | El dominio o el correo ya están registrados |
| `413` | El cuerpo supera `MAX_REQUEST_BYTES` |
| `429` | Demasiados intentos o scans: el encabezado `Retry-After` dice cuántos segundos esperar |
| `503` | El motor está saturado calculando contraseñas: reintentá tras `Retry-After` |

---

## Pruebas y CI

```bash
# Motor: necesita un PostgreSQL descartable (el nombre de la base tiene que incluir "test") con las migraciones aplicadas
cd apps/engine
pip install -r requirements-dev.txt
export DATABASE_URL=postgresql+asyncpg://usuario:clave@localhost:5432/recon_test
export MIGRATION_DATABASE_URL='postgresql+psycopg2://usuario:clave@localhost:5432/recon_test?sslmode=disable'
export JWT_SECRET=<un valor de al menos 32 caracteres>
alembic upgrade head
TEST_DATABASE_URL=$DATABASE_URL python -m pytest -q

# Web: después de compilar, verifica que cada página lleve la CSP con nonce y las demás cabeceras
pnpm install --frozen-lockfile
pnpm --filter @recon/core build && pnpm --filter @recon/web build
pnpm --filter @recon/web check:headers
```

El workflow de GitHub Actions (`.github/workflows/ci.yml`) corre en cada pull request: las pruebas del motor contra un PostgreSQL real (Python 3.12 y 3.13, con las migraciones aplicadas desde cero), `pip-audit` y `pnpm audit` sobre las dependencias de producción, el build, los tipos y las cabeceras de la web, y construye las imágenes de Docker con `docker compose` para probar un registro y un login reales. Dependabot propone las actualizaciones cada semana.

---

## Roadmap

Features planned to evolve recon-scope from a portfolio project into a production-ready platform:

- [ ] Email verification on registration (Resend / SendGrid)
- [ ] Password reset flow via email
- [ ] Two-factor authentication (TOTP / authenticator app)
- [ ] Dark mode for the dashboard
- [ ] Active DNS brute-force enumeration (behind ownership gate)
- [ ] Shodan API integration for passive port intelligence
- [ ] Scheduled recurring scans with change detection
- [ ] Slack / webhook notifications on new findings
- [ ] Rate limiting backed by Redis (currently in-memory)
- [ ] Per-user Row Level Security policies via Supabase Auth (today RLS denies everything except the engine's owner role)
- [ ] AWS deployment option (ECS + RDS)

---

## Autor

**Franco Villagra** — Desarrollador · Ciberseguridad

- Portfolio: [francoverse.fvillagra-dev.workers.dev](https://francoverse.fvillagra-dev.workers.dev)
- GitHub: [@francovillagra](https://github.com/francovillagra)

---

## Licencia

MIT — libre para usar, modificar y distribuir.
