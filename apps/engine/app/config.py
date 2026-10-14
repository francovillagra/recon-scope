from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database — use postgresql+asyncpg:// scheme for async driver
    DATABASE_URL: str
    MIGRATION_DATABASE_URL: str = ""

    # Auth
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRES_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12

    # Server
    PORT: int = 8000
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    DEBUG: bool = False
    # Cuántos proxies de confianza hay delante del motor (Railway = 1). Con 0 se usa la IP del socket.
    # Solo con un valor mayor que 0 se lee X-Forwarded-For (para los límites de ritmo y la auditoría).
    TRUSTED_PROXY_COUNT: int = 0
    MAX_REQUEST_BYTES: int = 1_000_000

    # Escaneos
    # Solo para desarrollo o redes propias: permite escanear/verificar direcciones privadas (loopback, 10/8...).
    # En un despliegue compartido tiene que quedar en false: es lo que impide usar el motor para mirar su red interna.
    ALLOW_PRIVATE_TARGETS: bool = False
    SCAN_MAX_CONCURRENT: int = 3  # escaneos corriendo a la vez en este proceso; el resto espera en "queued"
    SCAN_MAX_PER_USER: int = 2  # escaneos en curso (en cola o corriendo) por usuario
    SCAN_MAX_SECONDS: int = 900  # tope de duración; al llegar, el escaneo guarda lo que tiene y avisa que es parcial
    SCAN_MAX_HOSTS: int = 25  # hosts distintos que se escanean activamente (puertos / huella) por escaneo
    SCAN_MAX_SUBDOMAINS: int = 500  # nombres que se resuelven por escaneo
    MAX_DOMAINS_PER_USER: int = 25
    # Días que vale una verificación de dominio. 0 = no vence (comportamiento anterior). Recomendado en un servicio
    # público: 90. Al vencer hay que volver a verificar (el registro TXT publicado sigue sirviendo).
    VERIFICATION_MAX_AGE_DAYS: int = 0


settings = Settings()
