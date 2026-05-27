from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyUrl


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database — use postgresql+asyncpg:// scheme for async driver
    DATABASE_URL: str

    # Auth
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRES_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12

    # Server
    PORT: int = 8000
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    DEBUG: bool = False


settings = Settings()
