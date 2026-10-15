from app.database import migration_engine_args


def test_asyncpg_url_becomes_psycopg2_and_requires_ssl_by_default():
    url, args = migration_engine_args("postgresql+asyncpg://u:p@db.example.com:5432/app")
    assert url.drivername == "postgresql+psycopg2"
    assert args == {"sslmode": "require"}


def test_asyncpg_ssl_param_is_dropped():
    url, args = migration_engine_args("postgresql+asyncpg://u:p@db.example.com/app?ssl=require")
    assert "ssl" not in url.query
    assert args == {"sslmode": "require"}


def test_heroku_style_scheme_is_accepted():
    url, _ = migration_engine_args("postgres://u:p@db.example.com/app")
    assert url.drivername == "postgresql+psycopg2"


def test_local_postgres_without_ssl_opts_out_in_the_url():
    """El docker-compose usa Postgres sin SSL: lo indica con ?sslmode=disable y no se le fuerza otra cosa."""
    url, args = migration_engine_args(
        "postgresql+asyncpg://recon:recon@postgres:5432/recon",
        "postgresql+psycopg2://recon:recon@postgres:5432/recon?sslmode=disable",
    )
    assert url.query["sslmode"] == "disable"
    assert args == {}


def test_migration_url_wins_over_database_url():
    url, _ = migration_engine_args("postgresql+asyncpg://u:p@a/app", "postgresql://u:p@b/app?sslmode=verify-full")
    assert url.host == "b"
    assert url.query["sslmode"] == "verify-full"
