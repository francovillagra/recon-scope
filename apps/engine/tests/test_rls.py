"""Row Level Security: ninguna tabla queda expuesta a los roles de la API de datos de Supabase.

Supabase publica el esquema `public` por PostgREST con una clave pública (`anon`). Sin RLS ni permisos revocados,
cualquiera con esa clave puede leer y escribir estas tablas (hashes de contraseña incluidos) sin pasar por el motor.
El motor se conecta como dueño de las tablas (el usuario `postgres`), al que RLS no le aplica.
"""
import importlib.util
import pathlib

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clean_db")]

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions" / "006_enable_rls.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_006_enable_rls", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CREATE_ROLE = """
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
    CREATE ROLE {role} NOLOGIN;
  END IF;
END $$
"""


async def _only_if_superuser(conn):
    if (await conn.execute(text("SELECT current_setting('is_superuser')"))).scalar() != "on":
        pytest.skip("hace falta un usuario con permiso para crear roles (en CI es postgres)")


async def test_every_table_in_the_schema_has_row_level_security(db_engine):
    """Guarda para el futuro: una migración nueva que cree una tabla sin habilitar RLS hace fallar esta prueba."""
    async with db_engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = current_schema() AND c.relkind = 'r' AND NOT c.relrowsecurity ORDER BY 1"
        ))
        without_rls = [r[0] for r in rows]
    assert without_rls == [], f"tablas sin RLS: {without_rls}"


async def test_the_migration_covers_every_table_the_models_define():
    from app.models import Base

    migration = _load_migration()
    assert set(Base.metadata.tables) <= set(migration.TABLES)


async def test_supabase_api_roles_lose_access_to_every_table(db_engine):
    migration = _load_migration()
    async with db_engine.connect() as conn:
        await _only_if_superuser(conn)
        try:
            for role in ("anon", "authenticated"):
                await conn.exec_driver_sql(CREATE_ROLE.format(role=role))
            # Lo que Supabase concede por defecto a las tablas nuevas del esquema public:
            await conn.exec_driver_sql(
                f"GRANT ALL ON {', '.join(migration.TABLES)} TO anon, authenticated"
            )
            await conn.exec_driver_sql(migration.HARDEN_SQL)

            for role in ("anon", "authenticated"):
                await conn.exec_driver_sql(f"SET LOCAL ROLE {role}")
                for table in migration.TABLES:
                    savepoint = await conn.begin_nested()
                    with pytest.raises(DBAPIError, match="permission denied"):
                        await conn.exec_driver_sql(f"SELECT 1 FROM {table} LIMIT 1")
                    await savepoint.rollback()
                await conn.exec_driver_sql("RESET ROLE")
        finally:
            await conn.rollback()


async def test_a_role_that_still_has_privileges_sees_no_rows(db_engine):
    """RLS sin políticas: lo que no sea el dueño no ve filas aunque tenga permiso sobre la tabla."""
    migration = _load_migration()
    async with db_engine.connect() as conn:
        await _only_if_superuser(conn)
        try:
            await conn.exec_driver_sql(CREATE_ROLE.format(role="rls_probe"))
            await conn.exec_driver_sql("GRANT SELECT ON users TO rls_probe")
            await conn.exec_driver_sql("INSERT INTO users (email, password_hash) VALUES ('rls@example.com', 'x')")
            await conn.exec_driver_sql("ALTER TABLE users DISABLE ROW LEVEL SECURITY")

            await conn.exec_driver_sql("SET LOCAL ROLE rls_probe")
            assert (await conn.exec_driver_sql("SELECT count(*) FROM users")).scalar() == 1  # sin RLS: lo ve
            await conn.exec_driver_sql("RESET ROLE")

            await conn.exec_driver_sql(migration.HARDEN_SQL)

            await conn.exec_driver_sql("SET LOCAL ROLE rls_probe")
            assert (await conn.exec_driver_sql("SELECT count(*) FROM users")).scalar() == 0  # con RLS: no
            await conn.exec_driver_sql("RESET ROLE")
            # El dueño (el motor) sigue viendo todo.
            assert (await conn.exec_driver_sql("SELECT count(*) FROM users")).scalar() == 1
        finally:
            await conn.rollback()


async def test_the_migration_can_run_twice(db_engine):
    migration = _load_migration()
    async with db_engine.connect() as conn:
        try:
            await conn.exec_driver_sql(migration.HARDEN_SQL)
            await conn.exec_driver_sql(migration.HARDEN_SQL)
        finally:
            await conn.rollback()
