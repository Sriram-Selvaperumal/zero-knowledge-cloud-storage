from sqlalchemy import inspect

from app.database.database import engine


def test_migration_creates_expected_tables() -> None:
    table_names = set(inspect(engine).get_table_names())

    assert "users" in table_names
    assert "file_metadata" in table_names
    assert "alembic_version" in table_names
