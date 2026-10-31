"""Alembic environment. Uses the engine passed in by tiw.storage.db when available."""

from alembic import context
from sqlalchemy import create_engine

from tiw.storage.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    engine = config.attributes.get("engine") or create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        connection.commit()


run_migrations_online()
