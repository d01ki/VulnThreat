"""Database bootstrap, sessions, app metadata and the (optionally fixed) clock."""

from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from tiw.storage.models import AppMeta, Base

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
DEFAULT_TIMEZONE = "Asia/Tokyo"
DEFAULT_BRAND = "VulnThreat"


@dataclass(frozen=True)
class Workspace:
    """A data directory: SQLite DB, content-addressed objects, exports, API token."""

    data_dir: Path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "tiw.db"

    @property
    def objects_dir(self) -> Path:
        return self.data_dir / "objects"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def staging_dir(self) -> Path:
        return self.data_dir / "staging"

    @property
    def token_path(self) -> Path:
        return self.data_dir / "api_token"

    @property
    def url(self) -> str:
        return f"sqlite:///{self.db_path.as_posix()}"

    def exists(self) -> bool:
        return self.db_path.exists()


def resolve_workspace(data_dir: str | os.PathLike[str] | None = None) -> Workspace:
    raw = data_dir or os.environ.get("TIW_DATA_DIR") or ".tiw"
    return Workspace(Path(raw).resolve())


_engines: dict[str, Engine] = {}


def get_engine(ws: Workspace) -> Engine:
    if ws.url not in _engines:
        engine = create_engine(ws.url, future=True)

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

        _engines[ws.url] = engine
    return _engines[ws.url]


def dispose_engine(ws: Workspace) -> None:
    engine = _engines.pop(ws.url, None)
    if engine is not None:
        engine.dispose()


def session_factory(ws: Workspace) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(ws), expire_on_commit=False, future=True)


@contextmanager
def session_scope(ws: Workspace) -> Iterator[Session]:
    session = session_factory(ws)()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def _alembic_config(ws: Workspace):  # type: ignore[no-untyped-def]
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", ws.url)
    cfg.attributes["engine"] = get_engine(ws)
    return cfg


def init_workspace(ws: Workspace, *, synthetic: bool = False) -> bool:
    """Create directories, run migrations, set metadata. Returns True if newly created.

    Never deletes data. Re-running on an existing workspace only applies pending migrations.
    """
    from alembic import command

    created = not ws.exists()
    ws.data_dir.mkdir(parents=True, exist_ok=True)
    for d in (ws.objects_dir, ws.exports_dir, ws.staging_dir):
        d.mkdir(exist_ok=True)
    command.upgrade(_alembic_config(ws), "head")
    with session_scope(ws) as s:
        if get_meta(s, "data_mode") is None:
            set_meta(s, "data_mode", "synthetic" if synthetic else "live")
            set_meta(s, "timezone", DEFAULT_TIMEZONE)
            set_meta(s, "brand_name", os.environ.get("TIW_BRAND_NAME", DEFAULT_BRAND))
            set_meta(s, "created_at", utc_iso(datetime.now(timezone.utc)))
    if not ws.token_path.exists():
        ws.token_path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    return created


def schema_problems(ws: Workspace) -> list[str]:
    """Compare the migrated schema with the ORM metadata; empty list means consistent."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    with get_engine(ws).connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": False})
        diffs = compare_metadata(ctx, Base.metadata)
        tables = set(inspect(conn).get_table_names())
    problems = [repr(d) for d in diffs]
    missing = {t.name for t in Base.metadata.sorted_tables} - tables
    problems += [f"missing table {t}" for t in sorted(missing)]
    return problems


def get_meta(s: Session, key: str) -> str | None:
    row = s.get(AppMeta, key)
    return row.value if row else None


def set_meta(s: Session, key: str, value: str) -> None:
    row = s.get(AppMeta, key)
    if row is None:
        s.add(AppMeta(key=key, value=value))
    else:
        row.value = value
    s.flush()


def get_meta_json(s: Session, key: str, default: object) -> object:
    raw = get_meta(s, key)
    return json.loads(raw) if raw else default


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime:
    """Parse ISO-8601 with explicit offset (Z allowed). Naive values are rejected."""
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone offset (e.g. Z)")
    return dt.astimezone(timezone.utc)


def now(s: Session) -> datetime:
    """Current time: the fixed clock if set (demo/tests), else wall-clock UTC."""
    fixed = get_meta(s, "clock_fixed")
    if fixed:
        return parse_utc(fixed)
    env_fixed = os.environ.get("TIW_FIXED_NOW")
    if env_fixed:
        return parse_utc(env_fixed)
    return datetime.now(timezone.utc).replace(microsecond=0)


def is_synthetic_workspace(s: Session) -> bool:
    return get_meta(s, "data_mode") == "synthetic"


def ensure_schema_present(ws: Workspace) -> None:
    if not ws.exists():
        raise FileNotFoundError(f"workspace not initialised: run `tiw init --data-dir {ws.data_dir}`")
    with session_scope(ws) as s:
        if s.execute(select(AppMeta).limit(1)).first() is None:
            raise FileNotFoundError("workspace metadata missing; run `tiw init`")
