from collections.abc import Generator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def _ensure_sqlite_parent(database_url: str) -> None:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix) or database_url.startswith("sqlite:///:memory:"):
        return
    database_path = Path(database_url.removeprefix(prefix))
    if database_path.parent != Path("."):
        database_path.parent.mkdir(parents=True, exist_ok=True)


class Database:
    """Owns the SQLAlchemy engine and transaction-scoped sessions."""

    def __init__(self, database_url: str) -> None:
        _ensure_sqlite_parent(database_url)
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(database_url, connect_args=connect_args)
        if database_url.startswith("sqlite"):
            event.listen(self.engine, "connect", self._enable_sqlite_foreign_keys)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )

    @staticmethod
    def _enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def create_schema(self) -> None:
        from app.storage import models  # noqa: F401

        Base.metadata.create_all(self.engine)

    def drop_schema(self) -> None:
        from app.storage import models  # noqa: F401

        Base.metadata.drop_all(self.engine)

    def sessions(self) -> Generator[Session, None, None]:
        with self.session_factory() as session:
            yield session

    def dispose(self) -> None:
        self.engine.dispose()
