import sqlite3
from pathlib import Path
from typing import Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'discovered',
    score INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);
CREATE INDEX IF NOT EXISTS idx_urls_score ON urls(score DESC);
CREATE TABLE IF NOT EXISTS url_checks (
    url TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    http_status INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT ''
);
"""


class URLStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def add(self, url: str, host: str, source: str, seen_at: str, status: str = "discovered") -> bool:
        cur = self.db.execute(
            """INSERT INTO urls(url, host, source, first_seen, last_seen, status)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET last_seen=excluded.last_seen""",
            (url, host, source, seen_at, seen_at, status),
        )
        self.db.commit()
        return cur.rowcount > 0

    def add_many(self, rows: Iterable[tuple[str, str, str, str, str]]) -> int:
        count = 0
        for row in rows:
            if self.add(*row):
                count += 1
        return count

    def set_score(self, url: str, score: int, reasons: list[str]) -> None:
        self.db.execute("UPDATE urls SET score=?, reasons=? WHERE url=?", (score, "; ".join(reasons), url))
        self.db.commit()

    def rows(self, minimum_score: int = 0) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM urls WHERE score >= ? ORDER BY score DESC, url", (minimum_score,)))

    def rows_for_report(self, minimum_score: int = 0, live_only: bool = True) -> list[sqlite3.Row]:
        if live_only:
            return list(self.db.execute(
                """SELECT u.*, c.status AS validation_status, c.http_status, c.checked_at
                   FROM urls u JOIN url_checks c ON c.url = u.url
                   WHERE u.score >= ? AND c.status = 'live'
                   ORDER BY u.score DESC, u.url""",
                (minimum_score,),
            ))
        return self.rows(minimum_score)

    def save_check(self, url: str, status: str, http_status: int, checked_at: str, error: str = "") -> None:
        self.db.execute(
            """INSERT INTO url_checks(url, status, http_status, checked_at, error)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET status=excluded.status,
                 http_status=excluded.http_status, checked_at=excluded.checked_at, error=excluded.error""",
            (url, status, http_status, checked_at, error),
        )
        self.db.commit()

    def check_counts(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT status, count(*) AS count FROM url_checks GROUP BY status ORDER BY status"))

    def source_counts(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT source, count(*) AS count FROM urls GROUP BY source ORDER BY count DESC, source"))

    def host_inventory(self) -> list[sqlite3.Row]:
        return list(self.db.execute(
            """SELECT u.host,
                      count(*) AS url_count,
                      group_concat(DISTINCT u.source) AS sources,
                      max(c.status) AS validation_status,
                      max(c.http_status) AS http_status
               FROM urls u
               LEFT JOIN url_checks c ON c.url = u.url
               GROUP BY u.host
               ORDER BY u.host"""
        ))

    def close(self) -> None:
        self.db.close()
