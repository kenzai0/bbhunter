"""
SQLite tabanli bulgu deposu. Dedup saglar: ayni (kategori, hedef, imza)
tekrar eklenmez. Taramalar arasi kalici kayit tutar.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT UNIQUE,
    category TEXT,
    name TEXT,
    severity TEXT,
    target TEXT,
    detail TEXT,
    data TEXT,
    first_seen REAL,
    last_seen REAL
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT UNIQUE,
    kind TEXT,          -- subdomain | host | url | port | param | endpoint
    value TEXT,
    data TEXT,
    first_seen REAL
);
CREATE TABLE IF NOT EXISTS stages (
    stage_key TEXT PRIMARY KEY,
    stage TEXT,
    signature TEXT,
    meta TEXT,
    done_at REAL
);
CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_asset_kind ON assets(kind);
"""


def _key(*parts: str) -> str:
    return hashlib.sha1("||".join(parts).encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- assetler ----
    def add_asset(self, kind: str, value: str, data: dict | None = None) -> bool:
        key = _key(kind, value)
        try:
            self.conn.execute(
                "INSERT INTO assets(dedup_key, kind, value, data, first_seen) "
                "VALUES(?,?,?,?,?)",
                (key, kind, value, json.dumps(data or {}), time.time()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # zaten var

    def add_assets(self, kind: str, values: list[str]) -> int:
        n = 0
        for v in values:
            if self.add_asset(kind, v):
                n += 1
        return n

    def assets(self, kind: str | None = None) -> list[dict]:
        q = "SELECT kind, value, data, first_seen FROM assets"
        args: tuple = ()
        if kind:
            q += " WHERE kind=?"
            args = (kind,)
        q += " ORDER BY value"
        rows = self.conn.execute(q, args).fetchall()
        return [
            {"kind": r[0], "value": r[1], "data": json.loads(r[2] or "{}"), "first_seen": r[3]}
            for r in rows
        ]

    # ---- bulgular ----
    def add_finding(
        self, category: str, name: str, severity: str, target: str,
        detail: str = "", data: dict | None = None,
    ) -> bool:
        key = _key(category, target, name, detail[:120])
        now = time.time()
        cur = self.conn.execute("SELECT id FROM findings WHERE dedup_key=?", (key,))
        row = cur.fetchone()
        if row:
            self.conn.execute("UPDATE findings SET last_seen=? WHERE id=?", (now, row[0]))
            self.conn.commit()
            return False
        self.conn.execute(
            "INSERT INTO findings(dedup_key, category, name, severity, target, detail, data, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (key, category, name, severity, target, detail, json.dumps(data or {}), now, now),
        )
        self.conn.commit()
        return True

    def findings(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT category, name, severity, target, detail, data, first_seen, last_seen "
            "FROM findings ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, target"
        ).fetchall()
        return [
            {
                "category": r[0], "name": r[1], "severity": r[2], "target": r[3],
                "detail": r[4], "data": json.loads(r[5] or "{}"),
                "first_seen": r[6], "last_seen": r[7],
            }
            for r in rows
        ]

    def stats(self) -> dict:
        out = {"assets": {}, "findings": {}}
        for kind, n in self.conn.execute(
            "SELECT kind, COUNT(*) FROM assets GROUP BY kind"
        ):
            out["assets"][kind] = n
        for sev, n in self.conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ):
            out["findings"][sev] = n
        return out

    # ---- asamalar (resume/incremental) ----
    def mark_stage(self, stage: str, signature: str, meta: dict | None = None) -> None:
        key = f"{stage}:{signature}"
        self.conn.execute(
            "INSERT OR REPLACE INTO stages(stage_key, stage, signature, meta, done_at) "
            "VALUES(?,?,?,?,?)",
            (key, stage, signature, json.dumps(meta or {}), time.time()),
        )
        self.conn.commit()

    def is_stage_done(self, stage: str, signature: str) -> bool:
        key = f"{stage}:{signature}"
        row = self.conn.execute(
            "SELECT 1 FROM stages WHERE stage_key=?", (key,)
        ).fetchone()
        return row is not None

    def stages(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT stage, signature, meta, done_at FROM stages ORDER BY done_at"
        ).fetchall()
        return [
            {"stage": r[0], "signature": r[1], "meta": json.loads(r[2] or "{}"),
             "done_at": r[3]}
            for r in rows
        ]

    def clear_stages(self, signature: str | None = None) -> int:
        if signature is None:
            cur = self.conn.execute("DELETE FROM stages")
        else:
            cur = self.conn.execute("DELETE FROM stages WHERE signature=?", (signature,))
        self.conn.commit()
        return cur.rowcount

    def close(self) -> None:
        self.conn.close()
