"""Production Dual-Engine Relational State Store (PostgreSQL 16 + SQLite WAL).

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Guarantees zero data loss across process/container restarts:
- Automatically uses PostgreSQL when `GIGAMESH_DATABASE_URL=postgresql://...` is configured
  (e.g. Docker Compose / AWS ECS RDS / Kubernetes).
- Falls back cleanly to SQLite in WAL mode (`PRAGMA journal_mode=WAL; synchronous=FULL`)
  for air-gapped single-node and factory edge deployments.
- Persists tamper-evident SHA-256 hash-chained audit logs, UNS nodes/policies/contracts,
  enrolled/revoked edge devices, JIT Vendor SRA sessions & transcripts, correlated incidents,
  and multi-tenant RBAC user accounts.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class GigaMeshStateStore:
    """Thread-safe dual-engine (PostgreSQL / SQLite WAL) persistence layer."""

    def __init__(self, *, db_path: Path, database_url: str | None = None) -> None:
        self.db_path = db_path
        self.database_url = (database_url or "").strip() or None
        self.backend = "postgresql" if (self.database_url and self.database_url.startswith(("postgres://", "postgresql://"))) else "sqlite_wal"
        self._lock = threading.RLock()
        self._conn: Any = None
        self._init_connection()
        self._init_schema()

    def _init_connection(self) -> None:
        if self.backend == "postgresql":
            import psycopg

            self._conn = psycopg.connect(self.database_url, autocommit=True)
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=15.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=FULL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._conn = conn

    def _ph(self, count: int) -> str:
        tok = "%s" if self.backend == "postgresql" else "?"
        return ", ".join([tok] * count)

    def _exec(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall() if cur.description else []
            if self.backend != "postgresql":
                self._conn.commit()
            cur.close()
            return rows

    def _init_schema(self) -> None:
        stmts = [
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                seq INTEGER PRIMARY KEY,
                entry_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                actor TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS uns_nodes (
                topic TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS uns_policies (
                policy_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS uns_contracts (
                contract_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS edge_devices (
                device_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sra_sessions (
                session_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS incidents (
                case_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS rbac_users (
                username TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """,
        ]
        for s in stmts:
            self._exec(s)

    def _upsert(self, table: str, key_col: str, key_val: str, payload: dict[str, Any]) -> None:
        blob = json.dumps(payload, default=str)
        ph = self._ph(2)
        if self.backend == "postgresql":
            sql = f"INSERT INTO {table} ({key_col}, payload_json) VALUES ({ph}) ON CONFLICT ({key_col}) DO UPDATE SET payload_json = EXCLUDED.payload_json"
        else:
            sql = f"INSERT OR REPLACE INTO {table} ({key_col}, payload_json) VALUES ({ph})"
        self._exec(sql, (key_val, blob))

    def _load_all(self, table: str) -> list[dict[str, Any]]:
        rows = self._exec(f"SELECT payload_json FROM {table}")
        return [json.loads(r[0]) for r in rows]

    # ---- Audit Chain ----
    def append_audit_entry(self, seq: int, entry: dict[str, Any]) -> None:
        ph = self._ph(10)
        sql = (
            f"INSERT INTO audit_chain "
            f"(seq, entry_id, timestamp, category, severity, actor, summary, details_json, prev_hash, entry_hash) "
            f"VALUES ({ph})"
        )
        self._exec(
            sql,
            (
                seq,
                entry["entry_id"],
                entry["timestamp"],
                entry["category"],
                entry["severity"],
                entry["actor"],
                entry["summary"],
                json.dumps(entry.get("details", {}), default=str),
                entry["prev_hash"],
                entry["entry_hash"],
            ),
        )

    def load_audit_entries(self) -> list[dict[str, Any]]:
        rows = self._exec(
            "SELECT entry_id, timestamp, category, severity, actor, summary, details_json, prev_hash, entry_hash "
            "FROM audit_chain ORDER BY seq ASC"
        )
        return [
            {
                "entry_id": r[0],
                "timestamp": r[1],
                "category": r[2],
                "severity": r[3],
                "actor": r[4],
                "summary": r[5],
                "details": json.loads(r[6]),
                "prev_hash": r[7],
                "entry_hash": r[8],
            }
            for r in rows
        ]

    # ---- Domain Persistence Helpers ----
    def save_uns_node(self, topic: str, data: dict[str, Any]) -> None:
        self._upsert("uns_nodes", "topic", topic, data)

    def load_uns_nodes(self) -> list[dict[str, Any]]:
        return self._load_all("uns_nodes")

    def save_uns_policy(self, policy_id: str, data: dict[str, Any]) -> None:
        self._upsert("uns_policies", "policy_id", policy_id, data)

    def load_uns_policies(self) -> list[dict[str, Any]]:
        return self._load_all("uns_policies")

    def save_uns_contract(self, contract_id: str, data: dict[str, Any]) -> None:
        self._upsert("uns_contracts", "contract_id", contract_id, data)

    def load_uns_contracts(self) -> list[dict[str, Any]]:
        return self._load_all("uns_contracts")

    def save_edge_device(self, device_id: str, data: dict[str, Any]) -> None:
        self._upsert("edge_devices", "device_id", device_id, data)

    def load_edge_devices(self) -> list[dict[str, Any]]:
        return self._load_all("edge_devices")

    def save_sra_session(self, session_id: str, data: dict[str, Any]) -> None:
        self._upsert("sra_sessions", "session_id", session_id, data)

    def load_sra_sessions(self) -> list[dict[str, Any]]:
        return self._load_all("sra_sessions")

    def save_incident(self, case_id: str, data: dict[str, Any]) -> None:
        self._upsert("incidents", "case_id", case_id, data)

    def load_incidents(self) -> list[dict[str, Any]]:
        return self._load_all("incidents")

    # ---- Multi-Tenant RBAC Users ----
    def save_user(self, username: str, tenant_id: str, role: str, password_hash: str, created_at: str) -> None:
        ph = self._ph(6)
        if self.backend == "postgresql":
            sql = (
                f"INSERT INTO rbac_users (username, tenant_id, role, password_hash, enabled, created_at) "
                f"VALUES ({ph}) ON CONFLICT (username) DO UPDATE SET role=EXCLUDED.role, password_hash=EXCLUDED.password_hash"
            )
        else:
            sql = (
                f"INSERT OR REPLACE INTO rbac_users (username, tenant_id, role, password_hash, enabled, created_at) "
                f"VALUES ({ph})"
            )
        self._exec(sql, (username, tenant_id, role, password_hash, 1, created_at))

    def load_users(self) -> list[dict[str, Any]]:
        rows = self._exec("SELECT username, tenant_id, role, password_hash, enabled, created_at FROM rbac_users")
        return [
            {
                "username": r[0],
                "tenant_id": r[1],
                "role": r[2],
                "password_hash": r[3],
                "enabled": bool(r[4]),
                "created_at": r[5],
            }
            for r in rows
        ]

    def health(self) -> dict[str, Any]:
        try:
            self._exec("SELECT 1")
            return {"ok": True, "backend": self.backend, "path": str(self.db_path) if self.backend != "postgresql" else "postgresql"}
        except Exception as exc:
            return {"ok": False, "backend": self.backend, "error": str(exc)}

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
