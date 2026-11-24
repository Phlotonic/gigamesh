"""Tamper-Evident SHA-256 Hash-Chained Security Audit Trail (OWASP A09:2025).

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SecurityAuditEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: f"aud-{uuid4().hex[:10]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    category: str  # auth_failure | rate_limit | circuit_breaker | owasp_block | exception | access_denied
    severity: str = "high"
    actor: str = "unknown"
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str


class HashChainedSecurityAuditLog:
    """Append-only SHA-256 hash-chained audit trail persisted durably across restarts."""

    def __init__(self, max_entries: int = 2000, state_store: Any = None) -> None:
        self._lock = threading.RLock()
        self._state_store = state_store
        self._entries: list[SecurityAuditEntry] = []
        self._max_entries = max_entries
        self._head_hash = "0" * 64
        self._seq = 0
        if self._state_store is not None:
            for row in self._state_store.load_audit_entries():
                entry = SecurityAuditEntry(**row)
                self._entries.append(entry)
                self._head_hash = entry.entry_hash
                self._seq += 1
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries :]

    def record(
        self,
        *,
        category: str,
        summary: str,
        severity: str = "high",
        actor: str = "system",
        details: dict[str, Any] | None = None,
    ) -> SecurityAuditEntry:
        with self._lock:
            ts = datetime.now(timezone.utc).isoformat()
            eid = f"aud-{uuid4().hex[:10]}"
            prev = self._head_hash
            safe_details = details or {}
            canonical = json.dumps(
                {
                    "entry_id": eid,
                    "timestamp": ts,
                    "category": category,
                    "severity": severity,
                    "actor": actor,
                    "summary": summary,
                    "details": safe_details,
                    "prev_hash": prev,
                },
                sort_keys=True,
                default=str,
            )
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            entry = SecurityAuditEntry(
                entry_id=eid,
                timestamp=ts,
                category=category,
                severity=severity,
                actor=actor,
                summary=summary,
                details=safe_details,
                prev_hash=prev,
                entry_hash=digest,
            )
            self._head_hash = digest
            self._seq += 1
            self._entries.append(entry)
            if self._state_store is not None:
                self._state_store.append_audit_entry(self._seq, entry.model_dump(mode="json"))
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries :]
            return entry

    def verify_chain(self) -> dict[str, Any]:
        with self._lock:
            if not self._entries:
                return {"valid": True, "entries": 0, "head_hash": self._head_hash}
            for idx, entry in enumerate(self._entries):
                if idx > 0 and entry.prev_hash != self._entries[idx - 1].entry_hash:
                    return {"valid": False, "entries": len(self._entries), "broken_at": idx}
                canonical = json.dumps(
                    {
                        "entry_id": entry.entry_id,
                        "timestamp": entry.timestamp,
                        "category": entry.category,
                        "severity": entry.severity,
                        "actor": entry.actor,
                        "summary": entry.summary,
                        "details": entry.details,
                        "prev_hash": entry.prev_hash,
                    },
                    sort_keys=True,
                    default=str,
                )
                expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if expected != entry.entry_hash:
                    return {"valid": False, "entries": len(self._entries), "broken_at": idx}
            return {"valid": True, "entries": len(self._entries), "head_hash": self._head_hash}

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [e.model_dump(mode="json") for e in reversed(self._entries[-limit:])]
