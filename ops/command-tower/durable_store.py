"""Local SQLite durability adapter for the isolated DRAFT_HOLD runtime.

This is a same-user sandbox fixture, not tamper-proof storage or an OS identity
boundary. It stores no credentials and performs no network or Worker actions.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from isolated_runtime import JournalEntry, _digest


class PermitAlreadyConsumed(RuntimeError):
    """A durable permit digest has already been consumed."""


class PersistentJournal:
    def __init__(self, store: "DurableStore") -> None:
        self._store = store

    @property
    def entries(self) -> tuple[JournalEntry, ...]:
        rows = self._store._connection.execute(
            "SELECT sequence, event, payload, previous_hash, entry_hash FROM journal ORDER BY sequence"
        ).fetchall()
        return tuple(JournalEntry(
            row[0], row[1], tuple(tuple(pair) for pair in json.loads(row[2])), row[3], row[4]
        ) for row in rows)

    def append(self, event: str, **payload: str) -> JournalEntry:
        return self._store.append_event(event, **payload)

    def verify(self) -> bool:
        previous = "0" * 64
        for sequence, entry in enumerate(self.entries, start=1):
            if entry.sequence != sequence or entry.previous_hash != previous:
                return False
            body = {
                "sequence": entry.sequence,
                "event": entry.event,
                "payload": list(entry.payload),
                "previous_hash": entry.previous_hash,
            }
            if entry.entry_hash != _digest(body):
                return False
            previous = entry.entry_hash
        return True


class DurableStore:
    """SQLite journal, atomic permit consumption, and restart fail-closed state."""

    PermitAlreadyConsumed = PermitAlreadyConsumed

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=DELETE")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS journal ("
            "sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, payload TEXT NOT NULL, "
            "previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS consumed_permits ("
            "permit_digest TEXT PRIMARY KEY, consumed_at_entry INTEGER NOT NULL);"
        )
        self.journal = PersistentJournal(self)
        self._recover_or_start()

    @property
    def state(self) -> str:
        row = self._connection.execute("SELECT value FROM metadata WHERE key='state'").fetchone()
        return row[0] if row else "SAFE_STOPPED"

    @property
    def stop_reason(self) -> str | None:
        row = self._connection.execute("SELECT value FROM metadata WHERE key='stop_reason'").fetchone()
        return row[0] if row and row[0] else None

    def _recover_or_start(self) -> None:
        self._begin()
        try:
            row = self._connection.execute(
                "SELECT value FROM metadata WHERE key='state'"
            ).fetchone()
            if row is None:
                self._set_metadata("state", "DRAFT_HOLD")
                self._set_metadata("stop_reason", "")
                self._append_in_transaction("SESSION_STARTED", state="DRAFT_HOLD")
            elif row[0] == "DRAFT_HOLD":
                self._set_metadata("state", "SAFE_STOPPED")
                self._set_metadata("stop_reason", "unclean_restart")
                self._append_in_transaction("SAFE_STOP", reason="unclean_restart")
            elif row[0] == "CLOSED":
                self._set_metadata("state", "DRAFT_HOLD")
                self._set_metadata("stop_reason", "")
                self._append_in_transaction("SESSION_STARTED", state="DRAFT_HOLD")
            elif row[0] not in {"SAFE_STOPPED"}:
                self._set_metadata("state", "SAFE_STOPPED")
                self._set_metadata("stop_reason", "invalid_persisted_state")
                self._append_in_transaction("SAFE_STOP", reason="invalid_persisted_state")
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def append_event(self, event: str, **payload: str) -> JournalEntry:
        if not event or any(not isinstance(k, str) or not isinstance(v, str) for k, v in payload.items()):
            raise ValueError("journal accepts a named event and string payload only")
        self._begin()
        try:
            entry = self._append_in_transaction(event, **payload)
            self._connection.execute("COMMIT")
            return entry
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def consume_permit_and_record(self, permit_digest: str, **plan_payload: str) -> None:
        """Consume once and append both events in one durable transaction."""
        if not permit_digest:
            raise ValueError("permit digest is required")
        self._begin()
        try:
            if self.state != "DRAFT_HOLD":
                raise RuntimeError("durable runtime is not active")
            cursor = self._connection.execute(
                "SELECT 1 FROM consumed_permits WHERE permit_digest=?", (permit_digest,)
            ).fetchone()
            if cursor:
                raise PermitAlreadyConsumed(permit_digest)
            consumed_entry = self._append_in_transaction("PERMIT_CONSUMED", permit_digest=permit_digest)
            self._connection.execute(
                "INSERT INTO consumed_permits(permit_digest, consumed_at_entry) VALUES (?, ?)",
                (permit_digest, consumed_entry.sequence),
            )
            self._append_in_transaction("LOCAL_PLAN_PREPARED", **plan_payload)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def safe_stop(self, reason: str) -> None:
        self._begin()
        try:
            if self.state != "SAFE_STOPPED":
                self._set_metadata("state", "SAFE_STOPPED")
                self._set_metadata("stop_reason", reason)
                self._append_in_transaction("SAFE_STOP", reason=reason)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def close_cleanly(self) -> None:
        """Mark an active test session cleanly closed; never clears consumed permits."""
        self._begin()
        try:
            if self.state == "DRAFT_HOLD":
                self._set_metadata("state", "CLOSED")
                self._append_in_transaction("SESSION_CLOSED", state="CLOSED")
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._connection.close()

    def _begin(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def _set_metadata(self, key: str, value: str) -> None:
        self._connection.execute(
            "INSERT INTO metadata(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value)
        )

    def _append_in_transaction(self, event: str, **payload: str) -> JournalEntry:
        entries = self.journal.entries
        previous = entries[-1].entry_hash if entries else "0" * 64
        sequence = len(entries) + 1
        stable_payload = tuple(sorted(payload.items()))
        body: dict[str, Any] = {
            "sequence": sequence, "event": event,
            "payload": list(stable_payload), "previous_hash": previous,
        }
        entry_hash = _digest(body)
        self._connection.execute(
            "INSERT INTO journal(sequence, event, payload, previous_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (sequence, event, json.dumps(list(stable_payload), separators=(",", ":")), previous, entry_hash),
        )
        return JournalEntry(sequence, event, stable_payload, previous, entry_hash)
