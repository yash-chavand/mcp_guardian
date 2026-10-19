"""
Persistent Storage Engine for MCP Guardian V2 (SQLite + JSONL).
"""

import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from ..core.events import SecurityEvent, hash_identifier


class SecurityStorage:
    """Pluggable persistence engine for security events, tool profiles, baselines and graph records."""

    def __init__(self, db_path: Optional[Path] = None, jsonl_path: Optional[Path] = None):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        if self.db_path:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
        if self.jsonl_path:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    tokenized_session_id TEXT NOT NULL,
                    agent_id TEXT,
                    server_id TEXT,
                    tool_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    sub_scores_json TEXT,
                    reasons_json TEXT,
                    evidence_json TEXT,
                    latency_ms REAL
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_session ON security_events(session_id);
                CREATE INDEX IF NOT EXISTS idx_events_decision ON security_events(decision);
                CREATE INDEX IF NOT EXISTS idx_events_risk_level ON security_events(risk_level);

                CREATE TABLE IF NOT EXISTS tool_profiles (
                    tool_name TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL,
                    schema_hash TEXT NOT NULL,
                    profile_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baseline_metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_type TEXT NOT NULL,
                    mean REAL NOT NULL,
                    std REAL NOT NULL,
                    count INTEGER NOT NULL,
                    last_updated TEXT NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS drift_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    old_value REAL,
                    new_value REAL,
                    drift_score REAL,
                    status TEXT NOT NULL
                );
            """)

    def save_event(self, event: SecurityEvent):
        """Save event to SQLite and JSONL."""
        if self.jsonl_path:
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event.to_dict()) + "\n")
            except Exception as e:
                print(f"[Storage] JSONL write error: {e}")

        if self.db_path:
            try:
                with self._get_conn() as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_events (
                            event_id, timestamp, correlation_id, session_id,
                            tokenized_session_id, agent_id, server_id, tool_name,
                            event_type, risk_score, risk_level, decision,
                            sub_scores_json, reasons_json, evidence_json, latency_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id, event.timestamp, event.correlation_id,
                        event.tokenized_session_id, event.tokenized_session_id, event.tokenized_agent_id,
                        event.server_id, event.tool_name, event.event_type,
                        event.risk_score, event.risk_level, event.decision,
                        json.dumps(event.sub_scores), json.dumps(event.reasons),
                        json.dumps(event.evidence), event.latency_ms
                    ))
            except Exception as e:
                print(f"[Storage] SQLite write error: {e}")

    def get_events(self, limit: int = 50, decision: Optional[str] = None,
                   risk_level: Optional[str] = None, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent security events with filtering."""
        if not self.db_path or not self.db_path.exists():
            return []

        query = "SELECT * FROM security_events WHERE 1=1"
        params = []

        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        if session_id:
            query += " AND session_id = ?"
            params.append(hash_identifier(session_id))

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
            events = []
            for r in rows:
                ev = dict(r)
                ev["sub_scores"] = json.loads(ev.pop("sub_scores_json") or "{}")
                ev["reasons"] = json.loads(ev.pop("reasons_json") or "[]")
                ev["evidence"] = json.loads(ev.pop("evidence_json") or "{}")
                events.append(ev)
            return events

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        if not self.db_path:
            return None
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,)).fetchone()
            if not row:
                return None
            ev = dict(row)
            ev["sub_scores"] = json.loads(ev.pop("sub_scores_json") or "{}")
            ev["reasons"] = json.loads(ev.pop("reasons_json") or "[]")
            ev["evidence"] = json.loads(ev.pop("evidence_json") or "{}")
            return ev

    def save_tool_profile(self, tool_name: str, server_id: str, schema_hash: str, profile: Dict[str, Any]):
        if not self.db_path:
            return
        now = datetime.utcnow().isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO tool_profiles (
                    tool_name, server_id, schema_hash, profile_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, COALESCE((SELECT created_at FROM tool_profiles WHERE tool_name = ?), ?), ?)
            """, (tool_name, server_id, schema_hash, json.dumps(profile), tool_name, now, now))

    def get_tool_profiles(self) -> Dict[str, Dict[str, Any]]:
        if not self.db_path:
            return {}
        with self._get_conn() as conn:
            rows = conn.execute("SELECT tool_name, schema_hash, profile_json, updated_at FROM tool_profiles").fetchall()
            profiles = {}
            for r in rows:
                profiles[r["tool_name"]] = {
                    "schema_hash": r["schema_hash"],
                    "updated_at": r["updated_at"],
                    "profile": json.loads(r["profile_json"])
                }
            return profiles
