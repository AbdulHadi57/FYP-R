import os
import sqlite3
import threading
from pathlib import Path

# Database path from env or default relative to CWD.
DB_PATH = Path(os.getenv("AEGIS_DB_PATH", "data/aegisnet_live.db"))

# Module-level flag so schema init runs exactly once.
_schema_initialized = False
_schema_lock = threading.Lock()


def get_db_connection():
    """Return a SQLite connection.  Schema is initialised on first call only."""
    global _schema_initialized

    selected_path = DB_PATH
    if not selected_path.exists():
        selected_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(selected_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent-read perf

    if not _schema_initialized:
        with _schema_lock:
            if not _schema_initialized:
                _init_schema(conn)
                _schema_initialized = True
    return conn


def _init_schema(conn):
    """Initialize database schema if not exists."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol INTEGER,
            total_packets INTEGER,
            flow_duration REAL,
            ja4 TEXT,
            ja4s TEXT,
            ja4h TEXT,
            ja4_pred TEXT DEFAULT 'none',
            doh_pred TEXT DEFAULT 'none',
            apt_pred TEXT DEFAULT 'none',
            verdict TEXT,
            confidence REAL,
            severity REAL,
            summary TEXT,
            features_json TEXT,
            is_resolved INTEGER DEFAULT 0,
            resolution_note TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS module_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER,
            module_name TEXT,
            label TEXT,
            confidence REAL,
            score REAL,
            rationale TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(flow_id) REFERENCES flows(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            os_type TEXT,
            os_version TEXT,
            agent_version TEXT,
            domain_fqdn TEXT,
            dc_hint TEXT,
            dc_id TEXT,
            primary_ip TEXT,
            ip_addresses_json TEXT,
            interfaces_json TEXT,
            capabilities_json TEXT,
            auth_token TEXT NOT NULL,
            status TEXT DEFAULT 'offline',
            last_seen TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS domain_controllers (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            fqdn TEXT,
            domain_fqdn TEXT,
            forest_fqdn TEXT,
            site_name TEXT,
            os_version TEXT,
            runner_version TEXT,
            capabilities_json TEXT,
            auth_token TEXT NOT NULL,
            approval_status TEXT DEFAULT 'pending',
            approved_by TEXT,
            approved_at TEXT,
            status TEXT DEFAULT 'offline',
            last_seen TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            node_type TEXT NOT NULL,
            status TEXT,
            payload_json TEXT,
            captured_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS action_jobs (
            id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            payload_json TEXT,
            status TEXT DEFAULT 'queued',
            approval_required INTEGER DEFAULT 0,
            approval_status TEXT DEFAULT 'not_required',
            requested_by TEXT,
            reason TEXT,
            rollback_action_type TEXT,
            rollback_payload_json TEXT,
            rollback_of_action_id TEXT,
            result_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            dispatched_at TEXT,
            completed_at TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS action_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT NOT NULL,
            approved_by TEXT NOT NULL,
            approved INTEGER NOT NULL,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(action_id) REFERENCES action_jobs(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS action_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT,
            event_type TEXT NOT NULL,
            actor TEXT,
            target_info TEXT,
            details_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_dc_bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            dc_id TEXT NOT NULL,
            binding_source TEXT DEFAULT 'agent_hint',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(agent_id) REFERENCES agents(id),
            FOREIGN KEY(dc_id) REFERENCES domain_controllers(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS response_templates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            target_action_type TEXT NOT NULL,
            default_payload_json TEXT,
            require_approval INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Baseline templates can be customized via API later.
    conn.execute(
        """
        INSERT OR IGNORE INTO response_templates (
            id, name, description, target_action_type, default_payload_json, require_approval, enabled
        ) VALUES (
            'tpl_isolate_host',
            'isolate_host_default',
            'Isolate target host network access via responsible DC runner',
            'isolate_host',
            '{}',
            0,
            1
        )
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO response_templates (
            id, name, description, target_action_type, default_payload_json, require_approval, enabled
        ) VALUES (
            'tpl_restore_host',
            'restore_host_default',
            'Restore target host network access via responsible DC runner',
            'restore_host',
            '{}',
            0,
            1
        )
        """
    )

    # Lightweight migrations for existing databases.
    _ensure_column(conn, "action_jobs", "approval_required", "INTEGER DEFAULT 0")
    _ensure_column(conn, "action_jobs", "approval_status", "TEXT DEFAULT 'not_required'")
    _ensure_column(conn, "action_jobs", "rollback_action_type", "TEXT")
    _ensure_column(conn, "action_jobs", "rollback_payload_json", "TEXT")
    _ensure_column(conn, "action_jobs", "rollback_of_action_id", "TEXT")
    _ensure_column(conn, "domain_controllers", "approval_status", "TEXT DEFAULT 'pending'")
    _ensure_column(conn, "domain_controllers", "approved_by", "TEXT")
    _ensure_column(conn, "domain_controllers", "approved_at", "TEXT")
    _ensure_column(conn, "agents", "dc_id", "TEXT")
    _ensure_column(conn, "agents", "primary_ip", "TEXT")
    _ensure_column(conn, "agents", "ip_addresses_json", "TEXT")
    _ensure_column(conn, "action_audit_logs", "target_info", "TEXT")
    conn.commit()


def _ensure_column(conn, table_name: str, column_name: str, column_def: str):
    cols = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {row[1] for row in cols}
    if column_name not in existing:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")
