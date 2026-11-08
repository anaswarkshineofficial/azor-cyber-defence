import sqlite3
from datetime import datetime, timezone
from app.config import DATABASE_PATH

ALLOWED_STATUSES = {
    "new", "reviewing", "submitted_to_platform",
    "referred_to_authority", "closed", "false_positive"
}
ALLOWED_TARGETS = {"group", "channel", "bot", "account"}
ALLOWED_SOURCES = {"community_report", "public_observation"}

def now():
    return datetime.now(timezone.utc).isoformat()

def connect():
    con = sqlite3.connect(DATABASE_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            reporter_telegram_id INTEGER,
            category TEXT NOT NULL,
            target_type TEXT NOT NULL,
            public_link TEXT,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            reviewer_note TEXT,
            source TEXT NOT NULL DEFAULT 'community_report'
        )
        """)
        # Upgrade databases created by Phase 1 without destroying existing cases.
        columns = {row["name"] for row in con.execute("PRAGMA table_info(reports)")}
        if "source" not in columns:
            con.execute("ALTER TABLE reports ADD COLUMN source TEXT NOT NULL DEFAULT 'community_report'")
        con.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            report_id INTEGER
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS enforcement_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'prepared',
            destination TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            actor TEXT NOT NULL,
            reviewer_note TEXT,
            FOREIGN KEY(report_id) REFERENCES reports(id)
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS intel_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            display_value TEXT NOT NULL,
            actor TEXT NOT NULL,
            UNIQUE(report_id, indicator_type, normalized_value),
            FOREIGN KEY(report_id) REFERENCES reports(id)
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS case_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_a INTEGER NOT NULL,
            case_b INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(case_a, case_b, reason)
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS evidence_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            digest TEXT NOT NULL,
            description TEXT NOT NULL,
            actor TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES reports(id)
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS blackshield_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            label TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            scope TEXT NOT NULL,
            owner TEXT NOT NULL,
            authorization_basis TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            notes TEXT NOT NULL DEFAULT ''
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS blackshield_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            report_id INTEGER,
            note_type TEXT NOT NULL,
            reference TEXT NOT NULL,
            observation TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'unverified',
            actor TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES reports(id)
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS case_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL
        )
        """)

def audit(actor, action, report_id=None):
    with connect() as con:
        con.execute(
            "INSERT INTO audit_log (created_at, actor, action, report_id) VALUES (?, ?, ?, ?)",
            (now(), actor[:100], action[:200], report_id)
        )

def create_report(reporter_id, category, target_type, public_link, description,
                  source="community_report", actor="telegram_bot"):
    if target_type not in ALLOWED_TARGETS:
        raise ValueError("Invalid target type")
    if source not in ALLOWED_SOURCES:
        raise ValueError("Invalid report source")
    with connect() as con:
        cur = con.execute(
            """INSERT INTO reports
            (created_at, reporter_telegram_id, category, target_type, public_link, description, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now(), reporter_id, category[:100], target_type, public_link or None,
             description[:2000], source)
        )
        report_id = cur.lastrowid
        con.execute(
            "INSERT INTO audit_log (created_at, actor, action, report_id) VALUES (?, ?, ?, ?)",
            (now(), actor, "report_created", report_id)
        )
        con.execute(
            "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
            (report_id, now(), actor[:100], "case_created", f"Source: {source}; target: {target_type}")
        )
        return report_id

def list_reports(limit=500, query=None, status=None):
    sql = "SELECT * FROM reports"
    params = []
    clauses = []
    if status and status in ALLOWED_STATUSES:
        clauses.append("status = ?")
        params.append(status)
    if query:
        clauses.append("(CAST(id AS TEXT) LIKE ? OR category LIKE ? OR target_type LIKE ? OR description LIKE ? OR public_link LIKE ?)")
        params.extend([f"%{query}%"] * 5)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(max(int(limit), 1), 500))
    with connect() as con:
        return [dict(row) for row in con.execute(sql, params).fetchall()]

def update_report(report_id, status, note="", actor="dashboard_admin"):
    if status not in ALLOWED_STATUSES:
        raise ValueError("Invalid status")
    with connect() as con:
        cur = con.execute(
            "UPDATE reports SET status=?, reviewer_note=? WHERE id=?",
            (status, note[:1000], report_id)
        )
        if cur.rowcount:
            con.execute(
                "INSERT INTO audit_log (created_at, actor, action, report_id) VALUES (?, ?, ?, ?)",
                (now(), actor, f"status_changed:{status}; note_updated", report_id)
            )
            con.execute(
                "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
                (report_id, now(), actor[:100], "case_status_changed", status)
            )
        return cur.rowcount > 0

def create_enforcement_record(report_id, subject, body, destination, actor):
    with connect() as con:
        exists = con.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone()
        if not exists:
            return None
        cur = con.execute(
            """INSERT INTO enforcement_records
            (report_id, created_at, updated_at, status, destination, subject, body, actor)
            VALUES (?, ?, ?, 'prepared', ?, ?, ?, ?)""",
            (report_id, now(), now(), destination, subject[:200], body[:8000], actor[:100])
        )
        record_id = cur.lastrowid
        con.execute(
            "INSERT INTO audit_log (created_at, actor, action, report_id) VALUES (?, ?, ?, ?)",
            (now(), actor[:100], f"enforcement_draft_prepared:{record_id}", report_id)
        )
        con.execute(
            "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
            (report_id, now(), actor[:100], "enforcement_draft_prepared", f"Record #{record_id}")
        )
        return record_id

def list_enforcement_records(report_id=None, limit=200):
    sql = "SELECT * FROM enforcement_records"
    params = []
    if report_id is not None:
        sql += " WHERE report_id=?"
        params.append(report_id)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(max(int(limit), 1), 500))
    with connect() as con:
        return [dict(row) for row in con.execute(sql, params).fetchall()]

def update_enforcement_record(record_id, status, note, actor):
    allowed = {"prepared", "submitted", "acknowledged", "action_taken", "no_action", "needs_more_info", "withdrawn"}
    if status not in allowed:
        raise ValueError("Invalid enforcement status")
    with connect() as con:
        cur = con.execute(
            "UPDATE enforcement_records SET status=?, reviewer_note=?, updated_at=? WHERE id=?",
            (status, note[:1000], now(), record_id)
        )
        if cur.rowcount:
            row = con.execute("SELECT report_id FROM enforcement_records WHERE id=?", (record_id,)).fetchone()
            con.execute(
                "INSERT INTO audit_log (created_at, actor, action, report_id) VALUES (?, ?, ?, ?)",
                (now(), actor[:100], f"enforcement_status:{status}:record_{record_id}", row["report_id"])
            )
            con.execute(
                "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
                (row["report_id"], now(), actor[:100], "enforcement_status_changed", f"Record #{record_id}: {status}")
            )
        return cur.rowcount > 0

def list_audit(limit=200):
    with connect() as con:
        return [dict(row) for row in con.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 500),)
        ).fetchall()]

def add_intel_indicator(report_id, indicator_type, normalized_value, display_value, actor):
    with connect() as con:
        if not con.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone():
            return None
        try:
            cur = con.execute(
                """INSERT INTO intel_indicators
                (report_id, created_at, indicator_type, normalized_value, display_value, actor)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (report_id, now(), indicator_type, normalized_value, display_value, actor[:100])
            )
            indicator_id = cur.lastrowid
        except sqlite3.IntegrityError:
            row = con.execute(
                "SELECT id FROM intel_indicators WHERE report_id=? AND indicator_type=? AND normalized_value=?",
                (report_id, indicator_type, normalized_value)
            ).fetchone()
            return row["id"] if row else None
        con.execute(
            "INSERT INTO audit_log (created_at, actor, action, report_id) VALUES (?, ?, ?, ?)",
            (now(), actor[:100], f"intel_indicator_added:{indicator_type}:{indicator_id}", report_id)
        )
        con.execute(
            "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
            (report_id, now(), actor[:100], "indicator_added", f"{indicator_type}: {display_value[:250]}")
        )
        return indicator_id

def list_intel_indicators(report_id=None):
    sql = "SELECT * FROM intel_indicators"
    params = []
    if report_id is not None:
        sql += " WHERE report_id=?"
        params.append(report_id)
    sql += " ORDER BY id DESC LIMIT 500"
    with connect() as con:
        return [dict(row) for row in con.execute(sql, params).fetchall()]

def create_case_relation(case_a, case_b, reason):
    if case_a == case_b:
        return False
    a, b = sorted((int(case_a), int(case_b)))
    with connect() as con:
        exists = con.execute("SELECT id FROM reports WHERE id IN (?, ?)", (a, b)).fetchall()
        if len(exists) != 2:
            return False
        cur = con.execute(
            "INSERT OR IGNORE INTO case_relations (case_a, case_b, reason, created_at) VALUES (?, ?, ?, ?)",
            (a, b, reason[:200], now())
        )
        if cur.rowcount:
            for rid in (a, b):
                con.execute(
                    "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
                    (rid, now(), "system", "case_correlated", f"Related case #{b if rid == a else a}: {reason[:180]}")
                )
        return True

def list_case_relations(report_id):
    with connect() as con:
        rows = con.execute(
            """SELECT r.id, r.case_a, r.case_b, r.reason, r.created_at,
                      a.category AS category_a, b.category AS category_b
               FROM case_relations r
               JOIN reports a ON a.id=r.case_a JOIN reports b ON b.id=r.case_b
               WHERE r.case_a=? OR r.case_b=? ORDER BY r.id DESC""",
            (report_id, report_id)
        ).fetchall()
        return [dict(row) for row in rows]

def add_evidence_hash(report_id, digest, description, actor):
    with connect() as con:
        if not con.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone():
            return None
        cur = con.execute(
            "INSERT INTO evidence_hashes (report_id, created_at, algorithm, digest, description, actor) VALUES (?, ?, 'sha256', ?, ?, ?)",
            (report_id, now(), digest, description[:300], actor[:100])
        )
        hash_id = cur.lastrowid
        con.execute(
            "INSERT INTO case_events (report_id, created_at, actor, event_type, details) VALUES (?, ?, ?, ?, ?)",
            (report_id, now(), actor[:100], "metadata_hash_created", f"SHA-256 metadata record #{hash_id}")
        )
        return hash_id

def list_evidence_hashes(report_id):
    with connect() as con:
        return [dict(row) for row in con.execute(
            "SELECT * FROM evidence_hashes WHERE report_id=? ORDER BY id DESC", (report_id,)
        ).fetchall()]

def list_case_events(report_id):
    with connect() as con:
        return [dict(row) for row in con.execute(
            "SELECT * FROM case_events WHERE report_id=? ORDER BY id DESC LIMIT 300", (report_id,)
        ).fetchall()]


def create_blackshield_asset(label, asset_type, scope, owner, authorization_basis, notes, actor):
    with connect() as con:
        cur = con.execute("""INSERT INTO blackshield_assets
            (created_at,label,asset_type,scope,owner,authorization_basis,status,notes)
            VALUES (?,?,?,?,?,?,'active',?)""",
            (now(), label[:120], asset_type, scope[:500], owner[:120], authorization_basis[:1000], notes[:1000]))
        con.execute("INSERT INTO audit_log (created_at,actor,action) VALUES (?,?,?)",
                    (now(), actor[:100], f"blackshield_authorized_asset_added:{cur.lastrowid}"))
        return cur.lastrowid

def list_blackshield_assets():
    with connect() as con:
        return [dict(r) for r in con.execute("SELECT * FROM blackshield_assets ORDER BY id DESC LIMIT 300").fetchall()]

def update_blackshield_asset(asset_id, status, actor):
    if status not in {"active", "paused", "expired"}:
        raise ValueError("Invalid asset status")
    with connect() as con:
        cur=con.execute("UPDATE blackshield_assets SET status=? WHERE id=?",(status,asset_id))
        if cur.rowcount:
            con.execute("INSERT INTO audit_log (created_at,actor,action) VALUES (?,?,?)",
                        (now(),actor[:100],f"blackshield_asset_status:{asset_id}:{status}"))
        return cur.rowcount > 0

def create_blackshield_note(report_id, note_type, reference, observation, confidence, actor):
    with connect() as con:
        if report_id is not None and not con.execute("SELECT id FROM reports WHERE id=?",(report_id,)).fetchone():
            return None
        cur=con.execute("""INSERT INTO blackshield_notes
            (created_at,report_id,note_type,reference,observation,confidence,actor) VALUES (?,?,?,?,?,?,?)""",
            (now(),report_id,note_type,reference[:500],observation[:2000],confidence,actor[:100]))
        con.execute("INSERT INTO audit_log (created_at,actor,action,report_id) VALUES (?,?,?,?)",
                    (now(),actor[:100],f"blackshield_public_intel_note:{cur.lastrowid}",report_id))
        return cur.lastrowid

def list_blackshield_notes():
    with connect() as con:
        return [dict(r) for r in con.execute("SELECT * FROM blackshield_notes ORDER BY id DESC LIMIT 300").fetchall()]
