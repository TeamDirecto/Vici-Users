#!/usr/bin/env python3
"""Durable post-provisioning Asterisk synchronization for Vici-Users.

The worker watches successful provisioning operations in the local SQLite
inventory, asks VICIdial to rebuild generated Asterisk configuration for
eligible enabled nodes, waits for rebuild_conf_files to clear, then queues a
native AMI `sip reload` through vicidial_manager.

It intentionally does not SSH to dialers and does not roll back users/phones
when runtime synchronization fails.
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pymysql

APP_ROOT = Path(__file__).resolve().parent.parent
ASTGUI_CONF = Path(os.getenv("ASTGUI_CONF", "/etc/astguiclient.conf"))
INVENTORY_DB_FILE = Path(
    os.getenv("VICI_USERS_INVENTORY_DB", "/var/lib/vici-users/extension_inventory.db")
)
CLUSTER_NODES_FILE = Path(
    os.getenv(
        "VICI_USERS_CLUSTER_NODES_FILE",
        str(APP_ROOT / "config" / "cluster_nodes.json"),
    )
)
SYNC_ENABLED = os.getenv("VICI_USERS_ASTERISK_SYNC_ENABLED", "false").lower() in {
    "1", "true", "yes", "y"
}
SYNC_TIMEOUT = int(os.getenv("VICI_USERS_ASTERISK_SYNC_TIMEOUT", "180"))
EXPECTED_DB_HOST = os.getenv("VICI_DB_EXPECTED_HOST", "172.20.20.198")


def now_text():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def read_astguiclient_conf():
    values = {}
    wanted = {
        "VARDB_server": "host",
        "VARDB_database": "database",
        "VARDB_user": "user",
        "VARDB_pass": "password",
        "VARDB_port": "port",
    }
    if not ASTGUI_CONF.exists():
        raise RuntimeError("ASTGUICLIENT_CONF_NOT_FOUND")

    for raw in ASTGUI_CONF.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=>" not in line:
            continue
        key, value = [part.strip() for part in line.split("=>", 1)]
        if key in wanted:
            values[wanted[key]] = value

    required = ("host", "database", "user", "password")
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise RuntimeError("ASTGUICLIENT_DB_CONFIG_MISSING:%s" % ",".join(missing))
    if values["host"] != EXPECTED_DB_HOST:
        raise RuntimeError(
            "DB_HOST_MISMATCH expected=%s actual=%s"
            % (EXPECTED_DB_HOST, values["host"])
        )

    return {
        "host": values["host"],
        "database": values["database"],
        "user": values["user"],
        "password": values["password"],
        "port": int(values.get("port") or 3306),
        "charset": "utf8",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": True,
        "connect_timeout": 5,
    }


def load_enabled_servers():
    with CLUSTER_NODES_FILE.open("r") as fh:
        data = json.load(fh)
    nodes = data.get("nodes") or []
    enabled = []
    for node in nodes:
        if bool(node.get("enabled", True)):
            server_ip = str(node.get("server_ip") or "").strip()
            if server_ip:
                enabled.append(server_ip)
    if not enabled:
        raise RuntimeError("NO_ENABLED_CLUSTER_NODES")
    return enabled


def sqlite_connect():
    connection = sqlite3.connect(str(INVENTORY_DB_FILE), timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_schema(connection):
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS asterisk_sync_meta (
            meta_key TEXT PRIMARY KEY,
            meta_value TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS asterisk_sync_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idempotency_key TEXT NOT NULL UNIQUE,
            extension TEXT NOT NULL,
            username TEXT,
            required_servers_json TEXT NOT NULL,
            eligible_servers_json TEXT NOT NULL,
            ineligible_servers_json TEXT NOT NULL,
            manager_ids_json TEXT,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            rebuild_requested_at TEXT,
            reload_queued_at TEXT,
            completed_at TEXT,
            last_error TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_asterisk_sync_jobs_status
            ON asterisk_sync_jobs(status);
        """
    )
    connection.commit()


def baseline_existing_successes(connection):
    row = connection.execute(
        "SELECT meta_value FROM asterisk_sync_meta WHERE meta_key='baseline_complete'"
    ).fetchone()
    if row:
        return False

    enabled = load_enabled_servers()
    required_json = json.dumps(enabled, sort_keys=True)
    rows = connection.execute(
        """
        SELECT idempotency_key, extension, username
          FROM provisioning_operations
         WHERE status='SUCCESS'
        """
    ).fetchall()
    for item in rows:
        connection.execute(
            """
            INSERT OR IGNORE INTO asterisk_sync_jobs
                (idempotency_key, extension, username,
                 required_servers_json, eligible_servers_json,
                 ineligible_servers_json, status, completed_at,
                 last_error, updated_at)
            VALUES (?, ?, ?, ?, '[]', '[]', 'BASELINE', ?,
                    'Existing SUCCESS before Asterisk sync worker activation', ?)
            """,
            (
                str(item["idempotency_key"]),
                str(item["extension"]),
                str(item["username"] or ""),
                required_json,
                now_text(),
                now_text(),
            ),
        )

    connection.execute(
        """
        INSERT INTO asterisk_sync_meta(meta_key, meta_value, updated_at)
        VALUES('baseline_complete', ?, ?)
        """,
        (now_text(), now_text()),
    )
    connection.commit()
    print("BASELINE complete existing_successes=%d" % len(rows))
    return True


def discover_new_jobs(connection):
    enabled = load_enabled_servers()
    required_json = json.dumps(enabled, sort_keys=True)
    rows = connection.execute(
        """
        SELECT p.idempotency_key, p.extension, p.username
          FROM provisioning_operations p
          LEFT JOIN asterisk_sync_jobs j
            ON j.idempotency_key=p.idempotency_key
         WHERE p.status='SUCCESS'
           AND j.idempotency_key IS NULL
         ORDER BY p.updated_at, p.idempotency_key
        """
    ).fetchall()
    for item in rows:
        connection.execute(
            """
            INSERT INTO asterisk_sync_jobs
                (idempotency_key, extension, username,
                 required_servers_json, eligible_servers_json,
                 ineligible_servers_json, status, updated_at)
            VALUES (?, ?, ?, ?, '[]', '[]', 'NEW', ?)
            """,
            (
                str(item["idempotency_key"]),
                str(item["extension"]),
                str(item["username"] or ""),
                required_json,
                now_text(),
            ),
        )
    connection.commit()
    return len(rows)


def mysql_server_state(cursor, server_ips):
    placeholders = ",".join(["%s"] * len(server_ips))
    cursor.execute(
        """
        SELECT server_ip, active_asterisk_server,
               generate_vicidial_conf, rebuild_conf_files
          FROM servers
         WHERE server_ip IN (%s)
        """ % placeholders,
        tuple(server_ips),
    )
    return dict((str(row["server_ip"]), row) for row in cursor.fetchall())


def split_eligible(server_ips, states):
    eligible = []
    ineligible = []
    for server_ip in server_ips:
        row = states.get(server_ip)
        if not row:
            ineligible.append({"server_ip": server_ip, "reason": "SERVER_ROW_MISSING"})
            continue
        if str(row.get("active_asterisk_server") or "") != "Y":
            ineligible.append({"server_ip": server_ip, "reason": "SERVER_NOT_ACTIVE"})
            continue
        if str(row.get("generate_vicidial_conf") or "") != "Y":
            ineligible.append({"server_ip": server_ip, "reason": "CONF_GENERATION_DISABLED"})
            continue
        eligible.append(server_ip)
    return eligible, ineligible


def request_rebuild(sqlite_db, mysql_cursor, job):
    required = json.loads(job["required_servers_json"])
    states = mysql_server_state(mysql_cursor, required)
    eligible, ineligible = split_eligible(required, states)

    if not eligible:
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status='BLOCKED', eligible_servers_json='[]',
                   ineligible_servers_json=?, attempts=attempts+1,
                   last_error='NO_ELIGIBLE_ASTERISK_SERVERS', updated_at=?
             WHERE id=?
            """,
            (json.dumps(ineligible, sort_keys=True), now_text(), job["id"]),
        )
        sqlite_db.commit()
        return

    placeholders = ",".join(["%s"] * len(eligible))
    mysql_cursor.execute(
        """
        UPDATE servers
           SET rebuild_conf_files='Y'
         WHERE server_ip IN (%s)
           AND active_asterisk_server='Y'
           AND generate_vicidial_conf='Y'
        """ % placeholders,
        tuple(eligible),
    )

    sqlite_db.execute(
        """
        UPDATE asterisk_sync_jobs
           SET status='WAIT_REBUILD', eligible_servers_json=?,
               ineligible_servers_json=?, attempts=attempts+1,
               rebuild_requested_at=?, last_error=NULL, updated_at=?
         WHERE id=?
        """,
        (
            json.dumps(eligible, sort_keys=True),
            json.dumps(ineligible, sort_keys=True),
            now_text(),
            now_text(),
            job["id"],
        ),
    )
    sqlite_db.commit()
    print(
        "REBUILD requested extension=%s eligible=%s ineligible=%s"
        % (job["extension"], ",".join(eligible), len(ineligible))
    )


def queue_sip_reload(sqlite_db, mysql_cursor, job, eligible, ineligible):
    manager_ids = []
    stamp = datetime.utcnow().strftime("%H%M%S")
    for index, server_ip in enumerate(eligible):
        callerid = ("VUSR%s%s%02d" % (job["extension"], stamp, index))[:20]
        mysql_cursor.execute(
            """
            INSERT INTO vicidial_manager
                (entry_date, status, response, server_ip,
                 action, callerid, cmd_line_b)
            VALUES (NOW(), 'NEW', 'N', %s, 'Command', %s,
                    'Command: sip reload')
            """,
            (server_ip, callerid),
        )
        manager_ids.append(int(mysql_cursor.lastrowid))

    sqlite_db.execute(
        """
        UPDATE asterisk_sync_jobs
           SET status='RELOAD_QUEUED', manager_ids_json=?,
               reload_queued_at=?, updated_at=?, last_error=NULL
         WHERE id=?
        """,
        (json.dumps(manager_ids), now_text(), now_text(), job["id"]),
    )
    sqlite_db.commit()
    print(
        "SIP_RELOAD queued extension=%s manager_ids=%s%s"
        % (
            job["extension"],
            ",".join(str(item) for item in manager_ids),
            " partial=%d" % len(ineligible) if ineligible else "",
        )
    )


def process_wait_rebuild(sqlite_db, mysql_cursor, job):
    eligible = json.loads(job["eligible_servers_json"] or "[]")
    ineligible = json.loads(job["ineligible_servers_json"] or "[]")
    if not eligible:
        return

    states = mysql_server_state(mysql_cursor, eligible)
    pending = []
    for server_ip in eligible:
        row = states.get(server_ip)
        if not row or str(row.get("rebuild_conf_files") or "") != "N":
            pending.append(server_ip)

    if not pending:
        queue_sip_reload(sqlite_db, mysql_cursor, job, eligible, ineligible)
        return

    started = parse_ts(job["rebuild_requested_at"])
    if started and datetime.utcnow() - started > timedelta(seconds=SYNC_TIMEOUT):
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status='REBUILD_TIMEOUT', last_error=?, updated_at=?
             WHERE id=?
            """,
            (
                "REBUILD_PENDING:%s" % ",".join(pending),
                now_text(),
                job["id"],
            ),
        )
        sqlite_db.commit()
        print(
            "REBUILD_TIMEOUT extension=%s pending=%s"
            % (job["extension"], ",".join(pending))
        )


def process_reload_queued(sqlite_db, mysql_cursor, job):
    manager_ids = json.loads(job["manager_ids_json"] or "[]")
    ineligible = json.loads(job["ineligible_servers_json"] or "[]")
    if not manager_ids:
        return

    placeholders = ",".join(["%s"] * len(manager_ids))
    mysql_cursor.execute(
        "SELECT man_id, server_ip, status FROM vicidial_manager WHERE man_id IN (%s)"
        % placeholders,
        tuple(manager_ids),
    )
    rows = mysql_cursor.fetchall()
    by_id = dict((int(row["man_id"]), row) for row in rows)

    pending = []
    for man_id in manager_ids:
        row = by_id.get(int(man_id))
        if not row or str(row.get("status") or "") not in {"SENT", "DEAD"}:
            pending.append(str(man_id))

    if not pending:
        final_status = "PARTIAL" if ineligible else "READY"
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status=?, completed_at=?, updated_at=?, last_error=?
             WHERE id=?
            """,
            (
                final_status,
                now_text(),
                now_text(),
                (
                    "INELIGIBLE_SERVERS:%s"
                    % ",".join(
                        "%s=%s" % (item.get("server_ip"), item.get("reason"))
                        for item in ineligible
                    )
                    if ineligible else None
                ),
                job["id"],
            ),
        )
        sqlite_db.commit()
        print(
            "SYNC %s extension=%s"
            % (final_status, job["extension"])
        )
        return

    queued = parse_ts(job["reload_queued_at"])
    if queued and datetime.utcnow() - queued > timedelta(seconds=SYNC_TIMEOUT):
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status='RELOAD_TIMEOUT', last_error=?, updated_at=?
             WHERE id=?
            """,
            ("MANAGER_PENDING:%s" % ",".join(pending), now_text(), job["id"]),
        )
        sqlite_db.commit()
        print(
            "RELOAD_TIMEOUT extension=%s manager_ids=%s"
            % (job["extension"], ",".join(pending))
        )


def run_once(bootstrap_only=False):
    if not INVENTORY_DB_FILE.exists():
        raise RuntimeError("INVENTORY_DB_NOT_FOUND:%s" % INVENTORY_DB_FILE)

    sqlite_db = sqlite_connect()
    try:
        ensure_schema(sqlite_db)
        did_baseline = baseline_existing_successes(sqlite_db)
        if bootstrap_only or did_baseline:
            return 0

        if not SYNC_ENABLED:
            print("ASTERISK_SYNC disabled; no MySQL writes performed")
            return 0

        discovered = discover_new_jobs(sqlite_db)
        if discovered:
            print("DISCOVERED new_sync_jobs=%d" % discovered)

        cfg = read_astguiclient_conf()
        mysql_db = pymysql.connect(**cfg)
        try:
            cursor = mysql_db.cursor()
            jobs = sqlite_db.execute(
                """
                SELECT * FROM asterisk_sync_jobs
                 WHERE status IN ('NEW','WAIT_REBUILD','RELOAD_QUEUED')
                 ORDER BY id
                """
            ).fetchall()
            for job in jobs:
                try:
                    if job["status"] == "NEW":
                        request_rebuild(sqlite_db, cursor, job)
                    elif job["status"] == "WAIT_REBUILD":
                        process_wait_rebuild(sqlite_db, cursor, job)
                    elif job["status"] == "RELOAD_QUEUED":
                        process_reload_queued(sqlite_db, cursor, job)
                except Exception as exc:
                    sqlite_db.execute(
                        """
                        UPDATE asterisk_sync_jobs
                           SET attempts=attempts+1, last_error=?, updated_at=?
                         WHERE id=?
                        """,
                        (
                            "%s:%s" % (exc.__class__.__name__, str(exc))[:1000],
                            now_text(),
                            job["id"],
                        ),
                    )
                    sqlite_db.commit()
                    print(
                        "JOB_ERROR id=%s extension=%s error=%s:%s"
                        % (job["id"], job["extension"], exc.__class__.__name__, exc),
                        file=sys.stderr,
                    )
        finally:
            mysql_db.close()
    finally:
        sqlite_db.close()
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bootstrap-only",
        action="store_true",
        help="Create schema and baseline existing SUCCESS operations without MySQL writes",
    )
    args = parser.parse_args()
    try:
        return run_once(bootstrap_only=args.bootstrap_only)
    except Exception as exc:
        print("FATAL %s:%s" % (exc.__class__.__name__, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
