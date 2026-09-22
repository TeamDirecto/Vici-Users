#!/usr/bin/env python3
"""Race-safe Asterisk synchronization worker for Vici-Users.

This wrapper keeps the durable worker logic from asterisk_sync_worker.py but
adds an explicit WAIT_SETTLE phase between VICIdial configuration generation
and the AMI `sip reload`. The delay avoids reloading chan_sip before the newly
generated sip-vicidial.conf content is fully available.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

import pymysql

import asterisk_sync_worker as base

SETTLE_SECONDS = int(os.getenv("VICI_USERS_ASTERISK_SETTLE_SECONDS", "10"))


def ensure_schema(connection):
    """Create the base schema and add the durable settle timestamp if needed."""
    base.ensure_schema(connection)
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(asterisk_sync_jobs)").fetchall()
    }
    if "settle_started_at" not in columns:
        connection.execute(
            "ALTER TABLE asterisk_sync_jobs ADD COLUMN settle_started_at TEXT"
        )
        connection.commit()


def process_wait_rebuild(sqlite_db, mysql_cursor, job):
    eligible = json.loads(job["eligible_servers_json"] or "[]")
    if not eligible:
        return

    states = base.mysql_server_state(mysql_cursor, eligible)
    pending = []
    for server_ip in eligible:
        row = states.get(server_ip)
        if not row or str(row.get("rebuild_conf_files") or "") != "N":
            pending.append(server_ip)

    if not pending:
        stamp = base.now_text()
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status='WAIT_SETTLE', settle_started_at=?,
                   last_error=NULL, updated_at=?
             WHERE id=?
            """,
            (stamp, stamp, job["id"]),
        )
        sqlite_db.commit()
        print(
            "REBUILD complete extension=%s; settling=%ss"
            % (job["extension"], SETTLE_SECONDS)
        )
        return

    started = base.parse_ts(job["rebuild_requested_at"])
    if started and datetime.utcnow() - started > timedelta(seconds=base.SYNC_TIMEOUT):
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status='REBUILD_TIMEOUT', last_error=?, updated_at=?
             WHERE id=?
            """,
            (
                "REBUILD_PENDING:%s" % ",".join(pending),
                base.now_text(),
                job["id"],
            ),
        )
        sqlite_db.commit()
        print(
            "REBUILD_TIMEOUT extension=%s pending=%s"
            % (job["extension"], ",".join(pending))
        )


def process_wait_settle(sqlite_db, mysql_cursor, job):
    eligible = json.loads(job["eligible_servers_json"] or "[]")
    ineligible = json.loads(job["ineligible_servers_json"] or "[]")
    if not eligible:
        return

    # A second provisioning job can request another rebuild while this job is
    # settling. Never queue a reload while any eligible node is rebuilding.
    states = base.mysql_server_state(mysql_cursor, eligible)
    rebuilding = []
    for server_ip in eligible:
        row = states.get(server_ip)
        if not row or str(row.get("rebuild_conf_files") or "") != "N":
            rebuilding.append(server_ip)

    if rebuilding:
        stamp = base.now_text()
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET status='WAIT_REBUILD', rebuild_requested_at=?,
                   settle_started_at=NULL, updated_at=?
             WHERE id=?
            """,
            (stamp, stamp, job["id"]),
        )
        sqlite_db.commit()
        print(
            "SETTLE interrupted extension=%s rebuilding=%s"
            % (job["extension"], ",".join(rebuilding))
        )
        return

    started = base.parse_ts(job["settle_started_at"])
    if not started:
        stamp = base.now_text()
        sqlite_db.execute(
            """
            UPDATE asterisk_sync_jobs
               SET settle_started_at=?, updated_at=?
             WHERE id=?
            """,
            (stamp, stamp, job["id"]),
        )
        sqlite_db.commit()
        return

    if datetime.utcnow() - started < timedelta(seconds=SETTLE_SECONDS):
        return

    base.queue_sip_reload(
        sqlite_db,
        mysql_cursor,
        job,
        eligible,
        ineligible,
    )


def discover_group_change_jobs(connection):
    """Queue one rebuild/reload cycle for each completed group migration."""
    table = connection.execute(
        """
        SELECT name
          FROM sqlite_master
         WHERE type='table'
           AND name='group_change_operations'
        """
    ).fetchone()
    if not table:
        return 0

    enabled = base.load_enabled_servers()
    required_json = json.dumps(enabled, sort_keys=True)
    rows = connection.execute(
        """
        SELECT g.idempotency_key, g.target_extension, g.username
          FROM group_change_operations g
          LEFT JOIN asterisk_sync_jobs j
            ON j.idempotency_key=('GC:' || g.idempotency_key)
         WHERE g.status='SUCCESS'
           AND j.idempotency_key IS NULL
         ORDER BY g.updated_at, g.idempotency_key
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
                "GC:" + str(item["idempotency_key"]),
                str(item["target_extension"]),
                str(item["username"] or ""),
                required_json,
                base.now_text(),
            ),
        )
    connection.commit()
    return len(rows)


def run_once(bootstrap_only=False):
    if not base.INVENTORY_DB_FILE.exists():
        raise RuntimeError("INVENTORY_DB_NOT_FOUND:%s" % base.INVENTORY_DB_FILE)

    sqlite_db = base.sqlite_connect()
    try:
        ensure_schema(sqlite_db)
        did_baseline = base.baseline_existing_successes(sqlite_db)
        if bootstrap_only or did_baseline:
            return 0

        if not base.SYNC_ENABLED:
            print("ASTERISK_SYNC disabled; no MySQL writes performed")
            return 0

        discovered_provisioning = base.discover_new_jobs(sqlite_db)
        discovered_group_changes = discover_group_change_jobs(sqlite_db)
        discovered = discovered_provisioning + discovered_group_changes
        if discovered:
            print(
                "DISCOVERED new_sync_jobs=%d provisioning=%d group_change=%d"
                % (
                    discovered,
                    discovered_provisioning,
                    discovered_group_changes,
                )
            )

        cfg = base.read_astguiclient_conf()
        mysql_db = pymysql.connect(**cfg)
        try:
            cursor = mysql_db.cursor()
            jobs = sqlite_db.execute(
                """
                SELECT * FROM asterisk_sync_jobs
                 WHERE status IN (
                    'NEW','WAIT_REBUILD','WAIT_SETTLE','RELOAD_QUEUED'
                 )
                 ORDER BY id
                """
            ).fetchall()
            for job in jobs:
                try:
                    if job["status"] == "NEW":
                        base.request_rebuild(sqlite_db, cursor, job)
                    elif job["status"] == "WAIT_REBUILD":
                        process_wait_rebuild(sqlite_db, cursor, job)
                    elif job["status"] == "WAIT_SETTLE":
                        process_wait_settle(sqlite_db, cursor, job)
                    elif job["status"] == "RELOAD_QUEUED":
                        base.process_reload_queued(sqlite_db, cursor, job)
                except Exception as exc:
                    sqlite_db.execute(
                        """
                        UPDATE asterisk_sync_jobs
                           SET attempts=attempts+1, last_error=?, updated_at=?
                         WHERE id=?
                        """,
                        (
                            ("%s:%s" % (exc.__class__.__name__, str(exc)))[:1000],
                            base.now_text(),
                            job["id"],
                        ),
                    )
                    sqlite_db.commit()
                    print(
                        "JOB_ERROR id=%s extension=%s error=%s:%s"
                        % (
                            job["id"],
                            job["extension"],
                            exc.__class__.__name__,
                            exc,
                        ),
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
