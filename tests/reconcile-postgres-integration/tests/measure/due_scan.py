"""Paired PG 17.6 profile, run via measure::due_scan_profile in the suite fixture."""
from collections import Counter
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

import psycopg

BASE = "95bce6240cddba79957cb8f3265c7f571db3acd1"
INSTALL = "crates/reconcile-postgres/migrations/install.sql"
TENANT = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
OTHER = "f47ac10b-58cc-4372-a567-0e02b2c3d478"
CALL = """SELECT cardinality(claims), more, (claims[1]).entity
          FROM rss_reconcile.claim_due(%s,'profile',1,%s,60000)"""


def nodes(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from nodes(child)


def notice_counts(diag, counts):
    message = diag.message_primary
    if "plan:\n" not in message:
        return
    plan = json.loads(message.split("plan:\n", 1)[1])
    sql, root = plan["Query Text"], plan["Plan"]
    if sql.startswith("SELECT cardinality(claims)"):
        counts["buffers"] += root.get("Shared Hit Blocks", 0) + root.get("Shared Read Blocks", 0)
        return
    counts["nested_sql"] += 1
    for node in nodes(root):
        loops = node.get("Actual Loops", 0)
        if node.get("Relation Name") == "targets" and "Scan" in node["Node Type"]:
            counts["target_rows_examined"] += loops * sum(node.get(key, 0) for key in
                ("Actual Rows", "Rows Removed by Filter", "Rows Removed by Index Recheck"))
        if node["Node Type"] == "LockRows" and "entity=candidate.entity FOR UPDATE NOWAIT" in sql:
            counts["lock_attempts"] += loops
            counts["target_locks"] += loops * node["Actual Rows"]


def trace(conn):
    conn.execute("LOAD 'auto_explain'")
    conn.execute("""SET auto_explain.log_analyze=on; SET auto_explain.log_nested_statements=on;
        SET auto_explain.log_buffers=on; SET auto_explain.log_timing=off;
        SET auto_explain.log_level=notice; SET auto_explain.log_format=json;
        SET auto_explain.log_min_duration=0""")
    conn.execute("SET SESSION AUTHORIZATION reconcile_runtime")


def seed(admin, future, due, skew=0):
    # Set all tickets explicitly in seed order. Older eligible tickets have later due times.
    admin.execute("""TRUNCATE rss_reconcile.target_resources,rss_reconcile.resources,
                     rss_reconcile.targets,rss_reconcile.scans""")
    admin.execute("INSERT INTO rss_reconcile.scans(tenant_id,reconciler) VALUES(%s,'profile')", (TENANT,))
    admin.execute("""INSERT INTO rss_reconcile.targets(tenant_id,reconciler,entity,queue_ticket,binding_revision,next_run)
        SELECT %s,'profile',n::text,n,1, CASE WHEN n<=%s THEN now()+interval '1 hour'
               ELSE now()-n*interval '1 millisecond' END FROM generate_series(1,%s) n""", (TENANT, future, future+due))
    if skew:
        admin.execute("""INSERT INTO rss_reconcile.targets(tenant_id,reconciler,entity,queue_ticket,binding_revision)
            SELECT %s,'profile',n::text,n+%s,1 FROM generate_series(1,%s) n""", (OTHER, future+due, skew))
    admin.execute("ANALYZE rss_reconcile.targets")


def first(conn, budget=128, pause=0):
    start = time.perf_counter_ns()
    for page in range(1, 10002):
        count, more, entity = conn.execute(CALL, (TENANT, budget)).fetchone()
        if count or not more:
            return page, entity, (time.perf_counter_ns()-start)//1000
        if pause:
            time.sleep(pause)
    raise RuntimeError("round failed to terminate")


def compare(admin, runtime, instrumented, revision, future, due, skew=0):
    counts = Counter()
    def collect(diag):
        notice_counts(diag, counts)
    seed(admin, future, due, skew)
    instrumented.add_notice_handler(collect)
    try:
        pages, entity, _ = first(instrumented)
    finally:
        instrumented.remove_notice_handler(collect)
    assert entity == (str(future+1) if due else None)
    assert counts["nested_sql"] > 0 and counts["buffers"] > 0
    if revision != BASE:
        assert pages == 1 and counts["lock_attempts"] == counts["target_locks"] == int(bool(due))
    elif future == 10000 and due <= 1:
        assert pages == 79 and counts["target_locks"] == future+due
    times = []
    for _ in range(3):
        seed(admin, future, due, skew)
        actual_pages, actual_entity, elapsed = first(runtime)
        assert (actual_pages, actual_entity) == (pages, entity)
        times.append(elapsed)
    print(f"DUE revision={revision} future={future} eligible={due} skew={skew} pages={pages} "
          f"examined={counts['target_rows_examined']} lock_attempts={counts['lock_attempts']} "
          f"locked={counts['target_locks']} sql={counts['nested_sql']} buffers={counts['buffers']} "
          f"median_us={statistics.median(times)}", flush=True)


def renewal(admin, runtime, revision):
    seed(admin, 0, 1)
    _, entity, _ = first(runtime)
    token, epoch = admin.execute("SELECT token,epoch FROM rss_reconcile.targets WHERE tenant_id=%s AND entity=%s",
                                 (TENANT, entity)).fetchone()
    lsn = admin.execute("SELECT pg_current_wal_insert_lsn()").fetchone()[0]
    start = time.perf_counter()
    for _ in range(300):
        runtime.execute("SELECT rss_reconcile.renew(%s,'profile',%s,%s,%s,1,60000)", (TENANT, entity, token, epoch))
    elapsed = time.perf_counter()-start
    wal = admin.execute("SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),%s)", (lsn,)).fetchone()[0]
    print(f"RENEW revision={revision} calls=300 elapsed_ms={elapsed*1000:.2f} wal_bytes={wal}", flush=True)


def wake_strategies(admin, runtime):
    for earliest in (False, True):
        seed(admin, 1, 0)
        admin.execute("UPDATE rss_reconcile.targets SET next_run=clock_timestamp()+interval '100 ms'")
        start = time.perf_counter()
        _, entity, _ = first(runtime)
        assert entity is None
        delay = 0.5
        if earliest:
            delay = runtime.execute("""SELECT greatest(0,extract(epoch FROM
                 greatest(next_run,lease_until)-clock_timestamp())) FROM rss_reconcile.targets
                 WHERE tenant_id=%s AND reconciler='profile' AND next_run IS NOT NULL
                 ORDER BY greatest(next_run,lease_until) LIMIT 1""", (TENANT,)).fetchone()[0]
        time.sleep(float(delay))
        assert first(runtime)[1] == "1"
        print(f"WAKE earliest={earliest} extra_sql={int(earliest)} elapsed_ms={(time.perf_counter()-start)*1000:.2f}")
    for pause in (0, 0.01):
        seed(admin, 0, 5)
        with admin.transaction():
            admin.execute("SELECT FROM rss_reconcile.targets WHERE queue_ticket<5 FOR UPDATE")
            pages, entity, us = first(runtime, budget=1, pause=pause)
            assert pages == 5 and entity == "5"
            print(f"EMPTY_PAGE pause_ms={pause*1000} pages={pages} first_us={us}")


def main():
    fixture = json.load(sys.stdin)
    with tempfile.TemporaryDirectory() as directory:
        ca = Path(directory) / "ca.pem"
        ca.write_text(fixture.pop("ca"))
        options = dict(fixture, sslmode="verify-full", sslrootcert=str(ca), autocommit=True,
                       options=f"-c rss.tenant_id={TENANT} -c statement_timeout=60000")
        runtime_options = dict(options, user="reconcile_runtime", password="fixture-only")
        with psycopg.connect(**options) as admin:
            head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
            for revision in (BASE, head):
                ddl = subprocess.check_output(["/usr/bin/git", "show", f"{revision}:{INSTALL}"], text=True)
                with admin.transaction():
                    admin.execute("DROP SCHEMA rss_reconcile CASCADE; SET LOCAL ROLE reconcile_owner")
                    admin.execute(ddl)
                    admin.execute("""GRANT USAGE ON SCHEMA rss_reconcile TO reconcile_runtime;
                        GRANT SELECT ON ALL TABLES IN SCHEMA rss_reconcile TO reconcile_runtime;
                        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_reconcile TO reconcile_runtime""")
                with psycopg.connect(**runtime_options) as runtime, psycopg.connect(**options) as instrumented:
                    trace(instrumented)
                    for future in (0, 128, 1024, 10000):
                        for due in (0, 1):
                            compare(admin, runtime, instrumented, revision, future, due)
                    if revision == head:
                        for due in (1, 127, 128, 129, 1024):
                            compare(admin, runtime, instrumented, revision, 10000, due, skew=10000)
                        wake_strategies(admin, runtime)
                    renewal(admin, runtime, revision)


if __name__ == "__main__":
    main()
