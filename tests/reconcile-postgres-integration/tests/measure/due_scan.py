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
            counts["completed_lock_queries"] += loops
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


def first(conn, budget=128, pause=0, call=CALL):
    start = time.perf_counter_ns()
    for page in range(1, 10002):
        count, more, entity = conn.execute(call, (TENANT, budget)).fetchone()
        if count or not more:
            return page, entity, (time.perf_counter_ns()-start)//1000
        if pause:
            time.sleep(pause)
    raise RuntimeError("round failed to terminate")


def observed_first(conn, budget=128):
    counts = Counter()
    errors = []
    def collect(diag):
        # psycopg deliberately suppresses exceptions from notice callbacks.
        try:
            notice_counts(diag, counts)
        except (ValueError, KeyError, TypeError) as error:
            errors.append(error)
    conn.add_notice_handler(collect)
    try:
        pages, entity, _ = first(conn, budget)
    finally:
        conn.remove_notice_handler(collect)
    if errors:
        raise errors[0]
    assert counts["nested_sql"] and counts["buffers"]
    return pages, entity, counts


def compare(admin, runtime, instrumented, revision, future, due, skew=0):
    seed(admin, future, due, skew)
    pages, entity, counts = observed_first(instrumented)
    assert entity == (str(future+1) if due else None)
    assert counts["nested_sql"] > 0 and counts["buffers"] > 0
    if revision != BASE:
        assert pages == 1 and counts["completed_lock_queries"] == counts["target_locks"] == int(bool(due))
    elif future == 10000 and due <= 1:
        assert pages == 79 and counts["target_locks"] == future+due
    times = []
    for _ in range(3):
        seed(admin, future, due, skew)
        actual_pages, actual_entity, elapsed = first(runtime)
        assert (actual_pages, actual_entity) == (pages, entity)
        times.append(elapsed)
    print(f"DUE revision={revision} future={future} eligible={due} skew={skew} pages={pages} "
          f"examined={counts['target_rows_examined']} completed_lock_queries={counts['completed_lock_queries']} "
          f"locked={counts['target_locks']} sql={counts['nested_sql']} buffers={counts['buffers']} "
          f"median_us={statistics.median(times)}", flush=True)


def window_costs(admin, instrumented, revision):
    for distribution, budget in [("dense", 2147483647), ("past-cursor", 128)]:
        seed(admin, 0, 10000)
        if distribution == "past-cursor":
            admin.execute("UPDATE rss_reconcile.targets SET next_run=now()+interval '1 hour' WHERE queue_ticket>129")
            admin.execute("UPDATE rss_reconcile.scans SET cursor_ticket=128,high_watermark=10000")
            admin.execute("ANALYZE rss_reconcile.targets")
        pages, entity, counts = observed_first(instrumented, budget)
        expected = "129" if distribution == "past-cursor" else "1"
        assert pages == 1 and entity == expected
        print(f"WINDOW revision={revision} layout={distribution} budget={budget} counts={dict(counts)}", flush=True)
        if revision != BASE:
            # The large budget and inactive ticket suffix must not force a pass over 10k rows.
            assert counts["target_rows_examined"] < 512, counts


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
    # Nontransactional sequence values count attempts even when NOWAIT rolls back its subtransaction.
    definition = admin.execute("SELECT pg_get_functiondef('rss_reconcile.claim_due(uuid,text,int,int,bigint)'::regprocedure)").fetchone()[0]
    anchor = "SELECT * INTO row FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND entity=candidate.entity FOR UPDATE NOWAIT;"
    assert definition.count(anchor) == 1
    with admin.transaction():
        admin.execute("SET LOCAL ROLE reconcile_owner; CREATE SCHEMA lock_probe; CREATE SEQUENCE lock_probe.attempts")
        admin.execute(definition.replace("FUNCTION rss_reconcile.claim_due(", "FUNCTION lock_probe.claim_due(")
                      .replace(anchor, "PERFORM nextval('lock_probe.attempts'); " + anchor))
        admin.execute("GRANT USAGE ON SCHEMA lock_probe TO reconcile_runtime")
    seed(admin, 0, 5)
    with admin.transaction():
        admin.execute("SELECT FROM rss_reconcile.targets WHERE queue_ticket<5 FOR UPDATE")
        pages, entity, _ = first(runtime, budget=1, call=CALL.replace("rss_reconcile.claim_due", "lock_probe.claim_due"))
        attempts = admin.execute("SELECT last_value FROM lock_probe.attempts").fetchone()[0]
        assert (pages, entity, attempts) == (5, "5", 5)
        print(f"LOCKS known_held=4 attempts={attempts} locked=1")
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
        compiled_sql = fixture.pop("candidate_sql")
        ca = Path(directory) / "ca.pem"
        ca.write_text(fixture.pop("ca"))
        options = dict(fixture, sslmode="verify-full", sslrootcert=str(ca), autocommit=True,
                       options=f"-c rss.tenant_id={TENANT} -c statement_timeout=60000")
        runtime_options = dict(options, user="reconcile_runtime", password="fixture-only")
        with psycopg.connect(**options) as admin:
            head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
            assert compiled_sql == Path(INSTALL).read_text() == subprocess.check_output(
                ["/usr/bin/git", "show", f"{head}:{INSTALL}"], text=True), "candidate SQL differs from HEAD"
            for revision in (BASE, head):
                ddl = compiled_sql if revision == head else subprocess.check_output(["/usr/bin/git", "show", f"{revision}:{INSTALL}"], text=True)
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
                    window_costs(admin, instrumented, revision)
                    renewal(admin, runtime, revision)


if __name__ == "__main__":
    main()
