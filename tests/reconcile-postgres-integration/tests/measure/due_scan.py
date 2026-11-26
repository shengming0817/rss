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

BASE = "5d4c547dc86872d2c9b9b400ee1eee2aafe93c0a"
INSTALL = "crates/reconcile-postgres/migrations/install.sql"
TENANT = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
OTHER = "f47ac10b-58cc-4372-a567-0e02b2c3d478"
CALL = """SELECT cardinality(claims), more, (claims[1]).entity
          FROM rss_reconcile.claim_due(%s,'profile',%s,%s,60000)"""


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
            examined = loops * sum(node.get(key, 0) for key in
                ("Actual Rows", "Rows Removed by Filter", "Rows Removed by Index Recheck"))
            counts["target_rows_examined"] += examined
            if "LIMIT probe_limit" in sql or "LIMIT page_limit" in sql:
                counts["candidate_reads"] += examined
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


def first(conn, budget=128, pause=0, call=CALL, after_page=None, limit=1):
    start = time.perf_counter_ns()
    for page in range(1, 10002):
        count, more, entity = conn.execute(call, (TENANT, limit, budget)).fetchone()
        if after_page is not None:
            after_page()
        if count or not more:
            return page, entity, (time.perf_counter_ns()-start)//1000, count
        if pause:
            time.sleep(pause)
    raise RuntimeError("round failed to terminate")


def observed_first(conn, budget=128, limit=1, call=CALL):
    counts = Counter()
    errors = []
    def collect(diag):
        # psycopg deliberately suppresses exceptions from notice callbacks.
        try:
            notice_counts(diag, counts)
        except (ValueError, KeyError, TypeError) as error:
            errors.append(error)
    previous = 0
    def after_page():
        nonlocal previous
        current = counts["candidate_reads"]
        counts["max_page_candidate_reads"] = max(counts["max_page_candidate_reads"], current - previous)
        previous = current
    conn.add_notice_handler(collect)
    try:
        pages, entity, _, returned = first(conn, budget, after_page=after_page, limit=limit, call=call)
        counts["returned"] = returned
    finally:
        conn.remove_notice_handler(collect)
    if errors:
        raise errors[0]
    assert counts["nested_sql"] and counts["buffers"]
    return pages, entity, counts


def compare(admin, runtime, instrumented, revision, future, due, skew=0, limit=1, budget=128):
    seed(admin, future, due, skew)
    pages, entity, counts = observed_first(instrumented, budget, limit)
    slots = min(budget, limit)
    probe_limit = slots + 2  # A page, its lookahead, and the truncation sentinel.
    old_ticket_scan = revision == BASE and due >= probe_limit
    assert pages == (future // budget + 1 if old_ticket_scan else 1)
    expected_count = min(due, limit, budget - future % budget if old_ticket_scan else budget)
    assert counts["returned"] == counts["completed_lock_queries"] == counts["target_locks"] == expected_count
    if due:
        assert future < int(entity) <= future + due
        if revision == BASE or due < probe_limit or not future:
            assert entity == str(future + 1)
        assert 0 < counts["max_page_candidate_reads"] <= probe_limit + budget + 1, counts
    else:
        assert entity is None
    times = []
    for _ in range(3):
        seed(admin, future, due, skew)
        actual_pages, actual_entity, elapsed, returned = first(runtime, budget, limit=limit)
        assert (actual_pages, actual_entity, returned) == (pages, entity, expected_count)
        times.append(elapsed)
    print(f"DUE revision={revision} future={future} eligible={due} skew={skew} limit={limit} budget={budget} "
          f"pages={pages} claims={expected_count} candidates={counts['candidate_reads']} "
          f"examined={counts['target_rows_examined']} completed_lock_queries={counts['completed_lock_queries']} "
          f"locked={counts['target_locks']} sql={counts['nested_sql']} buffers={counts['buffers']} "
          f"max_candidate_reads={counts['max_page_candidate_reads']} median_us={statistics.median(times)}", flush=True)


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
            if distribution == "past-cursor":
                pages, entity, suffix = observed_first(instrumented, budget)
                assert entity is None and pages == (10000-129+budget-1)//budget
                assert suffix["target_locks"] == 0 and 0 < suffix["max_page_candidate_reads"] <= 132
                print(f"FUTURE_SUFFIX pages={pages} counts={dict(suffix)}", flush=True)


def deep_progress(admin, runtime, instrumented, revision):
    seed(admin, 0, 500000)
    admin.execute("UPDATE rss_reconcile.targets SET next_run=now()-interval '1 day'+queue_ticket*interval '1 ms'")
    admin.execute("ANALYZE rss_reconcile.targets")
    admin.execute("UPDATE rss_reconcile.scans SET cursor_ticket=450000,high_watermark=500000")
    runtime.execute("SET statement_timeout='20ms'")
    try:
        for ticket in range(450001, 450004):
            count, more, entity = runtime.execute(CALL, (TENANT, 1, 128)).fetchone()
            assert (count, more, entity) == (1, True, str(ticket))
    finally:
        runtime.execute("RESET statement_timeout")
    cursor = admin.execute("SELECT cursor_ticket FROM rss_reconcile.scans").fetchone()[0]
    assert cursor == 450003
    pages, entity, counts = observed_first(instrumented)
    assert pages == 1 and entity == "450004"
    if revision != BASE:
        assert 0 < counts["max_page_candidate_reads"] <= 132, counts
    print(f"DEEP revision={revision} timeout_ms=20 cursor={cursor} counts={dict(counts)}", flush=True)


def hot_progress(admin, runtime, instrumented):
    seed(admin, 0, 10001)
    admin.execute("SELECT setval('rss_reconcile.queue_tickets',10001)")
    runtime.execute("SELECT rss_reconcile.wake(%s,'holder','holder',ARRAY['hot'])", (TENANT,))
    runtime.execute("SELECT * FROM rss_reconcile.claim_due(%s,'holder',1,128,600000)", (TENANT,))
    admin.execute("""INSERT INTO rss_reconcile.target_resources(tenant_id,reconciler,entity,resource)
        SELECT tenant_id,reconciler,entity,'hot' FROM rss_reconcile.targets
        WHERE reconciler='profile' AND queue_ticket<=10000""")
    admin.execute("ANALYZE rss_reconcile.target_resources")
    pages, entity, counts = observed_first(instrumented)
    assert (pages, entity) == (79, "10001")
    assert 0 < counts["max_page_candidate_reads"] <= 132, counts
    print(f"HOT_WAITERS blocked=10000 first_page={pages} counts={dict(counts)}", flush=True)


def mixed_queue(admin, runtime, future):
    seed(admin, future, 4)
    admin.execute("SELECT setval('rss_reconcile.queue_tickets',%s)", (future + 4,))
    runtime.execute("SELECT rss_reconcile.wake(%s,'holder','holder',ARRAY['hot'])", (TENANT,))
    runtime.execute("SELECT * FROM rss_reconcile.claim_due(%s,'holder',1,128,600000)", (TENANT,))
    # The three earliest due targets share the live resource. The oldest ticket is independent.
    admin.execute("""INSERT INTO rss_reconcile.target_resources(tenant_id,reconciler,entity,resource)
        SELECT tenant_id,reconciler,entity,'hot' FROM rss_reconcile.targets
        WHERE reconciler='profile' AND queue_ticket>%s""", (future + 1,))


def release_holder(runtime):
    runtime.execute("""SELECT rss_reconcile.release(tenant_id,reconciler,entity,token,epoch)
        FROM rss_reconcile.targets WHERE tenant_id=%s AND reconciler='holder'""", (TENANT,))


def blocked_remote_sample(admin, runtime, instrumented, revision):
    future = 100000
    for blocker in ("lease", "protect", "target"):
        mixed_queue(admin, runtime, future)
        with admin.transaction():
            if blocker == "protect":
                assert admin.execute("""SELECT rss_reconcile.lock_execution(tenant_id,reconciler,entity,token,epoch,binding_revision)
                    FROM rss_reconcile.targets WHERE tenant_id=%s AND reconciler='holder'""", (TENANT,)).fetchone()[0]
            if blocker == "target":
                admin.execute("""SELECT FROM rss_reconcile.targets WHERE tenant_id=%s AND reconciler='profile'
                    AND queue_ticket>%s FOR UPDATE""", (TENANT, future + 1))
            attempted = None
            if revision == BASE:
                pages, entity, counts = observed_first(instrumented)
            else:
                before = admin.execute("SELECT last_value FROM lock_probe.attempts").fetchone()[0]
                pages, entity, counts = observed_first(instrumented, call=CALL.replace("rss_reconcile.claim_due", "lock_probe.claim_due"))
                attempted = admin.execute("SELECT last_value FROM lock_probe.attempts").fetchone()[0] - before
                if blocker == "lease":
                    assert attempted == 4
                else:
                    # Three hints per retry page, plus the independent ordinary ticket.
                    # Six startup probes (normal and backoff pages 1,2,4,8,16),
                    # then at most one every 32 pages.
                    assert 4 <= attempted <= 1 + 3 * (6 + (pages + 31) // 32), (blocker, attempted)
            assert (pages, entity) == (future // 128 + 1, str(future + 1))
            expected_locks = 1 if revision == BASE or blocker == "target" else attempted
            assert counts["target_locks"] == expected_locks, counts
            print(f"MIXED revision={revision} blocker={blocker} pages={pages} first={entity} "
                  f"attempts={attempted} locks={counts['target_locks']} candidates={counts['candidate_reads']} peak={counts['max_page_candidate_reads']}", flush=True)
        release_holder(runtime)
        # The ordinary stream rechecks both registered waiters and suppressed NOWAIT hints.
        assert first(runtime)[1] == str(future + 2)


def early_unblock(admin, runtime):
    future = 100000
    for unblock in ("release", "expiry"):
        mixed_queue(admin, runtime, future)
        assert runtime.execute(CALL, (TENANT, 1, 128)).fetchone() == (0, True, None)
        registered = admin.execute("""SELECT count(*) FROM rss_reconcile.target_resources WHERE tenant_id=%s
            AND reconciler='profile' AND waiting_ticket IS NOT NULL""", (TENANT,)).fetchone()[0]
        assert registered == 3
        if unblock == "release":
            release_holder(runtime)
        else:
            admin.execute("UPDATE rss_reconcile.targets SET lease_until=now()-interval '1 second' WHERE tenant_id=%s AND reconciler='holder'", (TENANT,))
        pages, entity, _, count = first(runtime)
        assert (pages, entity, count) == (1, str(future + 2), 1)
        print(f"UNBLOCK mode={unblock} pages={pages} first={entity} registered={registered}", flush=True)


def short_physical_lock(admin, runtime):
    future = 100000
    for blocker in ("target", "protect"):
        for held_pages in (1, 70):
            mixed_queue(admin, runtime, future)
            with admin.transaction():
                if blocker == "target":
                    admin.execute("""SELECT FROM rss_reconcile.targets WHERE tenant_id=%s AND reconciler='profile'
                        AND queue_ticket>%s FOR UPDATE""", (TENANT, future + 1))
                else:
                    assert admin.execute("""SELECT rss_reconcile.lock_execution(tenant_id,reconciler,entity,token,epoch,binding_revision)
                        FROM rss_reconcile.targets WHERE tenant_id=%s AND reconciler='holder'""", (TENANT,)).fetchone()[0]
                for _ in range(held_pages):
                    assert runtime.execute(CALL, (TENANT, 1, 128)).fetchone() == (0, True, None)
            release_holder(runtime)
            pages, entity, _, returned = first(runtime)
            assert entity == str(future + 2) and returned == 1
            assert 1 <= pages <= (1 if held_pages == 1 else 32), (blocker, held_pages, pages)
            print(f"ROW_UNLOCK mode={blocker} held_pages={held_pages} recovery_pages={pages} first={entity}", flush=True)


def renewal(admin, runtime, revision):
    seed(admin, 0, 1)
    _, entity, _, _ = first(runtime)
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
        _, entity, _, _ = first(runtime)
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
        pages, entity, _, _ = first(runtime, budget=1, call=CALL.replace("rss_reconcile.claim_due", "lock_probe.claim_due"))
        attempts = admin.execute("SELECT last_value FROM lock_probe.attempts").fetchone()[0]
        assert (pages, entity, attempts) == (5, "5", 5)
        print(f"LOCKS known_held=4 attempts={attempts} locked=1")
    # Two future positions try locked hints 5 and 6. The ticket stream later crosses both.
    seed(admin, 2, 5)
    with admin.transaction():
        admin.execute("SELECT FROM rss_reconcile.targets WHERE queue_ticket>2 FOR UPDATE")
        before = admin.execute("SELECT last_value FROM lock_probe.attempts").fetchone()[0]
        pages, entity, _, _ = first(runtime, budget=8, call=CALL.replace("rss_reconcile.claim_due", "lock_probe.claim_due"))
        attempts = admin.execute("SELECT last_value FROM lock_probe.attempts").fetchone()[0] - before
        assert (pages, entity, attempts) == (1, None, 5)
        print(f"LOCKS overlapping_hints=2 attempts={attempts} locked=0")
    for pause in (0, 0.01):
        seed(admin, 0, 5)
        with admin.transaction():
            admin.execute("SELECT FROM rss_reconcile.targets WHERE queue_ticket<5 FOR UPDATE")
            pages, entity, us, _ = first(runtime, budget=1, pause=pause)
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
                    for future, limit, budget in [(100000, 32, 128), (4096, 8, 8), (4096, 16, 8), (512, 4, 1)]:
                        threshold = min(limit, budget) + 2
                        for due in range(threshold - 1, threshold + 2):
                            compare(admin, runtime, instrumented, revision, future, due, limit=limit, budget=budget)
                    if revision == head:
                        for due in (1, 127, 128, 129, 1024):
                            compare(admin, runtime, instrumented, revision, 10000, due, skew=10000)
                        compare(admin, runtime, instrumented, revision, 100000, 2)
                        hot_progress(admin, runtime, instrumented)
                        wake_strategies(admin, runtime)
                        early_unblock(admin, runtime)
                        short_physical_lock(admin, runtime)
                    blocked_remote_sample(admin, runtime, instrumented, revision)
                    window_costs(admin, instrumented, revision)
                    deep_progress(admin, runtime, instrumented, revision)
                    renewal(admin, runtime, revision)


if __name__ == "__main__":
    main()
