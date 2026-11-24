"""Manual baseline/candidate measurement inside the Rust test's disposable TLS fixture."""
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

BASE = "c60f56a916c09ca8eff8405770ebef6d28a66f96"
MIGRATIONS = "crates/saga-postgres/migrations"
CLIENTS = 8
PER_CLIENT = 16


def git(*args):
    return subprocess.check_output(["/usr/bin/git", *args], text=True)


def psql(env, query):
    return subprocess.check_output(
        ["psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        env=env, input=query, text=True, timeout=120,
    ).strip()


def sql_json(value):
    return "'" + json.dumps(value, separators=(",", ":")).replace("'", "''") + "'::jsonb"


def contention(admin, runtime, call):
    args = ["psql", "-XqAt", "-v", "ON_ERROR_STOP=1"]
    with subprocess.Popen(args, env=runtime, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as holder:
        try:
            holder.stdin.write(f"BEGIN; SELECT {call}; SELECT 'held';\n")
            holder.stdin.flush()
            for line in holder.stdout:
                if line.strip() == "held":
                    break
            else:
                raise RuntimeError("holder exited before registration")
            with subprocess.Popen(args + ["-c", f"SELECT {call}"], env=dict(runtime, PGAPPNAME="saga_waiter"),
                                  stdout=subprocess.DEVNULL) as waiter:
                try:
                    end = time.monotonic() + 10
                    while waiter.poll() is None:
                        wait = psql(admin, "SELECT wait_event FROM pg_stat_activity WHERE application_name='saga_waiter' AND cardinality(pg_blocking_pids(pid))>0")
                        if wait:
                            return wait
                        if time.monotonic() >= end:
                            raise TimeoutError("registration produced no lock witness or completion")
                    if waiter.returncode:
                        raise RuntimeError("waiting registration failed")
                    return "completed before holder commit"
                finally:
                    holder.stdin.write("COMMIT;\n")
                    holder.stdin.close()
                    if waiter.wait(timeout=10):
                        raise RuntimeError("registration failed after holder release")
        finally:
            if not holder.stdin.closed:
                holder.stdin.close()


def measure(directory, label, admin, runtime, call, size):
    psql(admin, "TRUNCATE rss_saga.journal, rss_saga.instances")
    psql(runtime, f"SELECT {call}")
    # The composite comes from the installed schema. Both revisions get identical instance counts.
    psql(admin, f"""
        INSERT INTO rss_saga.instances SELECT clone.* FROM
        (SELECT to_jsonb(i) AS seed FROM rss_saga.instances i LIMIT 1) s,
        generate_series(2,{size}) n,
        LATERAL jsonb_populate_record(NULL::rss_saga.instances,
          s.seed || jsonb_build_object('saga_id',md5(n::text)::uuid)) clone;
        ANALYZE rss_saga.instances;
    """)
    assert int(psql(admin, "SELECT count(*) FROM rss_saga.instances")) == size
    # auto_explain emits nested SPI queries as client notices in this representative call only.
    psql(admin, f"""
        LOAD 'auto_explain';
        SET auto_explain.log_min_duration=0;
        SET auto_explain.log_nested_statements=on;
        SET auto_explain.log_analyze=on;
        SET auto_explain.log_buffers=on;
        SET auto_explain.log_timing=off;
        SET auto_explain.log_level=notice;
        SET ROLE saga_runtime;
        BEGIN; SELECT {call}; ROLLBACK;
    """)
    wait = contention(admin, runtime, call)
    prefix = directory / f"{label}-{size}"
    subprocess.run(["pgbench", "-n", "-c", str(CLIENTS), "-j", str(CLIENTS), "-t", str(PER_CLIENT),
                    "-l", "--log-prefix", str(prefix), "-f", str(directory / "register.sql")],
                   env=runtime, check=True, timeout=120)
    times = sorted(int(line.split()[2]) for path in directory.glob(prefix.name + ".*")
                   for line in path.read_text().splitlines())
    assert len(times) == CLIENTS * PER_CLIENT
    assert int(psql(admin, "SELECT count(*) FROM rss_saga.instances")) == size + 2 + len(times)
    print(f"SAGA_REGISTER revision={label} history={size} clients={CLIENTS} n={len(times)} "
          f"mean_us={statistics.mean(times):.1f} p50_us={statistics.median(times):.1f} "
          f"p95_us={times[(95*len(times)+99)//100-1]} contention={wait}", flush=True)


def main():
    fixture = json.load(sys.stdin)
    with tempfile.TemporaryDirectory(prefix="saga-register-") as tmp:
        directory = Path(tmp)
        ca = directory / "ca.pem"
        ca.write_text(fixture["ca"])
        env = dict(os.environ, PGHOST=fixture["host"], PGPORT=str(fixture["port"]), PGDATABASE=fixture["db"],
                   PGSSLROOTCERT=str(ca), PGSSLMODE="verify-full", PGCONNECT_TIMEOUT="10",
                   PGOPTIONS="-c rss.tenant_id=11111111-2222-4333-8444-555555555555 -c statement_timeout=60000")
        admin = dict(env, PGUSER=fixture["user"], PGPASSWORD=fixture["password"])
        runtime = dict(env, PGUSER="saga_runtime", PGPASSWORD="fixture-only")
        call = f"rss_saga.register(gen_random_uuid(),{sql_json(fixture['definition'])},{sql_json(fixture['capacity'])})"
        (directory / "register.sql").write_text(f"SELECT {call};\n")
        files = git("ls-tree", "-r", "--name-only", BASE, MIGRATIONS).splitlines()
        baseline = "\n".join(git("show", f"{BASE}:{path}") for path in files if path.endswith(".sql"))
        # Each version gets a clean schema with the same grants on the same disposable server.
        for label, ddl in [(BASE, baseline), (git("rev-parse", "HEAD").strip(), Path(MIGRATIONS, "install.sql").read_text())]:
            psql(admin, "DROP SCHEMA rss_saga CASCADE; SET ROLE saga_owner;\n" + ddl +
                 "\nRESET ROLE; GRANT USAGE ON SCHEMA rss_saga TO saga_runtime; "
                 "GRANT SELECT ON ALL TABLES IN SCHEMA rss_saga TO saga_runtime; "
                 "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_saga TO saga_runtime;")
            for size in (100, 1000, 10000):
                print(f"PLAN revision={label} history={size}", flush=True)
                measure(directory, label, admin, runtime, call, size)


if __name__ == "__main__":
    main()
