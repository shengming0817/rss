"""Extract transaction lock samples from the isolated PG fixture. Never print SQL parameters."""
import json
import re
import subprocess
import sys

PREFIX = re.compile(r"^(\d+\.\d+)\|(\d+)\|(identity_[0-9a-f]+)\|\s+([A-Z]+):\s+(.*)")
DURATION = re.compile(r"duration: ([\d.]+) ms\s+(?:execute [^:]+|statement):\s*(.*)", re.I)
ACQUIRED = re.compile(r"process \d+ acquired .* after ([\d.]+) ms")


def lock_kind(query):
    if "kind='profile_sequence'" in query and query.startswith("update"):
        return "sequence"
    if "kind='attempt_capacity'" in query and "for update" in query:
        return "attempt_capacity"
    if "identity_authority.tenants" in query and query.endswith("for update"):
        return "collection"
    if "identity_authority.tenants" in query and query.endswith("for key share"):
        return "scope"
    if "rss_ledger" in query and ("lock" in query or "prepare_append" in query):
        return "ledger"
    return None


def operation(query):
    normalized = " ".join(query.split())
    for prefix, name in [
        ("insert into identity_authority.password_attempts", "password_claim"),
        ("delete from identity_authority.password_attempts where tenant_id=$1::uuid and login_digest", "password_settlement"),
        ("update identity_authority.password_attempts set", "password_settlement"),
        ("insert into identity_authority.attempts", "reserve"),
        ("insert into identity_authority.platform_challenges", "platform_challenge"),
        ("delete from identity_authority.platform_challenges where tenant_id=$1::uuid and challenge_id=$2", "platform_issue"),
        ("insert into identity_authority.oidc_transactions", "oidc_begin"),
        ("update identity_authority.oidc_transactions set claimed", "oidc_claim"),
        ("delete from identity_authority.oidc_transactions where tenant_id=$1::uuid and attempt_id=$2", "oidc_callback"),
        ("insert into identity_authority.sessions", "session_issue"),
    ]:
        if normalized.startswith(prefix) or (name == "session_issue" and prefix in normalized):
            return name
    return None


def records(lines):
    current = None
    for line in lines:
        match = PREFIX.match(line)
        if match or re.match(r"^\d+\.\d+\|", line):
            if current:
                yield current
            current = list(match.groups()) if match else None
        elif current:
            current[-1] += line
    if current:
        yield current


def plan_nodes(node):
    fields = ("Node Type", "Relation Name", "Index Name", "Actual Rows", "Actual Loops",
              "Rows Removed by Filter", "Rows Removed by Index Recheck",
              "Shared Hit Blocks", "Shared Read Blocks")
    return {**{k: node[k] for k in fields if k in node},
            "Plans": [plan_nodes(child) for child in node.get("Plans", [])]}


def within(window, row):
    return (window["db"] == row["db"] and window["waiter"] == row["pid"]
            and window["start"] - 1000 <= row["end_us"] <= window["end"] + 1000)


def samples(lines, plans, controls):
    transactions = {}
    counter_databases = set()
    observed_plans = set()
    observed_kinds = set()
    validated = set()
    for clock, pid, db, level, message in records(lines):
        key = (db, int(pid))
        tx = transactions.get(key)
        if level == "CONTEXT" and tx and tx["waits"] and "account_capacity_delta()" in message:
            tx["waits"][-1]["trigger"] = True
        if level != "LOG":
            continue
        now = round(float(clock) * 1_000_000)
        if plans and " plan:" in message and "{" in message:
            item, _ = json.JSONDecoder().raw_decode(message[message.index("{"):])
            sql = " ".join(item["Query Text"].split())
            for table in ("attempts", "password_attempts", "oidc_transactions", "link_intents", "tenant_state", "changed"):
                needle = "FROM changed" if table == "changed" else "identity_authority." + table
                if needle.lower() in sql.lower():
                    observed_plans.add(table)
                    print("AUTH_PLAN", json.dumps([db, now, sql, plan_nodes(item["Plan"])], separators=(",", ":")))
                    break
            continue
        wait = ACQUIRED.match(message)
        if wait and tx:
            tx["waits"].append({"at_us": now, "duration_us": round(float(wait[1]) * 1000)})
        completed = DURATION.match(" ".join(message.split()))
        if not completed:
            continue
        duration = round(float(completed[1]) * 1000)
        query = completed[2].lower().strip()
        if query.startswith("begin"):
            transactions[key] = {"begin_us":now, "waits": [], "op": "other", "events": [], "statements": 0}
            continue
        if tx is None:
            continue
        tx["statements"] += 1
        op = operation(query)
        if op:
            tx["op"] = op
        if "kind='oidc_capacity'" in query:
            counter_databases.add(db)
        kind = lock_kind(query)
        trigger_kind = None
        if db in counter_databases and op in ("oidc_begin", "oidc_callback"):
            # Successful insert/consume charges one row under the tenant collection lock.
            trigger_kind = "oidc_capacity"
        waits, tx["waits"] = tx["waits"], []
        event_kinds = {k for k in (kind, trigger_kind) if k}
        for event in waits:
            event["kind"] = (trigger_kind if event.pop("trigger", False) else kind) or "other"
            event_kinds.add(event["kind"])
        for name in sorted(event_kinds):
            tx["events"].append((name,now,duration,[w for w in waits if w["kind"] == name]))
        if not query.startswith(("commit", "rollback")):
            continue
        # %n resolves milliseconds. PG acquires inside the lock statement and
        # releases inside settlement. Bracket both endpoints, retaining repeated acquisitions.
        for name, end, statement_us, waits in tx["events"]:
            row = dict(db=db,pid=int(pid),begin_us=tx["begin_us"],end_us=now,operation=tx["op"],
                       lock=name,outcome=query.split()[0],statement_us=statement_us,
                       statement_end_to_tx_end_us=now-end,hold_min_us=max(0,now-duration-end-1000),
                       hold_max_us=now-end+statement_us+1000,sql_statements=tx["statements"],
                       wait_log_threshold_us=1000,observed_waits=waits)
            observed_kinds.add(name)
            for i, window in enumerate(controls):
                if within(window, row) and waits and window["lock"] == name:
                    validated.add(i)
            yield row
        del transactions[key]
    required = {"attempt_capacity", "sequence", "collection"}
    if not plans:
        required.add("ledger")
    if counter_databases:
        required.add("oidc_capacity")
    if required - observed_kinds or len(validated) != len(controls):
        raise RuntimeError(f"incomplete lock evidence: missing {required - observed_kinds}, controls {validated}/{len(controls)}")
    if plans:
        required = {"attempts", "password_attempts", "oidc_transactions", "link_intents", "tenant_state"}
        if counter_databases:
            required.add("changed")
        if required - observed_plans:
            raise RuntimeError(f"missing plans for {required - observed_plans}")


if __name__ == "__main__":
    cid = subprocess.check_output(
        ["docker", "ps", "-q", "--filter", "network=" + sys.argv[1]], text=True
    ).split()
    if len(cid) != 1:
        raise RuntimeError("expected one PG container on the measurement network")
    plans = sys.argv[2] == "--plans"
    controls = [] if plans else json.loads(sys.argv[2])
    with subprocess.Popen(["docker", "logs", cid[0]], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as logs:
        for row in samples(logs.stdout, plans, controls):
            print("AUTH_LOCK", json.dumps(row, separators=(",", ":")))
        if logs.wait():
            raise RuntimeError("could not read PG logs")
