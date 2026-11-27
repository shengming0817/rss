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
    for prefix, name in [
        ("insert into identity_authority.password_attempts", "password_claim"),
        ("delete from identity_authority.password_attempts where tenant_id=", "password_settlement"),
        ("insert into identity_authority.attempts", "reserve"),
        ("insert into identity_authority.platform_challenges", "platform_challenge"),
        ("delete from identity_authority.platform_challenges where tenant_id=$1::uuid and challenge_id=$2", "platform_issue"),
        ("insert into identity_authority.oidc_transactions", "oidc_begin"),
        ("update identity_authority.oidc_transactions set claimed", "oidc_claim"),
        ("delete from identity_authority.oidc_transactions where tenant_id=$1::uuid and attempt_id=$2", "oidc_callback"),
        ("insert into identity_authority.sessions", "session_issue"),
    ]:
        if query.startswith(prefix) or (query.startswith("with ") and prefix in query):
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


def samples(lines, plans):

    transactions = {}
    for clock, pid, db, level, message in records(lines):
        if level != "LOG":
            continue
        now = round(float(clock) * 1_000_000)
        if plans and " plan:" in message and "{" in message:
            item, _ = json.JSONDecoder().raw_decode(message[message.index("{"):])
            sql = " ".join(item["Query Text"].split())
            if any("identity_authority." + t in sql for t in ("attempts", "password_attempts", "oidc_transactions", "link_intents", "tenant_state")):
                # Production queries use placeholders. Restrict output to their prepared shapes.
                print("AUTH_PLAN", json.dumps([db, now, sql, plan_nodes(item["Plan"])], separators=(",", ":")))
            continue
        wait = ACQUIRED.match(message)
        key = (pid, db)
        if wait and key in transactions:
            transactions[key]["wait"] += round(float(wait[1]) * 1000)
        completed = DURATION.match(" ".join(message.split()))
        if not completed:
            continue
        duration = round(float(completed[1]) * 1000)
        query = completed[2].lower().strip()
        if query.startswith("begin"):
            transactions[key] = {"wait": 0, "op": "other", "locks": {}, "statements": 0}
            continue
        tx = transactions.get(key)
        if tx is None:
            continue
        tx["statements"] += 1
        kind = lock_kind(query)
        if kind or tx["wait"]:
            tx["locks"].setdefault(kind or "other", [now, duration, tx["wait"]])
        tx["wait"] = 0
        op = operation(query)
        if op:
            tx["op"] = op
        if query.startswith(("commit", "rollback")):
            for kind, (acquired, duration, wait) in tx["locks"].items():
                yield [db, now, tx["op"], kind, duration, now-acquired, wait or None, tx["statements"]]
            del transactions[key]


if __name__ == "__main__":
    cid = subprocess.check_output(
        ["docker", "ps", "-q", "--filter", "network=" + sys.argv[1]], text=True
    ).split()
    if len(cid) != 1:
        raise RuntimeError("expected one PG container on the measurement network")
    with subprocess.Popen(["docker", "logs", cid[0]], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as logs:
        for row in samples(logs.stdout, "--plans" in sys.argv):
            print("AUTH_LOCK", json.dumps(row, separators=(",", ":")))
        if logs.wait():
            raise RuntimeError("could not read PG logs")
