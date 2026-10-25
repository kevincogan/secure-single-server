# SPDX-License-Identifier: Apache-2.0
"""Versioned prepared-capacity contracts, independent of workflow authorization.

Only the authenticated installer selects this mode. Native contexts remain
immutable; allocation stores a separate run-specific binding in the same SQLite
transaction as the one-use claim. Legacy contexts are never reinterpreted.
"""

from __future__ import annotations
import hashlib
import json
import re
import time

from deployment_artifacts import IMAGE_REFERENCE
from deployment_profile import active_profile
from identity_demo_connector import Denied, supported_connectors

FRESH_SECONDS = 900
ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def initialize(db):
    db.executescript("""
      CREATE TABLE IF NOT EXISTS console_pool_contract (
        id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL,
        configuration TEXT NOT NULL, receipt TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS console_profile_contexts (
        workload TEXT PRIMARY KEY, profile TEXT NOT NULL, fingerprint TEXT NOT NULL,
        verified_until INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS console_pool_profile_active ON console_pool_items
        (json_extract(context,'$.profile_id'),state) WHERE state<>'retired';
      CREATE INDEX IF NOT EXISTS console_pool_state ON console_pool_items(state);
      CREATE INDEX IF NOT EXISTS console_pool_profile_attempt ON console_pool_items
        (json_extract(context,'$.profile_id'));
      CREATE TABLE IF NOT EXISTS console_run_contexts (
        run_id TEXT PRIMARY KEY REFERENCES runs(id), context TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS console_pool_contract_history (
        digest TEXT PRIMARY KEY, configuration TEXT NOT NULL,
        receipt TEXT NOT NULL, recorded_at INTEGER NOT NULL);
    """)


def configuration(db):
    row = db.execute(
        "SELECT version,configuration FROM console_pool_contract WHERE id=1"
    ).fetchone()
    if not row:
        return None
    if row["version"] != 2:
        raise Denied("pool_schema")
    return json.loads(row["configuration"])


def fingerprint(profile):
    return digest({k: v for k, v in profile.items() if k != "target"})


def validate(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "profiles", "workflows"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or not isinstance(value["profiles"], list)
        or not 1 <= len(value["profiles"]) <= 12
        or not isinstance(value["workflows"], list)
        or not 1 <= len(value["workflows"]) <= 64
    ):
        raise Denied("pool_configuration")
    installation = active_profile()
    profiles = {}
    required = {
        "id",
        "role",
        "namespace",
        "service_account",
        "workload_image",
        "supervisor_image",
        "policy",
        "trust_domain",
        "issuer",
        "tools",
        "write_actions",
        "target",
    }
    for p in value["profiles"]:
        if (
            not isinstance(p, dict)
            or set(p) != required
            or not isinstance(p["id"], str)
            or not ID.fullmatch(p["id"])
            or p["id"] in profiles
            or p["role"] not in ("triage", "reader")
            or p["namespace"] != installation.namespace_for(p["role"])
            or p["service_account"] != "fixture-openshell-sandbox"
            or p["trust_domain"] != installation.trust_domain
            or type(p["target"]) is not int
            or not 1 <= p["target"] <= 12
            or any(
                not isinstance(p[k], str)
                or not IMAGE_REFERENCE.fullmatch(p[k])
                or p[k].endswith("0" * 64)
                for k in ("workload_image", "supervisor_image")
            )
            or not isinstance(p["policy"], dict)
            or type(p["policy"].get("version")) is not int
            or p["policy"].get("version") != 1
            or len(json.dumps(p["policy"])) > 8192
        ):
            raise Denied("pool_profile")
        from deployment_artifacts import native_supervisor_images

        if (
            p["issuer"]
            != installation.native_build_contract["OPENSHELL_DEMO_JWT_AUDIENCE"]
            or p["supervisor_image"] not in native_supervisor_images()
        ):
            raise Denied("pool_profile")
        for key in ("tools", "write_actions"):
            if (
                not isinstance(p[key], list)
                or len(p[key]) > 32
                or any(not isinstance(v, str) or not ID.fullmatch(v) for v in p[key])
                or len(set(p[key])) != len(p[key])
            ):
                raise Denied("pool_profile")
        if p["role"] == "reader" and p["write_actions"]:
            raise Denied("workload_permission")
        profiles[p["id"]] = p
    if sum(p["target"] for p in profiles.values()) > 12:
        raise Denied("pool_capacity")
    seen = set()
    actions = {name: {"tools": set(), "writes": set()} for name in profiles}
    for w in value["workflows"]:
        if (
            not isinstance(w, dict)
            or set(w) != {"workflow", "profile", "project", "connector"}
            or not isinstance(w["profile"], str)
            or w["profile"] not in profiles
            or not isinstance(w["workflow"], str)
            or not ID.fullmatch(w["workflow"])
            or not isinstance(w["project"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}", w["project"])
            or not isinstance(w["connector"], str)
            or not ID.fullmatch(w["connector"])
        ):
            raise Denied("pool_workflow")
        contract = supported_connectors().resolve(w["connector"])
        role = profiles[w["profile"]]["role"]
        if (not contract.profile_tools or role not in contract.workload_roles
                or not contract.valid_scope(w["project"])):
            raise Denied("pool_connector_permissions")
        approved = actions[w["profile"]]
        if role in contract.write_workload_roles:
            approved["tools"].update(contract.profile_tools)
            approved["writes"].update(contract.profile_write_actions)
        else:
            approved["tools"].update(set(contract.profile_tools) - set(contract.profile_write_actions))
        key = (w["workflow"], profiles[w["profile"]]["role"])
        if key in seen:
            raise Denied("pool_workflow")
        seen.add(key)
    if {w["profile"] for w in value["workflows"]} != set(profiles):
        raise Denied("pool_workflow")
    for name, p in profiles.items():
        if (set(p["tools"]) != actions[name]["tools"]
                or set(p["write_actions"]) != actions[name]["writes"]):
            raise Denied("pool_connector_permissions")
    return value


def configure(db, value, receipt):
    validate(value)
    if not isinstance(receipt, str) or not re.fullmatch("[a-f0-9]{64}", receipt):
        raise Denied("pool_configuration")
    old = configuration(db)
    if old is not None and old != value:
        replacements = {p["id"]: fingerprint(p) for p in value["profiles"]}
        # Pending/quarantined creation can have no verified profile row yet.
        # Its original reservation still pins the security fingerprint.
        active = [
            json.loads(row[0])
            for row in db.execute(
                "SELECT context FROM console_pool_items WHERE state<>'retired'"
            )
        ]
        if any(
            "profile_id" in context
            and (
                not isinstance(context.get("profile_fingerprint"), str)
                or replacements.get(context["profile_id"])
                != context["profile_fingerprint"]
            )
            for context in active
        ):
            raise Denied("pool_contract_changed")
        previous = db.execute(
            "SELECT receipt FROM console_pool_contract WHERE id=1"
        ).fetchone()[0]
        db.execute(
            "INSERT OR IGNORE INTO console_pool_contract_history VALUES(?,?,?,?)",
            (digest(old), json.dumps(old, sort_keys=True), previous, int(time.time())),
        )
    if db.execute(
        "SELECT 1 FROM console_pool_items WHERE state='ready' AND workload NOT IN "
        "(SELECT workload FROM console_profile_contexts)"
    ).fetchone():
        raise Denied("legacy_contexts_not_retired")
    encoded = json.dumps(value, sort_keys=True)
    db.execute(
        "INSERT OR IGNORE INTO console_pool_contract_history VALUES(?,?,?,?)",
        (digest(value), encoded, receipt, int(time.time())),
    )
    db.execute(
        "INSERT INTO console_pool_contract VALUES(1,2,?,?) ON CONFLICT(id) DO UPDATE SET configuration=excluded.configuration,receipt=excluded.receipt",
        (encoded, receipt),
    )
    db.execute(
        "INSERT INTO console_pool_settings VALUES(1,1,?,?) ON CONFLICT(id) DO UPDATE SET enabled=1,receipt=excluded.receipt,updated=excluded.updated",
        (receipt, int(time.time())),
    )


def profile_for(db, identifier):
    config = configuration(db)
    if not config:
        raise Denied("pool_profile")
    matches = [p for p in config["profiles"] if p["id"] == identifier]
    if len(matches) != 1:
        raise Denied("pool_profile")
    return matches[0]


def ready(db, workload):
    row = db.execute(
        "SELECT profile,fingerprint,verified_until FROM console_profile_contexts WHERE workload=?",
        (workload,),
    ).fetchone()
    return bool(
        row
        and row["fingerprint"] == fingerprint(profile_for(db, row["profile"]))
        and row["verified_until"] > time.time()
    )


def expand(db, contexts):
    """Offer compatible virtual choices without changing a stored native context."""
    config = configuration(db)
    if not config:
        return contexts
    result = []
    for c in contexts:
        if "profile_id" not in c:
            result.append(c)
            continue
        binding = db.execute(
            "SELECT context FROM console_run_contexts x JOIN runs r ON r.id=x.run_id WHERE r.workload=?",
            (c["workload"],),
        ).fetchone()
        if binding:
            result.append(json.loads(binding[0]))
            continue
        if not any(w["profile"] == c["profile_id"] for w in config["workflows"]):
            result.append(c)
            continue
        for w in config["workflows"]:
            if w["profile"] == c["profile_id"]:
                result.append(
                    dict(
                        c,
                        workflow=w["workflow"],
                        project=w["project"],
                        connector=w["connector"],
                    )
                )
    return result


def bind(db, run, context, workflow, project, role, connector):
    row = db.execute(
        "SELECT context FROM console_pool_items WHERE workload=?", (context,)
    ).fetchone()
    base = json.loads(row[0]) if row else {}
    if not configuration(db):
        return
    if "profile_id" not in base or not ready(db, context):
        raise Denied("context_unavailable")
    profile = profile_for(db, base["profile_id"])
    if (
        base.get("profile_fingerprint") != fingerprint(profile)
        or profile["role"] != role
        or base.get("namespace") != profile["namespace"]
    ):
        raise Denied("pool_profile")
    matches = [
        w
        for w in configuration(db)["workflows"]
        if w["workflow"] == workflow
        and w["profile"] == profile["id"]
        and w["project"] == project
        and w["connector"] == connector
    ]
    if len(matches) != 1:
        raise Denied("pool_workflow")
    db.execute(
        "INSERT INTO console_run_contexts VALUES(?,?)",
        (
            run,
            json.dumps(
                dict(base, workflow=workflow, project=project, connector=connector),
                sort_keys=True,
            ),
        ),
    )



def state_counts(db):
    """Seven transactionally maintained totals; tombstones are never rescanned."""
    return {row["state"]: row["n"] for row in db.execute(
        "SELECT state,n FROM console_pool_state_counts")}


def snapshot(db):
    config = configuration(db)
    if not config:
        return None
    counts = state_counts(db)
    slots = []
    for p in config["profiles"]:
        rows = db.execute(
            "SELECT workload,state FROM console_pool_items INDEXED BY console_pool_profile_active WHERE json_extract(context,'$.profile_id')=? AND state<>'retired'",
            (p["id"],),
        ).fetchall()
        slots.append(
            {
                "profile_id": p["id"],
                "workflow": p["id"],
                "role": p["role"],
                "project": "",
                "target": p["target"],
                "available": sum(
                    r["state"] == "ready" and ready(db, r["workload"]) for r in rows
                ),
                "preparing": sum(r["state"] == "preparing" for r in rows),
            }
        )
    return {
        "mode": "profiles",
        "target": sum(p["target"] for p in config["profiles"]),
        "limit": 12,
        "managed": sum(v for k, v in counts.items() if k != "retired"),
        "states": counts,
        "slots": slots,
    }


def next_target(db, closed):
    view = snapshot(db)
    stale = db.execute(
        "SELECT p.id,p.context FROM console_pool_items p JOIN console_profile_contexts c ON c.workload=p.workload "
        "WHERE p.state='ready' AND c.verified_until<=? ORDER BY c.verified_until,p.id LIMIT 1",
        (int(time.time()),),
    ).fetchone()
    if stale:
        previous = json.loads(stale["context"])
        return {
            "operation": "verify",
            "automatic": True,
            "item_id": stale["id"],
            "previous": previous,
            "role": previous["role"],
            "profile_id": previous["profile_id"],
            "profile": profile_for(db, previous["profile_id"]),
        }
    depleted = [
        s for s in view["slots"] if s["available"] + s["preparing"] < s["target"]
    ]
    if view["managed"] >= 12 or not depleted:
        item = db.execute(
            "SELECT * FROM console_pool_items WHERE state='consumed' ORDER BY updated,id LIMIT 1"
        ).fetchone()
        if item and closed(db, item["workload"]):
            c = json.loads(item["context"])
            db.execute(
                "UPDATE console_pool_items SET state='retiring',updated=? WHERE id=?",
                (int(time.time()), item["id"]),
            )
            return {
                "operation": "retire",
                "automatic": True,
                "item_id": item["id"],
                "previous": c,
                "role": c["role"],
                "workflow": c.get("workflow", "cve"),
                "project": c.get("project", "TEST"),
                "disposable": bool(item["disposable"]),
            }
    if view["managed"] >= 12 or not depleted:
        return None
    attempted = {
        s["profile_id"]: db.execute(
            "SELECT coalesce(max(rowid),0) FROM console_pool_items WHERE json_extract(context,'$.profile_id')=?",
            (s["profile_id"],),
        ).fetchone()[0]
        for s in depleted
    }
    s = min(depleted, key=lambda s: (s["available"], attempted[s["profile_id"]]))
    p = profile_for(db, s["profile_id"])
    return {
        "operation": "prepare",
        "automatic": True,
        "previous": None,
        "disposable": True,
        "role": p["role"],
        "profile_id": p["id"],
        "profile_fingerprint": fingerprint(p),
        "profile": p,
    }


def finish(db, target, context):
    if context is None:
        return
    p = profile_for(db, target["profile_id"])
    if (
        context.get("profile_id") != p["id"]
        or context.get("profile_fingerprint") != fingerprint(p)
        or context["role"] != p["role"]
        or context["namespace"] != p["namespace"]
        or context["service_account"] != p["service_account"]
        or not isinstance(context.get("native_policy_hash"), str)
        or not re.fullmatch("[a-f0-9]{64}", context["native_policy_hash"])
        or "workflow" in context
        or "project" in context
        or "connector" in context
    ):
        raise Denied("preparation_binding")
    db.execute(
        "INSERT INTO console_profile_contexts VALUES(?,?,?,?) ON CONFLICT(workload) DO UPDATE SET verified_until=excluded.verified_until",
        (
            context["workload"],
            p["id"],
            fingerprint(p),
            int(time.time()) + FRESH_SECONDS,
        ),
    )
