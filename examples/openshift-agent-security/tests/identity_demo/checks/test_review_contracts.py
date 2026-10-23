# SPDX-License-Identifier: Apache-2.0
"""Review regressions: UI vocabulary and durable maintenance boundaries."""

import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import deployment_backup as backup
import identity_demo_console as console
from identity_demo_console_store import ConsoleStore, STAGES
import identity_demo_execution_setup as execution
from identity_demo_run_store import Denied


def test_every_recordable_stage_has_explicit_ui_copy() -> None:
    """New coordinator stages must never silently use an unrelated UI state."""
    assert STAGES <= console.STAGE_COPY.keys()
    assert all(len(console.STAGE_COPY[s]) == 3 and all(console.STAGE_COPY[s]) for s in STAGES)


def test_producers_and_animation_share_the_durable_stage_vocabulary() -> None:
    """Catch spelling drift at the actual coordinator/helper producer boundaries."""
    import ast
    from pathlib import Path
    from identity_demo_console_visuals import EVENTS
    root = Path(__file__).resolve().parents[3]
    produced = set()
    for directory in ('scripts/identity_demo', 'tests/identity_demo'):
        for source in (root / directory).glob('*.py'):
            for call in ast.walk(ast.parse(source.read_text())):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr == 'progress' and call.args
                        and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
                    produced.add(call.args[0].value)
    assert produced and produced <= STAGES
    # Expiry is derived directly from the original run deadline in projection().
    assert STAGES - {'expired'} <= {name.removeprefix('console_') for name in EVENTS}


def lifecycle_database(blocker: str) -> sqlite3.Connection:
    """Small legacy-compatible schema; each blocker exists independently."""
    db = sqlite3.connect(':memory:')
    db.executescript("CREATE TABLE runs(id TEXT,active INTEGER);"
        "CREATE TABLE actions(state TEXT);CREATE TABLE audit(value TEXT);"
        "CREATE TABLE console_jobs(state TEXT,evidence TEXT);"
        "CREATE TABLE console_preparations(state TEXT);")
    if blocker == 'run':
        db.execute("INSERT INTO runs VALUES('synthetic',1)")
    elif blocker == 'action':
        db.execute("INSERT INTO actions VALUES('unknown')")
    elif blocker == 'job':
        db.execute("INSERT INTO console_jobs VALUES('queued','{}')")
    elif blocker == 'preparation':
        db.execute("INSERT INTO console_preparations VALUES('preparing')")
    elif blocker == 'blocked_preparation':
        db.execute("INSERT INTO console_preparations VALUES('blocked')")
    elif blocker in ('recovery', 'recovered'):
        db.execute("INSERT INTO console_jobs VALUES('failed',?)", (json.dumps({
            'failure_code': 'recovery_required', 'cleanup_verified': blocker == 'recovered'}),))
    db.commit()
    return db


@pytest.mark.parametrize('blocker', ['idle','run','action','job','preparation','blocked_preparation','recovery','recovered'])
def test_backup_and_console_agree_on_durable_idle(blocker: str) -> None:
    """Maintenance must not bypass a lease-independent console recovery block."""
    with lifecycle_database(blocker) as db:
        allowed = blocker in ('idle', 'recovered')
        if allowed:
            ConsoleStore.pool_idle(db)
        else:
            with pytest.raises(Denied):
                ConsoleStore.pool_idle(db)
        state = backup.lifecycle(db.serialize())
    if allowed:
        backup.driver_quiescent(state)
    else:
        with pytest.raises(ValueError):
            backup.driver_quiescent(state)


@pytest.mark.parametrize('blocker', ['idle','run','action','job','preparation','blocked_preparation','recovery','recovered'])
def test_execution_inventory_obeys_same_durable_boundary(monkeypatch: pytest.MonkeyPatch, blocker: str) -> None:
    """Execute the real in-Pod inventory against a synthetic SQLite connection."""
    with lifecycle_database(blocker) as db:
        class ReadOnlyConnection:
            def __call__(self, *args, **kwargs):
                return db
        output = []
        def run(argv, **kwargs):
            scope = {'print': lambda value: output.append(value)}
            monkeypatch.setattr(sqlite3, 'connect', ReadOnlyConnection())
            exec(argv[-1], scope)
            return SimpleNamespace(returncode=0, stdout=output[-1])
        monkeypatch.setenv('DRIVER_DATABASE', '/synthetic.sqlite')
        monkeypatch.setattr(execution, 'guard', lambda args: None)
        monkeypatch.setattr(execution, 'owned', lambda obj: None)
        monkeypatch.setattr(execution, 'read', lambda *args: {})
        monkeypatch.setattr(execution.subprocess, 'run', run)
        result = execution.inspect_state(SimpleNamespace(kubeconfig='synthetic'))
        assert result['rollback_quiescent'] == (blocker in ('idle', 'recovered'))


def test_run_association_uses_only_the_selected_trust_domain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A supported installation domain must work without accepting another domain."""
    import time
    from uuid import uuid4
    import deployment_profile
    from identity_demo_run_store import RunStore
    profile = deployment_profile.DeploymentProfile.from_dict({
        **deployment_profile.LEGACY.to_dict(), 'trust_domain': 'agents.example.org'})
    config = tmp_path / 'installation.json'
    config.write_text(json.dumps(profile.to_dict()))
    config.chmod(0o600)
    monkeypatch.setenv('IDENTITY_DEMO_CONFIG', str(config))
    store = RunStore(tmp_path / 'runs.db')
    values = dict(issuer='https://issuer.example.org', user='synthetic-user', user_role='analyst',
        workload_role='triage', project='TEST', expires=int(time.time()) + 300, assessment='Synthetic')
    for domain in ('foreign.example.org', 'agents.example.org.attacker.test', 'agents.example.test'):
        with pytest.raises(ValueError):
            store.create_run(**values, workload='spiffe://' + domain + '/openshell/sandbox/' + str(uuid4()))
    assert store.create_run(**values, workload='spiffe://agents.example.org/openshell/sandbox/' + str(uuid4()))


@pytest.mark.parametrize('blocker', ['idle','run','action','job','preparation','blocked_preparation','recovery','recovered'])
def test_profile_cleanup_obeys_same_durable_boundary(monkeypatch: pytest.MonkeyPatch, blocker: str, capsys: pytest.CaptureFixture[str]) -> None:
    """Exercise the actual embedded cleanup SQL, without any Kubernetes mutations."""
    import ast
    import inspect
    import identity_demo_setup as setup
    tree = ast.parse(inspect.getsource(setup.cleanup))
    programs = [ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'program' for t in n.targets)]
    assert len(programs) == 1
    with lifecycle_database(blocker) as db:
        monkeypatch.setattr(sqlite3, 'connect', lambda *args, **kwargs: db)
        monkeypatch.setenv('DRIVER_DATABASE', '/synthetic.sqlite')
        exec(programs[0], {})
        assert json.loads(capsys.readouterr().out)['safe'] == (blocker in ('idle','recovered'))
