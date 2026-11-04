# SPDX-License-Identifier: Apache-2.0
"""Independent immutable storage and credential separation for document reuse."""
import importlib.util
from pathlib import Path
import sqlite3

import pytest
from starlette.testclient import TestClient
from agent_security_contracts import Denied


@pytest.fixture
def backend(monkeypatch):
    directory = Path(__file__).resolve().parents[3] / "examples/document-agent"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("document_backend", directory / "backend.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def publication():
    return {"collection": "engineering", "document": "runbook", "revision": 1,
        "content": "Synthetic observation", "operation_id": "a" * 32}


def test_committed_revision_survives_restart_and_has_independent_digest(backend, tmp_path, publication):
    store = backend.RevisionStore(tmp_path / "documents.db")
    reference = store.publish(publication)
    reopened = backend.RevisionStore(store.path)
    assert reopened.observe(reference) == publication
    assert reopened.inventory() == [{"reference": reference, "operation_id": publication["operation_id"],
        "digest": backend.DOCUMENTS.canonical(publication)[1]}]
    assert store.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("change", [{"content": "changed"}, {"revision": 2}])
def test_neither_revision_nor_operation_can_be_reused(backend, tmp_path, publication, change):
    store = backend.RevisionStore(tmp_path / "documents.db")
    reference = store.publish(publication)
    with pytest.raises(Denied, match="immutable_revision"):
        store.publish({**publication, **change})
    assert store.observe(reference) == publication and len(store.inventory()) == 1


@pytest.mark.parametrize("statement", ["UPDATE revisions SET digest = 'changed'", "DELETE FROM revisions"])
def test_storage_rejects_in_place_history_changes(backend, tmp_path, publication, statement):
    store = backend.RevisionStore(tmp_path / "documents.db")
    reference = store.publish(publication)
    with pytest.raises(sqlite3.IntegrityError, match="immutable revision"):
        with store.connection() as db:
            db.execute(statement)
    assert store.observe(reference) == publication


@pytest.mark.parametrize("token", [None, "wrong", "observe-key-" * 4])
def test_only_host_write_credential_can_publish(backend, tmp_path, publication, token):
    store = backend.RevisionStore(tmp_path / "documents.db")
    client = TestClient(backend.application(store, "write-key-" * 4, "observe-key-" * 4))
    headers = {"Authorization": "Bearer " + token} if token else {}
    assert client.post("/revisions", json=publication, headers=headers).status_code == 403
    assert store.inventory() == []


def test_observer_reads_exact_committed_effects_but_cannot_write(backend, tmp_path, publication):
    store = backend.RevisionStore(tmp_path / "documents.db")
    client = TestClient(backend.application(store, "write-key-" * 4, "observe-key-" * 4))
    response = client.post("/revisions", json=publication, headers={"Authorization": "Bearer " + "write-key-" * 4})
    assert response.status_code == 201
    headers = {"Authorization": "Bearer " + "observe-key-" * 4}
    assert client.get("/revisions/" + response.json()["reference"], headers=headers).json() == publication
    assert client.get("/revisions", headers=headers).json()[0]["operation_id"] == publication["operation_id"]
    assert client.post("/revisions", json={**publication, "revision": 2}, headers=headers).status_code == 403
    assert len(store.inventory()) == 1


@pytest.mark.parametrize("change", [{"collection": []}, {"collection": "external"}, {"revision": True},
    {"operation_id": "forged"}, {"content": "x" * 2001}, {"destination": "https://external.invalid"}])
def test_malformed_or_agent_selected_backend_effects_are_rejected(backend, tmp_path, publication, change):
    store = backend.RevisionStore(tmp_path / "documents.db")
    client = TestClient(backend.application(store, "write-key-" * 4, "observe-key-" * 4))
    response = client.post("/revisions", json={**publication, **change},
        headers={"Authorization": "Bearer " + "write-key-" * 4})
    assert response.status_code == 403 and store.inventory() == []


def test_duplicate_authentication_and_oversized_body_do_not_mutate(backend, tmp_path, publication):
    store = backend.RevisionStore(tmp_path / "documents.db")
    client = TestClient(backend.application(store, "write-key-" * 4, "observe-key-" * 4))
    auth = ("Authorization", "Bearer " + "write-key-" * 4)
    assert client.post("/revisions", json=publication, headers=[auth, auth]).status_code == 403
    assert client.post("/revisions", content=b"x" * 16385, headers=[auth]).status_code == 403
    assert store.inventory() == []


@pytest.mark.parametrize('mode', ['database_symlink', 'public_database', 'public_directory'])
def test_backend_rejects_untrusted_storage(backend, tmp_path, mode):
    private=tmp_path/'private';private.mkdir(mode=0o700)
    path=private/'documents.db'
    if mode=='database_symlink':
        target=private/'other';target.touch(mode=0o600);path.symlink_to(target)
    elif mode=='public_database':
        path.touch(mode=0o600)
        path.chmod(0o644)
    else:private.chmod(0o755)
    with pytest.raises(ValueError,match='Private backend storage'):
        backend.RevisionStore(path)


def test_lost_response_does_not_undo_or_repeat_backend_commit(backend, tmp_path, publication):
    store=backend.RevisionStore(tmp_path/'documents.db')
    client=TestClient(backend.application(store,'write-key-'*4,'observe-key-'*4,lose_response_revision=3))
    effects={**publication,'revision':3}
    with pytest.raises(OSError,match='synthetic committed response loss'):
        client.post('/revisions',json=effects,headers={'Authorization':'Bearer '+'write-key-'*4})
    assert store.observe('engineering/runbook@3')==effects
    response=client.post('/revisions',json=effects,headers={'Authorization':'Bearer '+'write-key-'*4})
    assert response.status_code==403 and len(store.inventory())==1


def test_platform_group_permissions_restore_without_losing_revisions(backend, tmp_path):
    path = tmp_path / 'private' / 'history.db'
    store = backend.RevisionStore(path)
    effects = backend.DOCUMENTS.proposal({'collection': 'engineering', 'document': 'runbook',
        'revision': 1, 'content': 'Retained synthetic revision'}, 'f' * 32)
    reference = store.publish(effects)
    path.parent.chmod(0o770)
    path.chmod(0o660)
    restarted = backend.RevisionStore(path)
    assert restarted.observe(reference) == effects
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
