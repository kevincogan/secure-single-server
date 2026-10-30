# SPDX-License-Identifier: Apache-2.0
"""Isolate scope and run expiry from other checks that can mask their absence."""
import time
import pytest
from identity_demo_run_store import Denied
from checks.test_run_store import prepare


def test_exact_approval_cannot_authorize_another_project(tmp_path):
    store,run,workload,_=prepare(tmp_path)
    p=store.propose(run,'user-a',{'project':'OTHER','summary':'Summary','description':'Description'})
    store.approve(run,p['action_id'],'user-a',p['digest'],int(time.time())+90)
    d=store.decision(run,p['action_id'],'user-a',workload,p['arguments'],claim=True)
    assert d == {'allowed':False,'dispatch':False,'reason':'project_permission'}


def test_expired_run_cannot_accept_a_new_proposal(tmp_path,monkeypatch):
    store,run,workload,_=prepare(tmp_path)
    future=time.time()+1000
    monkeypatch.setattr('identity_demo_run_store.time.time',lambda:future)
    with pytest.raises(Denied,match='run_inactive'):
        store.propose(run,'user-a',{'project':'TEST','summary':'Summary','description':'Description'})
