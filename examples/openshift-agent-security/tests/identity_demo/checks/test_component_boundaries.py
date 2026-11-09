# SPDX-License-Identifier: Apache-2.0
"""Behavior at the optional UI and installer-maintenance boundaries."""
import ast
import builtins
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from starlette.testclient import TestClient

from checks.support.driver import setup
from identity_demo_driver import Driver
from agent_security_runtime import VerifiedActor


def test_protected_operations_work_when_rendering_imports_are_forbidden(tmp_path, monkeypatch):
    previous, _, run, _ = setup(tmp_path)
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name in {'identity_demo_browser_routes', 'identity_demo_console', 'identity_demo_console_visuals'}:
            raise ImportError('UI must remain optional')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    backend = Driver(previous.config, previous.verify, with_ui=False)
    backend.sessions = previous.sessions
    client = TestClient(backend.app, base_url=backend.config.origin)
    assert client.get('/').status_code == 404
    assert client.get('/healthz').status_code == 200
    actor = VerifiedActor('user-a', backend.config.contexts[0]['workload'])
    proposal = backend.actions.propose(actor, run, {'project':'TEST','summary':'Headless operation','description':'Synthetic'})
    backend.actions.approve(actor, run, proposal['action_id'], proposal['digest'], int(time.time())+60)
    assert backend.store.decision(run, proposal['action_id'], actor.user, actor.workload,
                                  proposal['arguments'], claim=True)['dispatch'] is True
    assert not client.post('/internal/operator/run', json={}).is_success


def test_browser_projection_never_passes_tokens_or_arbitrary_claims_to_rendering(tmp_path, monkeypatch):
    from identity_demo_browser_routes import display_claims
    driver, _, _, _ = setup(tmp_path)
    session = driver.sessions['opaque']
    session['claims']['unexpected_private_claim'] = 'private-value'
    projected = display_claims(driver, session)
    assert projected['sub'] == 'user-a'
    assert not {'token','refresh_token','unexpected_private_claim','realm_access'} & projected.keys()


@pytest.mark.parametrize('changed', ['profile', 'module'])
def test_unused_retirement_required_checks_survive_optimized_python(tmp_path, changed):
    import unused_context_retirement as maintenance
    source = ast.parse(inspect.getsource(maintenance.state))
    program = next(n.value.value for n in ast.walk(source)
                   if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='program' for t in n.targets))
    configuration = tmp_path/'configuration.json'
    configuration.write_text('{}')
    value = {'profile': {'wrong':'installation'} if changed=='profile' else {},
             'modules': {name:'0'*64 for name in ('identity_demo_warm_pool','identity_demo_run_store',
                                                'agent_security','agent_security_contracts')}}
    result = subprocess.run([sys.executable,'-O','-c',program], input=json.dumps(value),
        env={**os.environ,'IDENTITY_DEMO_CONFIG':str(configuration)}, capture_output=True,text=True,timeout=20)
    assert result.returncode != 0
    assert 'ValueError' in result.stderr
    assert ('Required maintenance or interface check failed' if changed=='profile'
            else 'Reviewed durable guards must be deployed first') in result.stderr


def test_operator_transport_never_sends_its_credential_to_other_routes():
    from identity_demo_control_transport import driver_request
    from identity_demo_action_policy import DRIVER
    from identity_demo_keycloak_upstream import BASE
    class UnusedClient:
        def open(self, *args, **kwargs):
            pytest.fail('Rejected destination reached the credential-bearing transport')
    for url in (DRIVER+'/', BASE+'/realms/identity-demo', 'https://unapproved.example.test/internal/operator/run'):
        with pytest.raises(ValueError):
            driver_request(UnusedClient(), url, value={}, operator_secret='operator-'*8)
