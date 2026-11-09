# SPDX-License-Identifier: Apache-2.0
"""Offline mutation-boundary checks, distinct from deployed authorization acceptance."""

from copy import deepcopy

import pytest

from protected_listener import HOST, LABELS, NS, gateway_patch, resources


def gateway() -> dict:
    """Supply one synthetic owned gateway with two existing listeners."""
    return {"metadata": {"name": "fixture-mcp", "namespace": NS,
                          "labels": dict(LABELS), "uid": "uid-a", "resourceVersion": "42"},
            "spec": {"listeners": [{"name": "mcp", "port": 8080},
                                   {"name": "mcps", "port": 8080}]}}


def test_exact_append_preserves_existing_listeners() -> None:
    """The renderer never reconstructs or overwrites the other listeners."""
    value = gateway()
    before = deepcopy(value)
    patch = gateway_patch(value)
    assert value == before
    assert patch[2]["value"] == before["spec"]
    assert patch[3]["path"] == "/spec/listeners/-"
    assert patch[3]["value"]["tls"]["mode"] == "Terminate"
    assert "options" not in patch[3]["value"]["tls"]


@pytest.mark.parametrize("mutation", ["owner", "namespace", "port", "name"])
def test_collision_or_other_owner_refused(mutation: str) -> None:
    """An ambiguous deployment must fail before the API mutation."""
    value = gateway()
    if mutation == "owner":
        value["metadata"]["labels"]["identity-demo-owner"] = "another-owner"
    elif mutation == "namespace":
        value["metadata"]["namespace"] = "shared"
    elif mutation == "port":
        value["spec"]["listeners"].append({"name": "other", "port": 8443})
    else:
        value["spec"]["listeners"].append({"name": "bound", "port": 9443})
    with pytest.raises(ValueError):
        gateway_patch(value)


def test_internal_service_reuses_gateway_and_sanitizes_claimed_peer() -> None:
    """No public endpoint or proxy is added; claimed peer metadata is stripped."""
    values = resources()
    assert [v["kind"] for v in values] == ["Service", "HTTPRoute", "EnvoyFilter"]
    assert all(v["metadata"]["namespace"] == NS for v in values)
    assert values[1]["spec"]["hostnames"] == [HOST]
    settings = values[2]["spec"]["configPatches"][0]["patch"]["value"]["typed_config"]
    assert settings["forward_client_cert_details"] == "SANITIZE"
    assert "set_current_client_cert_details" not in settings


def test_fresh_install_listener_strips_claimed_peer_headers():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    template = json.loads((root / 'infra/identity-demo/templates/application.json').read_text())
    peer, = [v for v in template['objects'] if v['kind'] == 'EnvoyFilter'
             and v['metadata']['name'] == 'fixture-mcp-bound-peer']
    settings = peer['spec']['configPatches'][0]['patch']['value']['typed_config']
    assert settings['forward_client_cert_details'] == 'SANITIZE'
    assert 'set_current_client_cert_details' not in settings


def test_public_cli_selects_the_enforced_protected_listener(monkeypatch, capsys):
    import native_exchange as native
    import sys
    arguments = ['probe']
    for name in ('kubeconfig', 'expected-server', 'credentials-file', 'cli', 'cli-config-dir', 'label', 'output-dir'):
        arguments += ['--' + name, '/synthetic/' + name]
    monkeypatch.setattr(sys, 'argv', arguments + ['--protected-listener', '--check-run-binding', '--upstream-development-issuer'])
    monkeypatch.setattr(native, 'driver_flow', lambda args: None)
    def run(args):
        assert args.protected_listener and args.check_run_binding and args.upstream_development_issuer
        assert not hasattr(args, 'bound_protected_listener')
        return {'passed': True}
    monkeypatch.setattr(native, 'run', run)
    with pytest.raises(SystemExit) as outcome:
        native.main()
    assert outcome.value.code == 0
    assert '"passed": true' in capsys.readouterr().out
