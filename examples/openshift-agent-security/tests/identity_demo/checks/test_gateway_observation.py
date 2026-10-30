# SPDX-License-Identifier: Apache-2.0
"""Incomplete read-only snapshots cannot bypass the actual readiness/security gates."""

from argparse import Namespace
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import native_backend as backend
import probe_gateway_credential_route as checks
import identity_demo_gateway_observation as observation


def cluster_probe(tmp_path,monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME','cluster')
    probe=backend.NativeBackend(Namespace(output_dir=tmp_path,label='discovery',gateway_mode='persistent',
        permission_flow=SimpleNamespace(progress=lambda *a:None)))
    probe.ca='trusted-public-ca'
    return probe


def test_cluster_discovery_reconciliation_waits_without_replaying_execution(tmp_path,monkeypatch):
    probe=cluster_probe(tmp_path,monkeypatch);calls=[]
    def current(*args):
        calls.append('read')
        if len(calls)==1:raise observation.GatewayDiscoveryPending({'status':{'discoveredTools':0}})
        return {'actual-security-checks':True}
    monkeypatch.setattr(observation,'current',current)
    monkeypatch.setattr(backend.time,'sleep',lambda *a:None)
    assert probe.ready()=={'actual-security-checks':True} and calls==['read','read']
    receipt=json.loads((tmp_path/'discovery.backend-discovery-wait-1.summary.json').read_text())
    assert receipt['discovered_tools']==0 and receipt['ready'] is False


def test_cluster_security_failure_is_never_retried_as_discovery(tmp_path,monkeypatch):
    probe=cluster_probe(tmp_path,monkeypatch);calls=[]
    def current(*args):
        calls.append('read');raise ValueError('Certificate or policy changed')
    monkeypatch.setattr(observation,'current',current)
    with pytest.raises(ValueError,match='Certificate'):probe.ready()
    assert calls==['read'] and not list(tmp_path.iterdir())


def test_cluster_discovery_wait_remains_bounded_and_never_assumes_success(tmp_path,monkeypatch):
    probe=cluster_probe(tmp_path,monkeypatch);now=[0.0];calls=[]
    def current(*args):
        calls.append('read');raise observation.GatewayDiscoveryPending({'status':{}})
    monkeypatch.setattr(observation,'current',current)
    monkeypatch.setattr(backend.time,'monotonic',lambda:now[0])
    monkeypatch.setattr(backend.time,'sleep',lambda duration:now.__setitem__(0,now[0]+duration))
    with pytest.raises(observation.GatewayDiscoveryPending):probe.ready()
    assert now[0]==30 and len(calls)==16


def snapshot(ca: str = "public-fixture-ca") -> dict:
    """Build a complete synthetic dump accepted by the real TLS/order validators."""
    route = backend.route
    names = [
        "envoy.filters.http.ext_authz.step56_identity",
        "envoy.filters.http.wasm",
        "envoy.filters.http.ext_proc",
        route.FILTER + "-step4",
        "envoy.filters.http.router",
    ]
    clusters = [
        {"cluster": {"name": name, "transport_socket": route.tls_context(host, ca)}}
        for name, host in (
            ("kuadrant-auth-service", route.AUTHORIZER + ".cluster.local"),
            ("outbound|8443||" + checks.candidate.ADAPTER, checks.candidate.ADAPTER),
            (route.CLUSTER + "-step4", checks.candidate.AUTHORIZER),
        )
    ]
    return {
        "configs": [
            *clusters,
            {
                "listener": {
                    "address": {"socket_address": {"port_value": 8443}},
                    "http_filters": [{"name": name} for name in names],
                }
            },
            {
                "route_config": {
                    "name": "http.8080",
                    "virtual_hosts": [
                        {
                            "domains": [route.READ_HOST],
                            "typed_per_filter_config": {route.FILTER + "-step4": {}},
                        },
                        {
                            "domains": ["other.synthetic.invalid"],
                            "typed_per_filter_config": {
                                route.FILTER + "-step4": {"disabled": True}
                            },
                        },
                    ],
                }
            },
            {"route_config": {"name": "https.8443.bound", "virtual_hosts": [{
                "domains": [route.READ_HOST],
                "typed_per_filter_config": {route.FILTER + "-step4": {}},
            }]}},
        ]
    }


def probe_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> backend.NativeBackend:
    """Mock only external GETs; retain the real TLS, ordering and discovery validators."""
    args = Namespace(
        output_dir=tmp_path,
        label="observation",
        kubeconfig="private",
        permission_flow=SimpleNamespace(progress=lambda *_: None),
    )
    probe = backend.NativeBackend(args)
    probe.ca = "public-fixture-ca"
    monkeypatch.setattr(
        backend.shared,
        "owned",
        lambda *a: {
            "status": {
                "summary": {"ready": True},
                "conditions": [{"type": "Ready", "status": "True"}],
                "discoveredTools": 2,
            }
        },
    )

    def kube(_: Namespace, *words: str, **kwargs: object) -> dict:
        assert words[0] == "get"  # Observation never creates/patches/replays a write.
        return {
            "items": [
                {
                    "metadata": {
                        "name": "owned-gateway",
                        "uid": "exact-pod",
                        "labels": dict(backend.shared.LABELS),
                    }
                }
            ]
        }

    monkeypatch.setattr(backend.shared, "kube", kube)
    monkeypatch.setattr(backend, "reconciliation_status", lambda _args: (
        {"status": {"conditions": [{"type": "Ready", "status": "True"}]}},
        {"status": {"discoveredTools": 2, "conditions": [{"type": "Ready", "status": "True"}]}}))
    monkeypatch.setattr(backend.time, "sleep", lambda _: None)
    return probe


@pytest.mark.parametrize(
    "body", ["", '{"configs":[{"partial":"fixture-private-value', "not-json"]
)
def test_truncated_snapshot_is_classified_without_retaining_body(
    monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    """A zero CLI status is insufficient when the JSON body was cut short."""
    calls = []

    def run(words: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(words)
        assert words[-3:] == ["request", "GET", "config_dump"]
        return subprocess.CompletedProcess(words, 0, stdout=body, stderr="")

    monkeypatch.setattr(backend.subprocess, "run", run)
    def unavailable(*args: object) -> None:
        raise backend.GatewayObservationUnavailable("incomplete_json", body)
    monkeypatch.setattr(backend, "gateway_http_snapshot", unavailable)
    with pytest.raises(backend.GatewayObservationUnavailable) as error:
        backend.gateway_snapshot(Namespace(kubeconfig="private"), "owned-gateway", 3)
    assert error.value.summary["category"] == "incomplete_json" and len(calls) == 1
    assert "fixture-private-value" not in str(
        error.value
    ) and "fixture-private-value" not in json.dumps(error.value.summary)


@pytest.mark.parametrize(
    "error",
    ["Forbidden: unexpected EOF", "Unauthorized", "x509 certificate error: EOF"],
)
def test_authorization_or_tls_rejection_is_terminal(
    monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    """A transport-looking substring cannot turn a security rejection into a retry."""
    monkeypatch.setattr(
        backend.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 1, stdout="", stderr=error),
    )
    with pytest.raises(RuntimeError) as caught:
        backend.gateway_snapshot(Namespace(kubeconfig="private"), "owned", 3)
    assert not isinstance(caught.value, backend.GatewayObservationUnavailable)


@pytest.mark.parametrize("body", ["[]", "null", '{"configs":{}}', '{"unrelated":true}'])
def test_complete_but_wrong_protocol_shape_cannot_be_ready(
    monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    """Malformed complete objects are never accepted as a successful snapshot."""
    monkeypatch.setattr(
        backend.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, stdout=body, stderr=""),
    )
    with pytest.raises(ValueError):
        backend.gateway_snapshot(Namespace(kubeconfig="private"), "owned", 3)


def test_incomplete_read_then_valid_snapshot_passes_every_real_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same readiness attempt can recover without a new run or any write retry."""
    probe = probe_at(tmp_path, monkeypatch)
    calls = []

    def observe(*args: object) -> dict:
        calls.append(True)
        if len(calls) == 1:
            raise backend.GatewayObservationUnavailable(
                "incomplete_json", "fixture-private-value"
            )
        return snapshot()

    monkeypatch.setattr(backend, "gateway_snapshot", observe)
    assert all(probe.ready().values()) and len(calls) == 2
    receipts = list(tmp_path.glob("*.backend-observation-*.summary.json"))
    assert len(receipts) == 1 and "fixture-private-value" not in receipts[0].read_text()


def test_valid_json_with_wrong_ca_is_not_a_recovery_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recovery must not accept a stale or malformed security configuration."""
    probe = probe_at(tmp_path, monkeypatch)
    dumps = iter([snapshot("foreign-ca"), snapshot()])
    calls = []

    def observe(*args: object) -> dict:
        calls.append(True)
        return next(dumps)

    monkeypatch.setattr(backend, "gateway_snapshot", observe)
    assert all(probe.ready().values()) and len(calls) == 2


def test_permanent_truncation_stops_after_three_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Persistent bad observations stop cleanly rather than looping or assuming readiness."""
    probe = probe_at(tmp_path, monkeypatch)
    calls = []

    def observe(*args: object) -> dict:
        calls.append(True)
        raise backend.GatewayObservationUnavailable("incomplete_json")

    monkeypatch.setattr(backend, "gateway_snapshot", observe)
    with pytest.raises(RuntimeError, match="three bounded reads"):
        probe.ready()
    assert len(calls) == 3 and not list(tmp_path.glob("*.backend-ready.summary.json"))


def test_ownership_is_rechecked_after_incomplete_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second observation cannot use the first one's cached ownership decision."""
    probe = probe_at(tmp_path, monkeypatch)
    reads = []
    snapshots = []

    def kube(*args: object, **kwargs: object) -> dict:
        reads.append(True)
        labels = dict(backend.shared.LABELS)
        if len(reads) > 1:
            labels["identity-demo-owner"] = "foreign"
        return {"items": [{"metadata": {"name": "owned-gateway", "labels": labels}}]}

    def observe(*args: object) -> dict:
        snapshots.append(True)
        raise backend.GatewayObservationUnavailable("incomplete_json")

    monkeypatch.setattr(backend.shared, "kube", kube)
    monkeypatch.setattr(backend, "gateway_snapshot", observe)
    with pytest.raises(ValueError, match="exact owned gateway"):
        probe.ready()
    assert len(reads) == 2 and len(snapshots) == 1


def test_truncated_exec_recovers_only_through_complete_http_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend.subprocess, "run", lambda *a, **kw:
        subprocess.CompletedProcess(a[0], 0, stdout='{"configs":[', stderr=''))
    calls = []
    expected = snapshot()
    def complete(args: Namespace, pod: str, timeout: float) -> dict:
        calls.append((pod, timeout))
        return expected
    monkeypatch.setattr(backend, "gateway_http_snapshot", complete)
    assert backend.gateway_snapshot(Namespace(kubeconfig="private"), "owned", 3) is expected
    assert calls[0][0] == "owned" and 0 < calls[0][1] <= 3


@pytest.mark.parametrize("body,exit_message,error", [
    ('{"configs":[]}', '', None),
    ('{"configs":[', '', backend.GatewayObservationUnavailable),
    ('{"unrelated":true}', '', ValueError),
    ('x' * (8 * 1024 * 1024 + 1), '', ValueError),
    ('', 'Forbidden', RuntimeError),
])
def test_http_snapshot_is_bounded_owned_loopback_and_always_closes_tunnel(
    monkeypatch: pytest.MonkeyPatch, body: str, exit_message: str, error: type | None
) -> None:
    from contextlib import contextmanager
    from io import BytesIO
    events = []
    class Process:
        def __init__(self, command: list[str], stdout: object, stderr: object) -> None:
            assert command[-4:] == ['port-forward', 'pod/owned', ':15000', '--address=127.0.0.1']
            stdout.write(exit_message or 'Forwarding from 127.0.0.1:43210 -> 15000')
            stdout.flush()
        def poll(self) -> None:
            return None
        def terminate(self) -> None:
            events.append('terminate')
        def wait(self, timeout: float) -> None:
            events.append('wait')
    @contextmanager
    def response(*args: object, **kw: object) -> object:
        assert args[0] == 'http://127.0.0.1:43210/config_dump' and 0 < kw['timeout'] <= 3
        yield BytesIO(body.encode())
    monkeypatch.setattr(backend.subprocess, 'Popen', Process)
    monkeypatch.setattr(backend, 'build_opener', lambda *a: SimpleNamespace(open=response))
    if error:
        with pytest.raises(error):
            backend.gateway_http_snapshot(Namespace(kubeconfig='private'), 'owned', 3)
    else:
        assert backend.gateway_http_snapshot(Namespace(kubeconfig='private'), 'owned', 3) == {'configs': []}
    assert events == ['terminate', 'wait']
