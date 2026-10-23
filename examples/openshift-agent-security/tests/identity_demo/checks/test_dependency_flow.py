# SPDX-License-Identifier: Apache-2.0
"""Guard outage simulation against other owners, drift and lost API responses."""

from copy import deepcopy
from urllib.parse import parse_qs

import pytest

import dependency_flow
from dependency_flow import IsolatedService
import probe_native_exchange as native


class Services:
    """Model exact API preconditions without modifying live infrastructure."""

    def __init__(self) -> None:
        self.value = {"metadata": {"uid": "service-uid", "resourceVersion": "1",
            "namespace": native.NAMESPACE, "labels": dict(native.LABELS)},
            "spec": {"selector": {"app": "fixture-identity-driver"}, "ports": [{"port": 8443}]}}
        self.mutations = 0
        self.lose_response = False

    def read(self, name: str) -> dict:
        """Return a snapshot, not a reference into shared test state."""
        assert name == "fixture-identity-driver"
        return deepcopy(self.value)

    def patch(self, name: str, operations: list) -> dict:
        """Assert all UID/version/spec preconditions before the selector change."""
        assert operations[0]["value"] == self.value["metadata"]["uid"]
        assert operations[1]["value"] == self.value["metadata"]["resourceVersion"]
        assert operations[2]["value"] == self.value["spec"]
        assert operations[3]["path"] == "/spec/selector"
        self.value["spec"]["selector"] = deepcopy(operations[3]["value"])
        self.mutations += 1
        self.value["metadata"]["resourceVersion"] = str(self.mutations + 1)
        if self.lose_response:
            self.lose_response = False
            raise TimeoutError("lost mutation response")
        return self.read(name)


def test_outage_restored_when_body_fails() -> None:
    """A failed assertion must propagate after restoring the original selector."""
    api = Services()
    before = deepcopy(api.value["spec"])
    with pytest.raises(AssertionError):
        with IsolatedService(api.read, api.patch, "fixture-identity-driver").unavailable():
            assert "identity-demo-unavailable-probe" in api.value["spec"]["selector"]
            raise AssertionError("probe failed")
    assert api.value["spec"] == before and api.mutations == 2


def test_lost_patch_response_restored_without_retrying_outage() -> None:
    """Observe authoritative state, restore exactly once and retain the failure."""
    api = Services()
    before = deepcopy(api.value["spec"])
    api.lose_response = True
    with pytest.raises(TimeoutError):
        with IsolatedService(api.read, api.patch, "fixture-identity-driver").unavailable():
            pytest.fail("must not proceed after unknown API response")
    assert api.value["spec"] == before and api.mutations == 2


def test_failed_probe_waits_for_original_endpoints_before_cleanup() -> None:
    """Restoring the Service spec alone does not prove endpoint readiness."""
    api = Services()
    before = deepcopy(api.value["spec"])
    waits = []

    def ready() -> None:
        assert api.value["spec"] == before
        waits.append(True)

    with pytest.raises(AssertionError):
        with IsolatedService(api.read, api.patch, "fixture-identity-driver", ready).unavailable():
            raise AssertionError("probe failed")
    assert waits == [True]


def test_independent_service_change_not_overwritten() -> None:
    """An unrelated edit must not be overwritten by restoration."""
    api = Services()
    with pytest.raises(ValueError, match="changed independently"):
        with IsolatedService(api.read, api.patch, "fixture-identity-driver").unavailable():
            api.value["spec"]["ports"] = [{"port": 9443}]
    assert api.mutations == 1 and api.value["spec"]["ports"] == [{"port": 9443}]


@pytest.mark.parametrize("field", ["namespace", "labels"])
def test_nonowned_service_denied(field: str) -> None:
    """No namespace or owner mismatch may reach a mutation."""
    api = Services()
    api.value["metadata"][field] = "other" if field == "namespace" else {}
    with pytest.raises(ValueError, match="owned"):
        IsolatedService(api.read, api.patch, "fixture-identity-driver")
    assert api.mutations == 0


def test_service_outside_exact_dependency_list_denied() -> None:
    """Even a caller-supplied name cannot select an arbitrary cluster Service."""
    with pytest.raises(ValueError, match="Exact owned dependency"):
        IsolatedService(lambda _: {}, lambda *_: {}, "another-service")


def test_service_grant_does_not_use_browser_origin(monkeypatch: object) -> None:
    """Keep confidential grants separate from browser requests and their CORS origin."""
    class Reply:
        """Return only a synthetic successful response."""
        status = 200

        def __enter__(self) -> object:
            """Match urllib's response object."""
            return self

        def __exit__(self, *args: object) -> None:
            """Keep the synthetic response cleanup inert."""
            return None

        def read(self, limit: int) -> bytes:
            """Require a finite response bound."""
            assert limit == 65_537
            return b'{"access_token":"synthetic-only"}'

    class Opener:
        """Inspect transport semantics without logging credential bodies."""
        def open(self, request: object, timeout: float) -> object:
            assert timeout == 8 and "Origin" not in request.headers
            assert request.full_url == dependency_flow.BASE + "/realms/identity-demo/protocol/openid-connect/token"
            assert parse_qs(request.data.decode())["client_secret"] == ["synthetic-secret"]
            return Reply()

    monkeypatch.setattr(dependency_flow, "build_opener", lambda *handlers: Opener())
    assert dependency_flow.service_grant("synthetic-secret")[0] == 200


@pytest.mark.parametrize("value", [{}, {"items": None}, {"items": []},
    {"items": [{"endpoints": None}]}, {"items": [{"endpoints": []}]},
    {"items": [{"endpoints": [{"addresses": ["10.0.0.1"], "conditions": {"ready": False}}]}]}])
def test_empty_or_unready_endpoints(value: dict) -> None:
    """Empty/transitioning endpoint slices must not crash outage observation."""
    assert not dependency_flow.ready_endpoints(value)


def test_actual_ready_endpoint_detected() -> None:
    """Only a ready backend counts toward restoration."""
    assert dependency_flow.ready_endpoints({"items": [{"endpoints": [
        {"addresses": ["10.0.0.1"], "conditions": {"ready": True}}]}]})
