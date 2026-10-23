# SPDX-License-Identifier: Apache-2.0
"""Require actual overlapping HTTP requests in native concurrency evidence."""

import pytest

from concurrency_flow import ConcurrencyFlow, overlapping, timed_program
from types import SimpleNamespace


@pytest.mark.parametrize("intervals,expected", [
    ([(1, 4), (2, 5), (3, 6)], True),
    ([(1, 2), (2, 3)], False),
    ([(1, 2), (3, 4)], False),
])
def test_requires_real_request_overlap(intervals: list, expected: bool) -> None:
    """Concurrent process launch alone does not establish concurrent enforcement."""
    values = [{"events": [{"method": "tools/call", "sent_at": start,
                           "received_at": end}]} for start, end in intervals]
    assert overlapping(values) is expected


def test_missing_tool_observation_cannot_pass() -> None:
    """Successful discovery alone cannot count as concurrency acceptance."""
    assert not overlapping([{"events": [{"method": "initialize"}]}, {"events": []}])


def test_timing_preserves_credential_free_native_client() -> None:
    """Only timing instrumentation changes; native protocol and credential checks stay."""
    program = timed_program("https://fixture.example/mcp", "readJiraProject", {}, "project_scope", 123)
    compile(program, "<timed-native-probe>", "exec")
    assert "sent_at = time.time()" in program and '"received_at":time.time()' in program
    assert "if method == 'tools/call': time.sleep" in program
    assert 'not any(k.lower() == "subject_token" for k in os.environ)' in program


def test_profile_provider_and_attachment_share_peer_workspace(tmp_path, monkeypatch) -> None:
    """A reader provider must not accidentally be created in the primary triage workspace."""
    flow = object.__new__(ConcurrencyFlow)
    reader = SimpleNamespace(provider_prefix="demo-s56-reader-d-exchange",
                             sandbox_name="demo-s56-reader-d", namespace="demo-reader")
    peer = SimpleNamespace(args=SimpleNamespace(label="reader"))
    flow.args = SimpleNamespace(output_dir=tmp_path)
    flow.peers = [(peer, reader, {"access_token": "private-fixture-token"})]
    flow.runtime_records = []
    flow.runtime_profile = {"id": "primary", "credentials": []}
    created = False
    calls = []

    def execute(words: list, **kwargs: object) -> object:
        nonlocal created
        assert kwargs["execution_context"] is reader
        calls.append(words[:3])
        if words[:3] == ["provider", "profile", "list"]:
            return {"profiles": []}
        if words[:2] == ["provider", "list"]:
            return {"providers": [{"name": reader.provider_prefix, "type": reader.provider_prefix,
                                    "id": "recorded-id"}] if created else []}
        if words[:2] == ["provider", "create"]:
            created = True
        return {}

    monkeypatch.setattr("concurrency_flow.components.verify", lambda *args, **kwargs: {"exp": 1000})
    flow.attach_peers(execute)
    assert flow.runtime_records[0]["provider_id"] == "recorded-id"
    assert flow.runtime_records[0]["attached"]
    assert ["sandbox", "provider", "attach"] in calls


@pytest.mark.parametrize("replaced", [False, True])
def test_cleanup_rechecks_id_before_idempotent_detach_retry(replaced: bool) -> None:
    """A revision race may be retried; a replaced provider must never be deleted."""
    flow = object.__new__(ConcurrencyFlow)
    reader = SimpleNamespace(sandbox_name="demo-s56-reader-d")
    flow.peers, flow.run_id = [], ""
    flow.runtime_records = [{"context": reader, "prefix": "recorded-profile", "attached": True,
                             "provider": True, "profile": True, "provider_id": "recorded-id"}]
    attached, attempts, deleted = True, 0, []

    def execute(words: list, **kwargs: object) -> dict:
        nonlocal attached, attempts
        assert kwargs["execution_context"] is reader
        if words[:3] == ["sandbox", "provider", "list"]:
            return {"providers": [{"name": "recorded-profile"}] if attached else []}
        if words[:2] == ["provider", "list"]:
            return {"providers": [{"name": "recorded-profile", "type": "recorded-profile",
                                   "id": "replaced-id" if replaced else "recorded-id"}]}
        if words[:3] == ["sandbox", "provider", "detach"]:
            attempts += 1
            if attempts == 1:
                raise RuntimeError("revision race")
            attached = False
        else:
            deleted.append(words)
        return {}

    flow.execute = execute
    if replaced:
        with pytest.raises(ValueError, match="cleanup ID mismatch"):
            flow.close()
        assert not deleted and attempts == 0
    else:
        flow.close()
        assert attempts == 2 and len(deleted) == 2
        assert not any(flow.runtime_records[0][field] for field in ("attached", "provider", "profile"))
