# SPDX-License-Identifier: Apache-2.0
"""Batched preflight remains read-only and refuses collisions or incomplete admission."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

import native_backend as backend


def resources():
    return [
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": n,
                "namespace": backend.shared.NS,
                "labels": dict(backend.shared.LABELS),
            },
            "stringData": {"fixture": "not-a-real-credential"},
        }
        for n in ["owned-a", "owned-b"]
    ]


def test_preflight_uses_only_one_inventory_and_one_server_dry_run(monkeypatch):
    calls = []
    values = resources()

    def kube(args, *words, payload, empty_output=None, collect_dry_run=False):
        calls.append(words)
        if words[0] == "get":
            assert all(
                set(v) == {"apiVersion", "kind", "metadata"} for v in payload["items"]
            )
            return {"kind": "List", "items": []}
        assert "--dry-run=server" in words
        return {"kind": "List", "items": deepcopy(values)}

    monkeypatch.setattr(backend.shared, "kube", kube)
    backend.preflight_resources(SimpleNamespace(), values)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "existing",
    [
        {},
        {"kind": "List", "items": None},
        {"kind": "List", "items": [{"kind": "Secret"}]},
    ],
)
def test_existing_or_unrecognized_inventory_prevents_admission(monkeypatch, existing):
    calls = []
    monkeypatch.setattr(
        backend.shared,
        "kube",
        lambda args, *words, **kw: calls.append(words) or existing,
    )
    with pytest.raises(ValueError):
        backend.preflight_resources(SimpleNamespace(), resources())
    assert len(calls) == 1 and calls[0][0] == "get"


@pytest.mark.parametrize("change", ["missing", "duplicate", "foreign", "unexpected"])
def test_admission_must_return_every_exact_owned_target(monkeypatch, change):
    admitted = resources()
    if change == "missing":
        admitted.pop()
    if change == "duplicate":
        admitted[1] = deepcopy(admitted[0])
    if change == "foreign":
        admitted[1]["metadata"]["namespace"] = "foreign"
    if change == "unexpected":
        admitted[1]["metadata"]["name"] = "unrequested"
    monkeypatch.setattr(
        backend.shared,
        "kube",
        lambda args, *w, **kw: {
            "kind": "List",
            "items": [] if w[0] == "get" else admitted,
        },
    )
    with pytest.raises(ValueError):
        backend.preflight_resources(SimpleNamespace(), resources())


@pytest.mark.parametrize(
    "stdout,expected", [("", {"kind": "List", "items": []}), ("{}", {})]
)
def test_only_successful_empty_cli_output_has_explicit_empty_inventory(
    monkeypatch, stdout, expected
):
    import subprocess

    monkeypatch.setattr(
        backend.shared.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, stdout, ""),
    )
    assert (
        backend.shared.kube(
            SimpleNamespace(kubeconfig="private"),
            "get",
            empty_output={"kind": "List", "items": []},
        )
        == expected
    )


def test_failed_inventory_cannot_be_interpreted_as_no_collisions(monkeypatch):
    import subprocess

    monkeypatch.setattr(
        backend.shared.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 1, "", "forbidden fixture"),
    )
    with pytest.raises(RuntimeError):
        backend.shared.kube(
            SimpleNamespace(kubeconfig="private"),
            "get",
            empty_output={"kind": "List", "items": []},
        )


def test_oc_multi_object_dry_run_keeps_all_admission_results(monkeypatch):
    import json
    import subprocess

    values = resources()
    monkeypatch.setattr(
        backend.shared.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            [], 0, "\n".join(json.dumps(v) for v in values), ""
        ),
    )
    result = backend.shared.kube(
        SimpleNamespace(kubeconfig="private"),
        "create",
        "--dry-run=server",
        collect_dry_run=True,
    )
    assert result["items"] == values


@pytest.mark.parametrize(
    "stdout", ["{}garbage", "{}[]", "not json", '{"kind":"List","items":null}']
)
def test_malformed_dry_run_output_is_not_silently_ignored(monkeypatch, stdout):
    import subprocess

    monkeypatch.setattr(
        backend.shared.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, stdout, ""),
    )
    with pytest.raises(ValueError):
        backend.shared.kube(
            SimpleNamespace(kubeconfig="private"),
            "create",
            "--dry-run=server",
            collect_dry_run=True,
        )


def test_output_collection_is_not_allowed_for_actual_mutations():
    with pytest.raises(ValueError, match="restricted"):
        backend.shared.kube(
            SimpleNamespace(kubeconfig="private"), "create", collect_dry_run=True
        )


def test_foreign_labels_are_refused_before_any_api_call(monkeypatch):
    values = resources()
    values[0]["metadata"]["labels"] = {"identity-demo-owner": "somebody-else"}
    monkeypatch.setattr(
        backend.shared,
        "kube",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not call")),
    )
    with pytest.raises(ValueError, match="Owned"):
        backend.preflight_resources(SimpleNamespace(), values)
