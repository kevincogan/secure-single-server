# SPDX-License-Identifier: Apache-2.0
"""Guard native concurrency orchestration; live identity evidence is separate."""

from types import SimpleNamespace

import pytest

import native_parallel


def context() -> object:
    """Return an already validated context-shaped fixture for process tests."""
    return SimpleNamespace(namespace="demo-triage", workspace="demo-triage",
                           role="triage", sandbox_name="demo-s56-triage-k")


@pytest.mark.parametrize("size", [0, 1, 5])
def test_bounded_parallel_jobs(size: int) -> None:
    """An unbounded or accidental sequential batch cannot count as concurrency."""
    with pytest.raises(ValueError):
        native_parallel.parallel_exec("cli", {}, [(context(), "pass")] * size, lambda *a: None)


def test_parallel_requires_owned_namespace() -> None:
    """A valid-looking sandbox name cannot select another namespace."""
    wrong = context()
    wrong.workspace = wrong.namespace = "someone-else"
    with pytest.raises(ValueError):
        native_parallel.parallel_exec("cli", {}, [(wrong, "pass"), (context(), "pass")], lambda *a: None)


def test_launches_once_and_keeps_private_results(monkeypatch) -> None:
    """Do not retry an operation with a potentially uncertain mutation outcome."""
    calls, records = [], []

    def run(words: list, **kwargs: object) -> object:
        calls.append(words)
        return SimpleNamespace(returncode=0, stdout='{"read_passed":true,"events":[]}\n', stderr="")

    monkeypatch.setattr(native_parallel.subprocess, "run", run)
    values = native_parallel.parallel_exec("cli", {}, [(context(), "pass")] * 2,
                                          lambda i, v: records.append((i, v)))
    assert len(calls) == len(records) == len(values) == 2
    assert all(v["read_passed"] for v in values)
    assert all(words[1:5] == ["--gateway", "identity-demo-runtime", "--workspace", "demo-triage"]
               for words in calls)


def test_process_failure_is_not_retried(monkeypatch) -> None:
    """Both jobs terminate before reporting a failed batch."""
    calls = []

    def run(words: list, **kwargs: object) -> object:
        calls.append(words)
        return SimpleNamespace(returncode=1, stdout="", stderr="private diagnostic")

    monkeypatch.setattr(native_parallel.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="details withheld"):
        native_parallel.parallel_exec("cli", {}, [(context(), "pass")] * 2, lambda *a: None)
    assert len(calls) == 2
