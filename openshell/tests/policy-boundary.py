#!/usr/bin/env python3
"""Prove shipped OpenShell policies remain within reviewed access boundaries.

Containment is proven in two layers. The pinned prover checks every authority
shape its initial model can express. The one extension the runtime needs that
the prover refuses by design — allow_encoded_slash, required for npm scoped
packages — is contained structurally: it may appear only on enforced,
rule-less, read-only rest endpoints, and only where the reviewed boundary
carries it too. Anything else fails closed, inside the prover or here.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[2]
FAMILIES = {
    "codex": (ROOT / "openshell/harnesses/codex/profiles", "codex.yaml"),
    "openclaw": (ROOT / "openshell/harnesses/openclaw/profiles", "openclaw.yaml"),
    "opencode": (ROOT / "openshell/harnesses/opencode/profiles", "opencode.yaml"),
    "openclaw-praxis": (ROOT / "configs/openshell-praxis/openclaw/profiles", "openclaw-praxis.yaml"),
    "openclaw-vllm": (ROOT / "configs/vllm/openclaw/profiles", "openclaw-vllm.yaml"),
    "openshell-praxis": (ROOT / "configs/openshell-praxis/profiles", "openshell-praxis.yaml"),
    "vllm-harness": (ROOT / "configs/vllm/harness/profiles", "vllm-harness.yaml"),
    "llm-d-sc": (ROOT / "configs/llm-d-sc/profiles", "openshell-praxis.yaml"),
}
REQUIRED_COVERAGE = {
    "filesystem",
    "network_l4",
    "network_rest",
    "process",
    "landlock",
}
# The prover's initial model refuses endpoint extensions outright (upstream
# crates/openshell-prover/src/containment.rs, validate_supported_endpoint_extensions):
# allow_encoded_slash, tls, the credential rewrites, and allow_uninspected_credentials.
# The runtime needs allow_encoded_slash on the npm registry — scoped packages
# request /@scope%2Fname paths — so this check strips that single extension and
# contains it structurally instead. Any other extension still fails closed
# inside the prover; extend this tuple only after proving containment for the
# new extension's runtime semantics.
PROVER_OPAQUE_EXTENSIONS = ("allow_encoded_slash",)


def discover_policies():
    policies = set(ROOT.glob("openshell/harnesses/*/profiles/*/policy.yaml"))
    policies.update(ROOT.glob("configs/**/profiles/**/policy.yaml"))
    return sorted(policies)


def boundary_for(policy):
    for family, (directory, boundary_name) in FAMILIES.items():
        try:
            policy.relative_to(directory)
        except ValueError:
            continue
        return family, boundary_name
    raise AssertionError(f"shipped policy has no boundary family: {policy.relative_to(ROOT)}")


def render_policy(source, target):
    target.write_text(source.read_text()
                      .replace("@@PRAXIS_PORT@@", "18080")
                      .replace("@@PRAXIS_API_PREFIX@@", ""))


def run_prover(prover, candidate, boundary):
    completed = subprocess.run(
        [prover, "check", str(candidate), "--boundary", str(boundary),
         "--output", "json", "--timeout", "30s"],
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"policy prover did not return JSON: {completed.stdout} {completed.stderr}"
        ) from error
    return completed.returncode, result


def assert_coverage(result, context):
    domains = set(result.get("coverage", {}).get("domains", []))
    missing = REQUIRED_COVERAGE - domains
    assert not missing, f"{context} has incomplete prover coverage: missing {sorted(missing)}"
    print(f"PASS boundary: {context} (coverage: domains={','.join(sorted(domains))})")


def collect_opaque_endpoints(policy, context):
    """Map (host, port) to rule name for endpoints carrying a prover-opaque extension.

    The extension only relaxes request-path parsing (it accepts %2F), so on an
    enforced, rule-less, read-only rest endpoint it cannot widen authority:
    every parsed request is still bounded by the read-only access preset on
    the same host, port, and binaries. Enforce exactly that shape and fail
    closed on anything the extension could interact with.
    """
    opaque = {}
    for name, rule in (policy.get("network_policies") or {}).items():
        for endpoint in rule.get("endpoints", []):
            if not any(endpoint.get(extension) for extension in PROVER_OPAQUE_EXTENSIONS):
                continue
            assert endpoint.get("protocol") == "rest", (
                f"{context} rule '{name}' carries a prover-opaque extension "
                "outside a rest endpoint"
            )
            assert endpoint.get("enforcement") == "enforce", (
                f"{context} rule '{name}' carries a prover-opaque extension "
                "without enforcement"
            )
            assert endpoint.get("access") == "read-only", (
                f"{context} rule '{name}' carries a prover-opaque extension "
                "beyond read-only access"
            )
            assert "rules" not in endpoint and "deny_rules" not in endpoint, (
                f"{context} rule '{name}' carries a prover-opaque extension on "
                "an endpoint with path rules, where it could bypass "
                "path-level authority"
            )
            opaque[(endpoint["host"], endpoint["port"])] = name
    return opaque


def assert_opaque_containment(candidate_opaque, boundary_opaque, context):
    exceeded = set(candidate_opaque) - set(boundary_opaque)
    assert not exceeded, (
        f"{context} grants prover-opaque endpoint extensions beyond the "
        f"boundary: {sorted(exceeded)}"
    )


def strip_opaque_extensions(policy):
    for rule in (policy.get("network_policies") or {}).values():
        for endpoint in rule.get("endpoints", []):
            for extension in PROVER_OPAQUE_EXTENSIONS:
                endpoint.pop(extension, None)
    return policy


def check_mutated_policy(prover, boundary, directory):
    source = ROOT / "openshell/harnesses/opencode/profiles/review/policy.yaml"
    policy = yaml.safe_load(source.read_text().replace("@@PRAXIS_PORT@@", "18080"))
    policy["network_policies"]["model_api"]["endpoints"].append(
        {
            "host": "example.invalid",
            "port": 443,
            "protocol": "rest",
            "access": "read-only",
            "enforcement": "enforce",
        }
    )
    candidate = directory / "mutated-policy.yaml"
    candidate.write_text(yaml.safe_dump(policy, sort_keys=False))
    returncode, result = run_prover(prover, candidate, boundary)
    assert returncode != 0, "mutated policy unexpectedly passed the boundary check"
    assert result["result"] == "exceeds_boundary", result
    assert result["counterexample"]["host"] == "example.invalid", result
    assert_coverage(result, "mutation control")


def check_mutated_opaque_extension(prover, boundary, boundary_opaque, directory):
    """Prove the structural check catches an extension grant the solver cannot see."""
    source = ROOT / "openshell/harnesses/opencode/profiles/dev/policy.yaml"
    policy = yaml.safe_load(source.read_text().replace("@@PRAXIS_PORT@@", "18080"))
    policy["network_policies"]["github_api"]["endpoints"][0]["allow_encoded_slash"] = True
    candidate_opaque = collect_opaque_endpoints(policy, "extension mutation control")
    try:
        assert_opaque_containment(candidate_opaque, boundary_opaque, "extension mutation control")
    except AssertionError:
        pass
    else:
        raise AssertionError("extension mutation control unexpectedly allowed a rogue extension")
    candidate = directory / "mutated-extension-policy.yaml"
    candidate.write_text(yaml.safe_dump(strip_opaque_extensions(policy), sort_keys=False))
    returncode, result = run_prover(prover, candidate, boundary)
    assert returncode == 0 and result["result"] == "within_boundary", (
        "extension mutation control expected the stripped rogue policy to pass "
        f"the solver, showing the gap is real: {result}"
    )
    print("PASS extension mutation control: solver-blind extension rejected structurally")


def main():
    prover = os.environ.get("OPENSHELL_PROVER_BIN", "openshell-prover")
    policies = discover_policies()
    assert len(policies) == 23, f"expected 23 shipped policies, found {len(policies)}"
    with tempfile.TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        boundaries = {}
        for index, source in enumerate(policies):
            family, boundary_name = boundary_for(source)
            if boundary_name not in boundaries:
                rendered = directory / boundary_name
                render_policy(ROOT / "tests/policy-boundary" / boundary_name, rendered)
                boundary_data = yaml.safe_load(rendered.read_text())
                boundary_opaque = collect_opaque_endpoints(boundary_data, boundary_name)
                proven = directory / f"{boundary_name}.proven.yaml"
                proven.write_text(
                    yaml.safe_dump(strip_opaque_extensions(boundary_data), sort_keys=False))
                boundaries[boundary_name] = {"proven": proven, "opaque": boundary_opaque}
            boundary = boundaries[boundary_name]
            context = source.relative_to(ROOT)
            rendered = directory / f"{family}-{index}.yaml"
            render_policy(source, rendered)
            policy = yaml.safe_load(rendered.read_text())
            candidate_opaque = collect_opaque_endpoints(policy, context)
            assert_opaque_containment(candidate_opaque, boundary["opaque"], context)
            candidate = directory / f"{family}-{index}.proven.yaml"
            candidate.write_text(yaml.safe_dump(strip_opaque_extensions(policy), sort_keys=False))
            returncode, result = run_prover(prover, candidate, boundary["proven"])
            assert returncode == 0, f"{context} exceeds or cannot be checked: {result}"
            assert result["result"] == "within_boundary", result
            assert_coverage(result, context)
        check_mutated_policy(prover, boundaries["opencode.yaml"]["proven"], directory)
        check_mutated_opaque_extension(
            prover, boundaries["opencode.yaml"]["proven"],
            boundaries["opencode.yaml"]["opaque"], directory)
    print("openshell-policy-boundary: all shipped policies within boundaries OK")
    return 0


if __name__ == "__main__":
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise SystemExit("Run tests without Python -O/PYTHONOPTIMIZE")
    raise SystemExit(main())
