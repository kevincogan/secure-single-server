#!/usr/bin/env python3
"""Prove policy parsing precedes an unreachable gateway using schema controls."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def validate_profiles(invoke, results):
    """Share identical controls between the native and container CLI runners."""
    with tempfile.TemporaryDirectory() as directory:
        policy = Path(directory) / 'policy.yaml'

        def validate(text):
            policy.write_text(text)
            policy.chmod(0o644)
            completed = invoke(policy)
            assert completed.returncode, 'unavailable gateway unexpectedly accepted a policy update'
            return completed.stdout + completed.stderr

        def accepted(output):
            return 'Connection refused' in output and 'transport error' in output

        source = ROOT / 'configs/openshell-praxis/profiles/review/policy.yaml'
        numeric = (source.read_text()
                   .replace('@@PRAXIS_PORT@@', '18080')
                   .replace('@@PRAXIS_API_PREFIX@@', '')
                   .replace('port: "18080"', 'port: 18080'))
        invalid = numeric.replace('port: 18080', 'port: "18080"')
        assert invalid != numeric, 'invalid-port control did not change the policy'
        output = validate(invalid)
        assert 'expected unsigned integer' in output, f'invalid-port control did not reach policy schema: {output[-1000:]}'
        output = validate(numeric)
        assert accepted(output), f'numeric-port control failed before gateway connection: {output[-1000:]}'
        policies = sorted((ROOT / 'openshell/harnesses').glob('*/profiles/*/policy.yaml'))
        policies += sorted((ROOT / 'configs/openshell-praxis/profiles').glob('*/policy.yaml'))
        policies += sorted((ROOT / 'configs/vllm/harness/profiles').glob('*/policy.yaml'))
        policies += sorted((ROOT / 'configs/openshell-praxis/openclaw/profiles').glob('*/policy.yaml'))
        policies += sorted((ROOT / 'configs/vllm/openclaw/profiles').glob('*/policy.yaml'))
        policies += sorted((ROOT / 'configs/llm-d-sc/profiles').glob('*/policy.yaml'))
        assert len(policies) == 23, f'expected all 23 policies, found {len(policies)}'
        for source in policies:
            output = validate(source.read_text()
                              .replace('@@PRAXIS_PORT@@', '18080')
                              .replace('@@PRAXIS_API_PREFIX@@', ''))
            passed = accepted(output)
            results.append({'path': str(source.relative_to(ROOT)), 'status': 'passed' if passed else 'failed',
                            'diagnostic': 'schema accepted; gateway deliberately unreachable' if passed else output[-1000:]})
            print(f"{'PASS' if passed else 'FAIL'} schema: {source.relative_to(ROOT)}")
        assert all(item['status'] == 'passed' for item in results), 'one or more policies failed schema validation'


def main():
    cli = os.environ.get('OPENSHELL_BIN', '/usr/local/bin/openshell')

    def invoke(policy):
        # sandbox create contacts the gateway BEFORE parsing a policy. policy
        # set parses first; the invalid-port control proves this on the pinned CLI.
        return subprocess.run([cli, 'policy', 'set', 'schema-only', '--policy', str(policy),
                               '--gateway-endpoint', 'http://127.0.0.1:9'],
                              capture_output=True, text=True, timeout=20)

    validate_profiles(invoke, [])


if __name__ == '__main__':
    if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
        raise SystemExit('Run tests without Python -O/PYTHONOPTIMIZE')
    main()
