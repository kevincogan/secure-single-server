# SPDX-License-Identifier: Apache-2.0
"""The user service runs an immutable private source snapshot, not Documents."""

import os
import pytest
from pathlib import Path

from identity_demo_console_launchd import definition, stage_source_bundle


def test_launchd_source_bundle_is_private_and_outside_repository(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[3]
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    os.chmod(private_root, 0o700)
    environment = private_root / "operator.env"
    environment.write_text("export DEMO_PRIVATE_ROOT=/private/example\n")
    os.chmod(environment, 0o600)

    bundle, digest = stage_source_bundle(repository, private_root)
    launchd = definition(environment, private_root, bundle)

    assert len(digest) == 64
    assert bundle.is_relative_to(private_root)
    assert (bundle / "scripts/identity_demo/identity_demo_console_launch.sh").is_file()
    assert (bundle / "scripts/identity_demo/identity_demo_console_worker.py").is_file()
    assert (bundle / "tests/identity_demo/probe_native_exchange.py").is_file()
    for source in ("inference.py", "client.py"):
        relative = Path("workloads/agents/service-request-demo/src") / source
        assert (bundle / relative).read_bytes() == (repository / relative).read_bytes()
    assert not list(bundle.rglob("*.pyc"))
    assert all(path.stat().st_mode & 0o077 == 0 for path in bundle.rglob("*"))
    assert launchd["WorkingDirectory"] == str(bundle)
    assert launchd["ProgramArguments"][1].startswith(str(private_root))
    assert launchd["EnvironmentVariables"] == {"DEMO_OPERATOR_ENV_FILE": str(environment)}
    assert "/Users/" not in launchd["ProgramArguments"][1]


def test_service_start_requires_positive_loaded_state(monkeypatch, tmp_path: Path) -> None:
    """A successful enable/bootstrap alone must never be reported as a running service."""
    from types import SimpleNamespace
    import pytest
    import identity_demo_console_launchd as service
    calls = []
    observed = iter([1, 0])

    def launch(*words: str, **kwargs: object) -> object:
        calls.append(words)
        return SimpleNamespace(returncode=next(observed) if words[0] == 'print' else 0)

    monkeypatch.setattr(service, 'launchctl', launch)
    service.ensure_started(tmp_path / 'owned.plist')
    assert [words[0] for words in calls] == ['enable', 'print', 'bootstrap', 'kickstart', 'print']
    observed = iter([1, 1])
    with pytest.raises(RuntimeError, match='not loaded'):
        service.ensure_started(tmp_path / 'owned.plist')
    assert all('-k' not in words for words in calls)


def test_uninstall_waits_for_old_registration_before_replacement(monkeypatch) -> None:
    from types import SimpleNamespace
    import identity_demo_console_launchd as service
    observed = iter([0, 0, 1])
    pauses = []
    monkeypatch.setattr(service, 'launchctl', lambda *a, **kw: SimpleNamespace(returncode=next(observed)))
    monkeypatch.setattr(service.time, 'sleep', lambda value: pauses.append(value))
    service.wait_unloaded()
    assert pauses == [.2, .2]


@pytest.mark.parametrize("mode", ["coordinator", "preparer"])
@pytest.mark.parametrize("login", [False, True])
def test_launcher_system_bash_optional_login(tmp_path: Path, mode: str, login: bool) -> None:
    """Run the real launcher with system Bash, including macOS Bash 3/no login file."""
    import json
    import shlex
    import shutil
    import subprocess
    import sys
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    scripts = root / "scripts/identity_demo"
    scripts.mkdir(parents=True)
    launcher = scripts / "identity_demo_console_launch.sh"
    shutil.copyfile(Path(__file__).resolve().parents[3] / "scripts/identity_demo/identity_demo_console_launch.sh", launcher)
    for name in ("identity_demo_console_worker.py", "identity_demo_console_preparer.py"):
        (scripts / name).write_text("# stub: no workload or credentials\n")
    capture = root / "arguments.json"
    python = root / "python-stub"
    python.write_text("#!" + sys.executable + "\nimport json,sys\nfrom pathlib import Path\nif sys.argv[1] == '-c': print('unique-launch')\nelse: Path(" + repr(str(capture)) + ").write_text(json.dumps(sys.argv[1:]))\n")
    python.chmod(0o700)
    values = {name: str(root / name.lower()) for name in (
        'DEMO_KUBECONFIG', 'DEMO_SERVER', 'DEMO_FIXTURE_CREDENTIALS', 'DEMO_OPENSHELL_CLI',
        'DEMO_CLI_CONFIG', 'DEMO_DRIVER_CREDENTIALS', 'DEMO_CATALOG_CREDENTIAL', 'DEMO_INFERENCE_CONFIG')}
    values.update(DEMO_PYTHON=str(python), DEMO_PRIVATE_ROOT=str(root), DEMO_SERVICE_MODE=mode)
    login_file = str(root / 'private login input.json')
    if login:
        values['DEMO_OPERATOR_LOGIN_FILE'] = login_file
    environment = root / 'operator.env'
    environment.write_text(''.join('export ' + k + '=' + shlex.quote(v) + '\n' for k, v in values.items()))
    environment.chmod(0o600)
    result = subprocess.run(['/bin/bash', str(launcher)], env={**os.environ,
        'DEMO_OPERATOR_ENV_FILE': str(environment), 'DEMO_OPERATOR_LOGIN_FILE': ''},
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    args = json.loads(capture.read_text())
    assert args[0].endswith('identity_demo_console_' + ('worker' if mode == 'coordinator' else 'preparer') + '.py')
    assert ('--operator-login-file' in args) is login
    if login:
        assert args[args.index('--operator-login-file') + 1] == login_file
    assert '--output-dir' in args
