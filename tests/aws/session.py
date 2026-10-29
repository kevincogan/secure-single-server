#!/usr/bin/env python3
"""Exercise the copy/paste AWS workflow in Bash and zsh, without AWS access."""
import errno
import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHELLS = [path for name in ("bash", "zsh") if (path := shutil.which(name))]
SETUP = """
source scripts/aws/session.sh || { printf 'SOURCE_FAILED\\n'; return 1; }
REGION=eu-central-1 ARCH=amd64 SUBNET='' CLIENT_CIDR='' RUN_PREFIX=gateway-test
SSH_KEY=/test-private-location/key
AWS_TEST_CREDENTIALS=ready
AWS_ACCESS_KEY_ID=synthetic-access AWS_SECRET_ACCESS_KEY=synthetic-secret
aws() {
  case "$*" in
    *'get-caller-identity'*)
      [ "$MODE" != denied ] || return 23
      printf '%s\\n' '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test"}' ;;
    *'describe-subnets'*)
      if [ "$MODE" = empty ]; then
        printf '%s\\n' '{"Subnets":[]}'
      else
        printf '%s\\n' '{"Subnets":[{"SubnetId":"subnet-b","AvailabilityZone":"zone-b","AvailableIpAddressCount":4},{"SubnetId":"subnet-full","AvailabilityZone":"zone-a","AvailableIpAddressCount":0},{"SubnetId":"subnet-a","AvailabilityZone":"zone-a","AvailableIpAddressCount":2}]}'
      fi ;;
    *) printf 'UNEXPECTED_AWS_CALL\\n'; return 99 ;;
  esac
}
curl() {
  [ "$MODE" != network_error ] || return 22
  if [ "$MODE" = invalid_ip ]; then printf 'invalid\\n'; else printf '192.0.2.7\\n'; fi
}
_aws_test_vm() {
  printf 'VM_CALL:%s\\nVM_ARGS:%s\\n' "$1" "$*" >&2
  if [ "$MODE" = first_failed ]; then return 1; fi
  if [ "$1" = verify ]; then
    if [ "$MODE" = no_ip ]; then
      printf '%s\\n' '{"State":"pending","PublicIpAddress":null}'
    elif [ "$MODE" = missing_metadata ]; then
      printf '%s\\n' '{"State":"running","PublicIpAddress":"192.0.2.8"}'
    else
      printf '%s\\n' '{"State":"running","PublicIpAddress":"192.0.2.8","VpcId":"vpc-test","Scenario":"remote-gateway","Inference":"cpu"}'
    fi
  fi
}
"""


def environment():
    return {**{key: value for key, value in os.environ.items()
               if not key.startswith("AWS_") and key not in ("BASH_ENV", "ENV")},
            "HISTFILE": "/dev/null"}


def shell_args(shell):
    return [shell, "--noprofile", "--norc"] if Path(shell).name == "bash" else [shell, "-f"]


class SessionTest(unittest.TestCase):
    def run_shell(self, shell, script):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            key.write_text("synthetic-private-key")
            key.with_suffix(".pub").write_text("ssh-ed25519 synthetic-public-key")
            script = script.replace("/test-private-location/key", shlex.quote(str(key)))
            result = subprocess.run(shell_args(shell) + ["-c", script], cwd=ROOT,
                                    env=environment(), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHELL_ALIVE", result.stdout)
        self.assertNotIn("UNEXPECTED_AWS_CALL", result.stdout)
        return result.stdout + result.stderr

    def test_missing_public_key_reports_recovery_before_planning(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
SSH_KEY="$SSH_KEY-missing"
if aws_test_plan all-in-one configs/aws/vllm-gpu.json --scenario all-in-one; then printf 'UNEXPECTED_SUCCESS\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertNotIn("UNEXPECTED_", output)
            self.assertIn("aws_test_key", output)

    def test_capacity_is_read_only_and_needs_no_launch_key_or_journal(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a
unset SSH_KEY
if aws_test_capacity g6.2xlarge; then printf 'CAPACITY_OK\\n'; fi
if aws_test_capacity; then printf 'UNEXPECTED_SUCCESS\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertIn("CAPACITY_OK", output)
            self.assertEqual(output.count("VM_CALL:capacity"), 1)
            self.assertIn("--instance-type g6.2xlarge --subnet-id subnet-a", output)
            self.assertNotIn("--state-file", output)
            self.assertNotIn("UNEXPECTED_", output)

    def test_reload_replaces_batch_helpers_and_keeps_credentials_and_run(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
aws_test_plan() { printf 'OBSOLETE_BATCH_PLAN\\n'; }
aws_test_apply() { printf 'OBSOLETE_BATCH_APPLY\\n'; }
if source scripts/aws/session.sh; then printf 'RELOADED\\n'; fi
_aws_test_vm() { printf 'VM_CALL:%s\\nVM_ARGS:%s\\n' "$1" "$*"; }
if aws_test_apply; then printf 'UNEXPECTED_APPLY\\n'; fi
if aws_test_plan all-in-one configs/aws/vllm-gpu.json --scenario all-in-one && aws_test_plan remote-gateway configs/aws/no-vllm.json --scenario remote-gateway; then
  printf 'PLANS_OK\\n'
fi
if [ "$AWS_ACCESS_KEY_ID" = synthetic-access ] && [ "$AWS_SECRET_ACCESS_KEY" = synthetic-secret ] &&
   [ "$AWS_TEST_CREDENTIALS" = ready ] && [ "$RUN_PREFIX" = gateway-test ] &&
   [ "$AWS_TEST_READY" = ready ] && [ -r "$SSH_KEY.pub" ]; then printf 'PRESERVED\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("OBSOLETE_BATCH", output)
            self.assertNotIn("UNEXPECTED_", output)
            self.assertIn("PRESERVED", output)
            self.assertIn("PLANS_OK", output)
            self.assertEqual(output.count("VM_CALL:plan"), 2)
            self.assertIn("--prefix gateway-test-all-in-one", output)
            self.assertIn("--config configs/aws/vllm-gpu.json", output)

    def test_public_ssh_override_is_forwarded_to_one_vm_only(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
if aws_test_plan all-in-one configs/aws/vllm-gpu.json --scenario all-in-one --ssh-access public &&
   aws_test_plan remote-gateway configs/aws/no-vllm.json --scenario remote-gateway --allowed-cidr 192.0.2.9/32; then printf 'PLANS_OK\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertIn("PLANS_OK", output)
            self.assertEqual(output.count("--ssh-access public"), 1)
            self.assertEqual(output.count("--allowed-cidr 192.0.2.7/32"), 2)
            self.assertEqual(output.count("--allowed-cidr 192.0.2.9/32"), 1)

    def test_vm_role_is_independent_of_inference_config(self):
        for shell in SHELLS:
            for name, configs in (("all-in-one", ("no-vllm", "vllm-cpu", "vllm-gpu")),
                                  ("remote-gateway", ("no-vllm", "vllm-cpu", "vllm-gpu")),
                                  ("vllm-server", ("vllm-cpu", "vllm-gpu"))):
                for config in configs:
                    with self.subTest(shell=shell, name=name, config=config):
                        output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + f"""
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
if aws_test_plan {name} configs/aws/{config}.json --scenario {name}; then printf 'PLAN_OK\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
                        self.assertIn("PLAN_OK", output)
                        self.assertEqual(output.count("VM_CALL:plan"), 1)
                        self.assertIn("--scenario " + name, output)
                        self.assertIn("--prefix gateway-test-" + name, output)

    def test_vllm_helpers_target_one_client_and_one_server(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 AWS_TEST_CREDENTIALS=ready REGION=eu-central-1 RUN_PREFIX=gateway-test
if aws_test_vllm_grant all-in-one vllm-server; then printf 'GRANT_PLAN_OK\n'; fi
if aws_test_vllm_grant_apply all-in-one vllm-server; then printf 'GRANT_APPLY_OK\n'; fi
RHEL_VPC_ID=vpc-test
RHEL_SCENARIO=remote-gateway
RHEL_STATE_FILE="$AWS_TEST_REPO/.state/gateway-test-all-in-one.json"
if aws_test_vllm_endpoint vllm-server; then printf 'ENDPOINT_OK\n'; fi
printf 'SHELL_ALIVE\n'
""")
            self.assertIn("GRANT_PLAN_OK", output)
            self.assertIn("GRANT_APPLY_OK", output)
            self.assertIn("ENDPOINT_OK", output)
            self.assertEqual(output.count("VM_CALL:vllm-grant"), 2)
            self.assertEqual(output.count("--client-state-file"), 3)
            self.assertEqual(output.count("--vllm-state-file"), 2)
            self.assertEqual(output.count("--apply"), 1)
            self.assertEqual(output.count("VM_CALL:vllm-endpoint"), 1)
            self.assertIn("--vllm-prefix gateway-test-vllm-server", output)
            self.assertIn("--client-state-file " + str(ROOT) + "/.state/gateway-test-all-in-one.json", output)
            self.assertIn("--client-vpc-id vpc-test", output)

    def test_vllm_helpers_require_the_recorded_account(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
unset ACCOUNT
if aws_test_vllm_grant all-in-one vllm-server; then printf 'UNEXPECTED_GRANT\\n'; fi
if aws_test_vllm_endpoint vllm-server; then printf 'UNEXPECTED_ENDPOINT\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertIn("Discover or set the recorded account first.", output)

    def test_vllm_endpoint_requires_the_recorded_client_vpc(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 AWS_TEST_CREDENTIALS=ready REGION=eu-central-1 RUN_PREFIX=gateway-test
unset RHEL_VPC_ID
if aws_test_vllm_endpoint vllm-server; then printf 'UNEXPECTED_ENDPOINT\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertNotIn("UNEXPECTED_ENDPOINT", output)
            self.assertIn("Verify the single server first so vLLM endpoint discovery can check the VPC.", output)

    def test_vllm_endpoint_requires_the_recorded_client_journal(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 AWS_TEST_CREDENTIALS=ready REGION=eu-central-1 RUN_PREFIX=gateway-test
RHEL_VPC_ID=vpc-test RHEL_SCENARIO=remote-gateway
unset RHEL_STATE_FILE
if aws_test_vllm_endpoint vllm-server; then printf 'UNEXPECTED_ENDPOINT\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertNotIn("UNEXPECTED_ENDPOINT", output)
            self.assertIn("Verify the single server first so vLLM endpoint discovery can check the VPC.", output)

    def test_vllm_endpoint_rejects_a_verified_vllm_server_as_client(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 AWS_TEST_CREDENTIALS=ready REGION=eu-central-1 RUN_PREFIX=gateway-test
RHEL_VPC_ID=vpc-test RHEL_SCENARIO=vllm-server
RHEL_STATE_FILE="$AWS_TEST_REPO/.state/gateway-test-vllm-server.json"
if aws_test_vllm_endpoint vllm-server; then printf 'UNEXPECTED_ENDPOINT\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertNotIn("UNEXPECTED_ENDPOINT", output)
            self.assertIn("Verify the single server first so vLLM endpoint discovery can check the VPC.", output)

    def test_vllm_endpoint_rejects_an_unsupported_verified_scenario(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 AWS_TEST_CREDENTIALS=ready REGION=eu-central-1 RUN_PREFIX=gateway-test
RHEL_VPC_ID=vpc-test RHEL_SCENARIO=attacker
RHEL_STATE_FILE="$AWS_TEST_REPO/.state/gateway-test-all-in-one.json"
if aws_test_vllm_endpoint vllm-server; then printf 'UNEXPECTED_ENDPOINT\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertNotIn("UNEXPECTED_ENDPOINT", output)
            self.assertIn("Verify the single server first so vLLM endpoint discovery can check the VPC.", output)

    def test_vllm_helpers_reject_extra_arguments(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 AWS_TEST_CREDENTIALS=ready REGION=eu-central-1 RUN_PREFIX=gateway-test
if aws_test_vllm_grant all-in-one vllm-server extra; then printf 'UNEXPECTED_GRANT\\n'; fi
if aws_test_vllm_endpoint vllm-server extra; then printf 'UNEXPECTED_ENDPOINT\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("VM_CALL:", output)
            self.assertNotIn("UNEXPECTED_", output)

    def test_canonical_vm_names_cannot_be_given_another_role(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
if aws_test_plan all-in-one configs/aws/vllm-gpu.json --scenario remote-gateway; then
  printf 'UNEXPECTED_SUCCESS\\n'
fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertNotIn("UNEXPECTED_", output)
            self.assertNotIn("VM_CALL:", output)

    def test_each_command_targets_exactly_one_named_vm(self):
        for shell in SHELLS:
            for name, config, scenario in (("all-in-one", "vllm-gpu", "all-in-one"),
                    ("all-in-one-cpu", "vllm-cpu", "all-in-one"), ("remote-gateway", "no-vllm", "remote-gateway")):
                with self.subTest(shell=shell, name=name):
                    output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + f"""
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
if aws_test_plan {name} configs/aws/{config}.json --scenario {scenario} &&
   aws_test_deploy {name} configs/aws/{config}.json --scenario {scenario} && aws_test_verify {name}; then
  printf 'SELECTED_OK\\n'
fi
printf 'HOST:%s\\nSHELL_ALIVE\\n' "${{RHEL_HOST:-}}"
""")
                    self.assertIn("SELECTED_OK", output)
                    for action in ("plan", "apply", "verify"):
                        self.assertEqual(output.count("VM_CALL:" + action), 1)
                    self.assertIn("HOST:ec2-user@192.0.2.8\n", output)
                    self.assertEqual(output.count("--config configs/aws/" + config + ".json"), 2)
                    self.assertEqual(output.count("--state-file " + str(ROOT) + "/.state/gateway-test-" + name + ".json"), 3)

    def test_resource_overrides_are_per_call_and_same_scenario_can_repeat(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
# Legacy batch settings cannot silently launch another VM or override its type.
SCENARIOS=all-in-one,remote-gateway INSTANCE_TYPE=wrong-type ARCH=arm64
if aws_test_deploy first configs/aws/vllm-gpu.json --scenario all-in-one --instance-type g6.4xlarge --volume-gib 300 --subnet-id subnet-b &&
   aws_test_deploy second configs/aws/vllm-gpu.json --scenario all-in-one; then printf 'BOTH_OK\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertIn("BOTH_OK", output)
            self.assertEqual(output.count("VM_CALL:apply"), 2)
            self.assertIn("--instance-type g6.4xlarge --volume-gib 300 --subnet-id subnet-b", output)
            second = next(line for line in output.splitlines() if line.startswith("VM_ARGS:") and "gateway-test-second" in line)
            self.assertNotIn("g6.4xlarge", second)
            self.assertNotIn("wrong-type", output)
            self.assertNotIn("--arch arm64", output)
            self.assertIn("--subnet-id subnet-a", second)

    def test_missing_or_invalid_name_and_config_fail_without_cloud_calls(self):
        for shell in SHELLS:
            for arguments in ("", "../escape configs/aws/no-vllm.json", "-option configs/aws/no-vllm.json",
                              "'good\n../escape' configs/aws/no-vllm.json",
                              "two,names configs/aws/no-vllm.json", "good", "good absent-config.json",
                              "good configs/aws/no-vllm.json --state-file replacement.json",
                              "good configs/aws/no-vllm.json --volume-gib"):
                with self.subTest(shell=shell, arguments=arguments):
                    output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + f"""
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
if aws_test_deploy {arguments}; then printf 'UNEXPECTED_SUCCESS\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
                    self.assertNotIn("VM_CALL:", output)
                    self.assertNotIn("UNEXPECTED_", output)

    def test_discovery_failure_never_exits_shell_or_leaves_ready_state(self):
        for shell in SHELLS:
            for mode in ("normal", "empty", "denied", "invalid_ip", "network_error"):
                with self.subTest(shell=shell, mode=mode):
                    output = self.run_shell(shell, "set -eu\nMODE=" + mode + "\n" + SETUP + """
AWS_TEST_READY=stale RHEL_HOST=stale
if aws_test_discover; then printf 'DISCOVER_OK\\n'; else printf 'DISCOVER_FAILED\\n'; fi
printf 'READY:%s\\nHOST:%s\\nSHELL_ALIVE\\n' "${AWS_TEST_READY:-}" "${RHEL_HOST:-}"
""")
                    self.assertEqual("DISCOVER_OK" in output, mode == "normal")
                    self.assertIn("HOST:\n", output)
                    if mode == "normal":
                        self.assertIn("subnet-a", output)
                        self.assertIn("192.0.2.7/32", output)
                    else:
                        self.assertIn("READY:\n", output)

    def test_failed_deploy_never_attempts_another_vm(self):
        for shell in SHELLS:
            output = self.run_shell(shell, "set -eu\nMODE=first_failed\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
if aws_test_deploy all-in-one configs/aws/vllm-gpu.json --scenario all-in-one; then printf 'UNEXPECTED_APPLY\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
            self.assertEqual(output.count("VM_CALL:apply"), 1)
            self.assertNotIn("UNEXPECTED_", output)

    def test_verify_failure_clears_previous_login_address(self):
        for shell in SHELLS:
            for mode in ("normal", "no_ip", "first_failed", "missing_metadata"):
                with self.subTest(shell=shell, mode=mode):
                    output = self.run_shell(shell, "set -eu\nMODE=" + mode + "\n" + SETUP + """
ACCOUNT=123456789012 RHEL_HOST=stale RHEL_SCENARIO=stale RHEL_INFERENCE=stale
if aws_test_verify all-in-one; then printf 'VERIFY_OK\\n'; else printf 'VERIFY_FAILED\\n'; fi
printf 'HOST:%s\\nSCENARIO:%s\\nINFERENCE:%s\\nSHELL_ALIVE\\n' "${RHEL_HOST:-}" "${RHEL_SCENARIO:-}" "${RHEL_INFERENCE:-}"
""")
                    self.assertEqual("VERIFY_OK" in output, mode == "normal")
                    self.assertIn("HOST:ec2-user@192.0.2.8" if mode == "normal" else "HOST:\n", output)
                    self.assertIn("SCENARIO:remote-gateway\n" if mode == "normal" else "SCENARIO:\n", output)
                    self.assertIn("INFERENCE:cpu\n" if mode == "normal" else "INFERENCE:\n", output)

    def test_ssh_verifies_the_requested_vm_instead_of_using_a_stale_host(self):
        for shell in SHELLS:
            for mode in ("normal", "no_ip", "first_failed"):
                output = self.run_shell(shell, "set -eu\nMODE=" + mode + "\n" + SETUP + """
ACCOUNT=123456789012 RHEL_HOST=stale
ssh() { printf 'SSH_CALL:%s\\n' "$*"; }
if aws_test_ssh all-in-one; then printf 'SSH_OK\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
                self.assertEqual("SSH_CALL:" in output, mode == "normal")
                self.assertNotIn("stale", output)
                if mode == "normal":
                    self.assertIn("ForwardAgent=no", output)
                    self.assertIn("ec2-user@192.0.2.8", output)

    def test_key_generation_is_quiet_and_keeps_passphrase_prompt(self):
        for shell in SHELLS:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                key = Path(directory) / 'keys' / 'test-key'
                output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + f"""
SSH_KEY={shlex.quote(str(key))}
ssh-keygen() {{
  case " $* " in *' -q '*) ;; *) printf 'UNEXPECTED_RANDOMART\n';; esac
  case " $* " in *' -N '*) printf 'UNEXPECTED_PASSPHRASE_OVERRIDE\n';; esac
  touch "$SSH_KEY" "$SSH_KEY.pub"
}}
aws_test_key
printf 'SHELL_ALIVE\\n'
""")
                self.assertNotIn('UNEXPECTED_', output)
                self.assertIn(str(key), output)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_key_overwrite_and_missing_settings_do_not_exit_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "existing"
            key.write_text("preserve this file")
            for shell in SHELLS:
                with self.subTest(shell=shell):
                    output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + f"""
SSH_KEY='{key}'
ssh-keygen() {{ printf 'UNEXPECTED_KEYGEN\\n'; }}
if aws_test_key; then printf 'UNEXPECTED_SUCCESS\\n'; fi
unset SSH_KEY
if aws_test_key; then printf 'UNEXPECTED_SUCCESS\\n'; fi
if aws_test_ssh all-in-one; then printf 'UNEXPECTED_SUCCESS\\n'; fi
printf 'SHELL_ALIVE\\n'
""")
                    self.assertNotIn("UNEXPECTED_", output)
                    self.assertEqual(key.read_text(), "preserve this file")

    def test_credential_prompts_on_a_real_terminal(self):
        for shell in SHELLS:
            for answers, loaded in (
                (("dummy-access", "dummy-secret", ""), True),
                (("dummy-access", "dummy-secret", "dummy-session"), True),
                (("",), False),
                (("dummy-access", ""), False),
                (("\x04",), False),
                (("dummy-access", "dummy-secret", "\x04"), False),
            ):
                with self.subTest(shell=shell, answers=len(answers)):
                    code = """
set -eu
if source scripts/aws/session.sh; then
  if aws_test_credentials; then printf 'CREDENTIALS_OK\\n'; else printf 'CREDENTIALS_FAILED\\n'; fi
fi
printf 'LOADED:%s\\nKEY:%s\\nSHELL_ALIVE\\n' "${AWS_TEST_CREDENTIALS:-}" "${AWS_ACCESS_KEY_ID:+present}"
"""
                    child, master = pty.fork()
                    if child == 0:
                        os.chdir(ROOT)
                        os.execve(shell, shell_args(shell) + ["-i", "-c", code], environment())
                    child_finished = False
                    transcript = b""
                    prompts = (b"AWS access key ID: ", b"AWS secret access key: ", b"AWS session token")
                    next_answer = 0
                    deadline = time.monotonic() + 8
                    try:
                        while time.monotonic() < deadline:
                            if select.select([master], [], [], 0.1)[0]:
                                try:
                                    chunk = os.read(master, 8192)
                                except OSError as error:
                                    if error.errno == errno.EIO:
                                        break
                                    raise
                                if not chunk:
                                    break
                                transcript += chunk
                            if (next_answer < len(answers) and prompts[next_answer] in transcript
                                    and not termios.tcgetattr(master)[3] & termios.ECHO):
                                answer = answers[next_answer]
                                os.write(master, (answer if answer == "\x04" else answer + "\n").encode())
                                next_answer += 1
                        finished, result = os.waitpid(child, os.WNOHANG)
                        while finished == 0 and time.monotonic() < deadline:
                            time.sleep(0.01)
                            finished, result = os.waitpid(child, os.WNOHANG)
                        child_finished = finished == child
                        self.assertTrue(child_finished, transcript.decode(errors="replace"))
                    finally:
                        if not child_finished:
                            os.kill(child, 9)
                            os.waitpid(child, 0)
                        os.close(master)
                    text = transcript.decode(errors="replace")
                    self.assertEqual(os.waitstatus_to_exitcode(result), 0, text)
                    self.assertIn("SHELL_ALIVE", text)
                    self.assertNotIn("dummy-access", text)
                    self.assertNotIn("dummy-secret", text)
                    self.assertNotIn("dummy-session", text)
                    if loaded:
                        self.assertIn("CREDENTIALS_OK", text)
                        self.assertIn("KEY:present", text)
                    else:
                        self.assertIn("CREDENTIALS_FAILED", text)
                        self.assertIn("KEY:\r\n", text)

    def test_guide_has_no_terminal_exiting_blocks(self):
        document = (ROOT / "docs/testing/aws.md").read_text()
        blocks = re.findall(r"^```console\n(.*?)^```", document, re.M | re.S)
        for block in blocks:
            self.assertNotRegex(block, r"\bexit\b|\bexec\b|\$\{[^}]*:\?|set -[a-zA-Z]*[eu]|read[^\n]* -p")
            for shell in SHELLS:
                result = subprocess.run(shell_args(shell) + ["-n"], input=block,
                                        capture_output=True, text=True, env=environment())
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_copyable_vm_and_access_choices_keep_one_plan_and_deploy_per_vm(self):
        document = (ROOT / "docs/testing/aws.md").read_text()
        reference = (ROOT / "docs/testing/aws-operations.md").read_text()
        blocks = re.findall(r"^```console\n(.*?)^```", document, re.M | re.S)
        policies = re.findall(r"^```console\n(.*?)^```", reference, re.M | re.S)
        for role in ("all-in-one", "remote-gateway"):
            for inference in ("cpu", "gpu", "cloud"):
                name = role + "-" + inference
                variable = name.upper().replace("-", "_") + "_VM"
                access_variable = role.upper().replace("-", "_") + "_ACCESS"
                plan = next(block for block in blocks if block.startswith(variable + "=("))
                deploy = next(block for block in blocks if block.startswith("aws_test_deploy " + name + " "))
                access = [block for block in policies if block.startswith(access_variable + "=(")]
                self.assertTrue(access)
                for shell in SHELLS:
                    for policy in access:
                        with self.subTest(name=name, shell=shell, policy=policy.strip()):
                            output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + """
ACCOUNT=123456789012 SUBNET=subnet-a CLIENT_CIDR=192.0.2.7/32 AWS_TEST_READY=ready
""" + policy + plan + deploy + "printf 'SHELL_ALIVE\\n'")
                            calls = [shlex.split(line[len("VM_ARGS:"):]) for line in output.splitlines()
                                     if line.startswith("VM_ARGS:")]
                            self.assertEqual([call[0] for call in calls], ["plan", "apply"])
                            self.assertEqual(calls[0][1:], calls[1][1:])
                            self.assertEqual(calls[0][calls[0].index("--scenario") + 1], role)
                            self.assertEqual(calls[0][calls[0].index("--prefix") + 1], "gateway-test-" + name)
                            self.assertEqual(calls[0][calls[0].index("--config") + 1], ("configs/aws/no-vllm.json" if inference == "cloud" else "configs/aws/vllm-" + inference + ".json"))
                            self.assertNotIn("error:", output)

    def test_inventory_lists_only_deployed_vms_and_preserves_selection(self):
        document = (ROOT / "docs/testing/aws.md").read_text()
        inventory = next(block for block in re.findall(r"^```console\n(.*?)^```", document, re.M | re.S)
                         if block.startswith("(\n"))
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / ".state"
            state.mkdir()
            for name in ("all-in-one-cpu", "all-in-one-gpu"):
                (state / ("gateway-test-" + name + ".json")).write_text("{}")
            for shell in SHELLS:
                output = self.run_shell(shell, "set -eu\nMODE=normal\n" + SETUP + f"""
ACCOUNT=123456789012 AWS_TEST_REPO={shlex.quote(directory)}
RHEL_HOST=previous-login RHEL_SCENARIO=previous-role RHEL_INFERENCE=previous-backend
""" + inventory + """
printf 'SELECTED:%s/%s/%s\\nSHELL_ALIVE\\n' "$RHEL_HOST" "$RHEL_SCENARIO" "$RHEL_INFERENCE"
""")
                self.assertEqual(output.count("VM_CALL:verify"), 2)
                self.assertIn("all-in-one-cpu login:", output)
                self.assertIn("all-in-one-gpu login:", output)
                self.assertNotIn("remote-gateway", "\n".join(line for line in output.splitlines() if line.startswith("VM_ARGS:")))
                self.assertIn("SELECTED:previous-login/previous-role/previous-backend", output)
                self.assertNotIn("synthetic-secret", output)

    def test_copyable_blocks_keep_shell_open_with_failed_commands(self):
        document = (ROOT / "docs/testing/aws.md").read_text()
        blocks = re.findall(r"^```console\n(.*?)^```", document, re.M | re.S)
        for shell in SHELLS:
            for block in blocks:
                with self.subTest(shell=shell, first_line=block.splitlines()[0]):
                    mocks = """
SSH_KEY=/test-private-location/key
ALL_IN_ONE_GPU_VM=(configs/aws/vllm-gpu.json --scenario all-in-one)
ALL_IN_ONE_CPU_VM=(configs/aws/vllm-cpu.json --scenario all-in-one)
REMOTE_GATEWAY_CPU_VM=(configs/aws/vllm-cpu.json --scenario remote-gateway)
REMOTE_GATEWAY_GPU_VM=(configs/aws/vllm-gpu.json --scenario remote-gateway)
VLLM_SERVER_GPU_VM=(configs/aws/vllm-gpu.json --scenario vllm-server)
ALL_IN_ONE_CLOUD_VM=(configs/aws/no-vllm.json --scenario all-in-one)
REMOTE_GATEWAY_CLOUD_VM=(configs/aws/no-vllm.json --scenario remote-gateway)
ALL_IN_ONE_ACCESS=(--ssh-access restricted)
REMOTE_GATEWAY_ACCESS=(--ssh-access restricted --https-access restricted)
ACCOUNT=123456789012 REGION=eu-central-1 RUN_PREFIX=no-deployed-fixtures
AWS_TEST_REPO=/unused RHEL_HOST=ec2-user@192.0.2.8
ssh() { return 1; }
aws_test_credentials() { return 1; }
ssh-add() { return 1; }
cp() { return 1; }
source() { return 1; }
aws_test_discover() { return 1; }
aws_test_key() { return 1; }
aws_test_plan() { return 1; }
aws_test_deploy() { return 1; }
aws_test_verify() { return 1; }
aws_test_ssh() { return 1; }
"""
                    self.run_shell(shell, "set -eu\n" + mocks + block + "\nprintf 'SHELL_ALIVE\\n'\n")

    def test_other_guides_have_no_explicit_parent_shell_exit(self):
        for path in (ROOT / "docs").rglob("*.md"):
            # docs/superpowers holds internal development artifacts (design specs,
            # implementation plans) that embed complete scripts verbatim, not
            # copy-paste terminal guides; they are out of scope for this check.
            if "superpowers" in path.parts:
                continue
            blocks = re.findall(r"^```(?:console|sh|bash)\n(.*?)^```", path.read_text(), re.M | re.S)
            for block in blocks:
                # Isolated subshells and quoted child Bash scripts may fail fast;
                # their shell options and exits cannot close the parent terminal.
                parent = re.sub(r"^\(\n.*?^\)\s*$", "", block, flags=re.M | re.S)
                parent = re.sub(r"\bbash -c '.*?^'\s*$", "bash -c CHILD_SCRIPT", parent, flags=re.M | re.S)
                self.assertNotRegex(parent, r"\bexit\s+[0-9]|\$\{[^}]*:\?|set -[a-zA-Z]*[eu]", str(path))

    def test_bad_remote_user_url_keeps_terminal_open_and_clears_credentials(self):
        document = (ROOT / "docs/quickstarts/remote-gateway/users.md").read_text()
        blocks = re.findall(r"^```console\n(.*?)^```", document, re.M | re.S)
        validation = next(block for block in blocks if block.startswith('PRAXIS_URL="${PRAXIS_URL%/}"'))
        code = "set -eu\nPRAXIS_URL=http://invalid PRAXIS_CALLER_JWT=dummy PRAXIS_CA=''\n"
        output = self.run_shell(shutil.which("bash"), code + validation + """
printf 'URL:%s\\nJWT:%s\\nSHELL_ALIVE\\n' "${PRAXIS_URL:-}" "${PRAXIS_CALLER_JWT:-}"
""")
        self.assertIn("URL:\nJWT:\n", output)


if __name__ == "__main__":
    unittest.main()
