#!/usr/bin/env python3
"""Run real harness entry points with fake CLI/SSH; never contact a gateway."""
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request

import sys
import unittest
import urllib.error
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[2]

# openclaw-native (run by an earlier test in this suite) patches the shared
# provider module's completion wrapper; keep the pristine function so the
# opencode fixture can be exercised on its own, independent of test order.
sys.path.insert(0, str(ROOT / "tests/common"))
import provider as _provider
_PRISTINE_COMPLETION = _provider.completion


class OpenCodeFixtureTest(unittest.TestCase):
    def test_streamed_bash_command_and_final_continuation(self):
        # The pinned image's opencode has no separate write tool (apply_patch
        # owns file edits), so the fixture drives the whole proof through the
        # bash tool itself: one tool call writes the proof, then the
        # continuation returns the marker.
        _provider.completion = _PRISTINE_COMPLETION
        fixture = runpy.run_path(str(Path(__file__).with_name('opencode-provider.py')))
        body = {'model': 'fixture-model', 'messages': [], 'tools': [
            {'type': 'function', 'function': {'name': 'bash'}}]}
        complete = fixture['completion']
        stream = fixture['provider'].events
        result = complete('/v1/chat/completions', body)
        call = result['choices'][0]['message']['tool_calls'][0]
        self.assertEqual(call['function']['name'], 'bash')
        self.assertEqual(call['id'], 'call_bash')
        arguments = json.loads(call['function']['arguments'])
        self.assertIn('opencode-exec-proof.txt', arguments['command'])
        frames = b''.join(stream('/v1/chat/completions', result))
        self.assertIn(b'[DONE]', frames)
        self.assertIn(b'bash', frames)
        body['messages'].append({'role': 'tool', 'tool_call_id': 'call_bash', 'content': 'success'})
        result = complete('/v1/chat/completions', body)
        self.assertEqual(result['choices'][0]['finish_reason'], 'stop')
        self.assertEqual(result['choices'][0]['message']['content'], 'OPENCODE_TOOL_OK')
        self.assertNotIn('tool_calls', result['choices'][0]['message'])


class AuthenticationEvidenceTest(unittest.TestCase):
    def test_unrelated_failure_cannot_pass_authentication_check(self):
        native = runpy.run_path(str(Path(__file__).with_name('openclaw-native.py')))
        check = native['assert_authentication_rejection']
        fixture = native['fixture_module'].provider.Provider(ports=(0, 0, 0))
        fixture.start()
        self.addCleanup(fixture.close)
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory) / 'proof.txt'
            failed = subprocess.CompletedProcess([], 125)
            with self.assertRaisesRegex(RuntimeError, 'No fresh upstream authentication rejection'):
                check(failed, proof, [])
            body = json.dumps({'model': 'fixture-model', 'messages': []}).encode()
            request = urllib.request.Request(
                f'http://127.0.0.1:{fixture.ports[0]}/v1/chat/completions', data=body,
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer wrong-synthetic-key'})
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(rejected.exception.code, 403)
            records = list(fixture.records)
            check(failed, proof, records)
            with self.assertRaisesRegex(RuntimeError, 'No fresh upstream authentication rejection'):
                check(failed, proof, [dict(record, credential_ok=True) for record in records])
            with self.assertRaisesRegex(RuntimeError, 'No fresh upstream authentication rejection'):
                check(failed, proof, [dict(record, classification_clean=False) for record in records])
            with self.assertRaisesRegex(RuntimeError, 'reported as success'):
                check(subprocess.CompletedProcess([], 0), proof, records)
            proof.write_text('unexpected success')
            with self.assertRaisesRegex(RuntimeError, 'reported as success'):
                check(failed, proof, records)


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.env = dict(os.environ, PATH=f"{self.work}:{os.environ['PATH']}",
                        OPENSHELL_BIN=str(self.work / "openshell"),
                        CAPTURE=str(self.work / "capture"), PRAXIS_PORT="18080",
                        PRAXIS_API_PREFIX="", OPENSHELL_SANDBOX_CPU="2", OPENSHELL_SANDBOX_MEMORY="4Gi",
                        OPENSHELL_MODEL_ID='fixture"quoted')
        for name, source in {
            "openshell": '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]

if args[:3] == ["sandbox", "template", "list"]:
    state = pathlib.Path(os.environ["CAPTURE"] + ".templates")
    data = json.loads(state.read_text()) if state.exists() else {}
    print(json.dumps({"templates":list(data.values()), "next_page_token":""}))
    sys.exit()
if args[:3] == ["sandbox", "template", "create"]:
    state = pathlib.Path(os.environ["CAPTURE"] + ".templates")
    data = json.loads(state.read_text()) if state.exists() else {}
    name = args[3]
    record = {"name":name,"image":args[args.index("--image")+1],
              "resources":{"cpu":args[args.index("--cpu")+1],"memory":args[args.index("--memory")+1]},
              "environment":{},"labels":{}}
    for flag,key in [("--label","labels"),("--env","environment")]:
        for index,argument in enumerate(args):
            if argument == flag:
                k,v=args[index+1].split("=",1);record[key][k]=v
    data[name]=record;state.write_text(json.dumps(data));sys.exit()
if args[:3] == ["sandbox", "template", "get"]:
    print(json.dumps(json.loads(pathlib.Path(os.environ["CAPTURE"] + ".templates").read_text())[args[3]]))
    sys.exit()
if args[:2] == ["sandbox", "create"]:
    pathlib.Path(os.environ["CAPTURE"] + ".args").write_text(json.dumps(args))
    p = pathlib.Path(args[args.index("--policy") + 1])
    pathlib.Path(os.environ["CAPTURE"]).write_text(p.read_text())
if args[:1] == ["logs"]:
    print("Acknowledged initial policy revision as loaded")
if args[:2] == ["sandbox", "list"]:
    if "--output" in args and args[args.index("--output") + 1] == "json":
        print(json.dumps({"sandboxes": [{"name": "test", "phase": "Ready"}]}))
    else:
        print("test Ready")
''',
            "ssh": '#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE.ssh"\ncat > "$CAPTURE.provider"\n',
        }.items():
            script = self.work / name
            script.write_text(source)
            script.chmod(0o755)

    def test_review_entry_point_pushes_contract_and_task(self):
        # The fake ssh appends every remote command and stdin payload.
        (self.work / "capture.sshlog").unlink(missing_ok=True)
        (self.work / "capture.stdin").unlink(missing_ok=True)
        script = self.work / "ssh"
        script.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CAPTURE.sshlog"\ncat >> "$CAPTURE.stdin"\n')
        script.chmod(0o755)
        args = ["bash", str(ROOT / "openshell/harnesses/opencode/review.sh"),
                "--name", "test", "--repo", "owner/repo", "--pr", "53", "--pr", "78",
                "--timeout", "60"]
        result = subprocess.run(args, env=self.env, capture_output=True, text=True,
                                timeout=15, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("No such file or directory", result.stderr)
        log = (self.work / "capture.sshlog").read_text()
        self.assertIn("rm -rf ~/review && mkdir -p ~/review ~/reports", log)
        self.assertIn("cat > ~/AGENTS.md", log)
        self.assertIn("cat > ~/review/task.md", log)
        # The turn still runs from the sandbox home with its own stdin closed,
        # but is now wrapped in a sandbox-side deadline so a host-side timeout
        # cannot leave a zombie turn holding gateway reservations.
        self.assertIn("cd ~ && ", log)
        self.assertIn('opencode run --format json "$(cat ~/review/task.md)" </dev/null', log)
        self.assertIn("timeout -k 30 60 opencode run", log)
        # Only the reports for the PRs under review are cleared.
        self.assertIn("rm -f ~/reports/pr-53.md ~/reports/pr-78.md", log)
        stdin = (self.work / "capture.stdin").read_text()
        self.assertIn("PR review agent instructions", stdin)
        self.assertIn("Review pull requests #53,#78 of the GitHub repository owner/repo.", stdin)

    def test_review_turn_stdin_reaches_eof(self):
        # `opencode run` drains piped stdin to EOF before submitting its argv
        # prompt. Over harness_ssh (no PTY) that stdin is the SSH channel,
        # which never EOFs while review.sh runs from a terminal, so the turn
        # must close stdin itself or it hangs before creating a session.
        # The fake ssh executes the remote command with stdin passed through,
        # like real ssh; the fake opencode blocks until stdin EOFs.
        self.env["HOME"] = str(self.work)
        for name, source in {
            "ssh": '#!/bin/sh\nwhile [ $# -gt 1 ]; do shift; done\nexec sh -c "$1"\n',
            "opencode": '#!/bin/sh\ncat > "$CAPTURE.opencode-stdin"\nprintf "OPENCODE_TURN_DONE\\n"\n',
        }.items():
            script = self.work / name
            script.write_text(source)
            script.chmod(0o755)
        read_fd, write_fd = os.pipe()
        try:
            args = ["bash", str(ROOT / "openshell/harnesses/opencode/review.sh"),
                    "--name", "test", "--repo", "owner/repo", "--pr", "53",
                    "--timeout", "60"]
            result = subprocess.run(args, env=self.env, capture_output=True, text=True,
                                    timeout=20, stdin=read_fd)
        finally:
            os.close(write_fd)
            os.close(read_fd)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OPENCODE_TURN_DONE", result.stdout)
        self.assertEqual((self.work / "capture.opencode-stdin").read_text(), "")

    def test_review_collect_entry_point_pulls_reports_over_ssh(self):
        collected = self.work / "collected"
        script = self.work / "ssh"
        script.write_text('#!/bin/sh\n'
                          'mkdir -p "$CAPTURE.reports"\n'
                          'printf "# PR #53\\n" > "$CAPTURE.reports/pr-53.md"\n'
                          # BSD tar adds AppleDouble ._member entries on macOS;
                          # GNU tar in the sandbox never does.
                          'COPYFILE_DISABLE=1 tar cf - -C "$CAPTURE.reports" .\n')
        script.chmod(0o755)
        args = ["bash", str(ROOT / "openshell/harnesses/opencode/review-collect.sh"),
                "--name", "test", "--dest", str(collected)]
        result = subprocess.run(args, env=self.env, capture_output=True, text=True,
                                timeout=15, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = collected / "pr-53.md"
        self.assertTrue(report.is_file())
        self.assertIn("# PR #53", report.read_text())

    def create(self, harness, profile, integrated=False, success=True, config_dir=None,
               provider=None, model=None):
        # Each invocation must produce fresh evidence, including subtests.
        for name in ("capture", "capture.provider"):
            (self.work / name).unlink(missing_ok=True)
        args = ["bash", str(ROOT / f"openshell/harnesses/{harness}/create.sh"),
                "--profile", profile, "--name", "test"]
        if integrated:
            args += ["--config", str(ROOT / (config_dir or "configs/openshell-praxis"))]
        if provider:
            args += ["--provider", provider]
        if model:
            args += ["--model", model]
        result = subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=10)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return yaml.safe_load((self.work / "capture").read_text())
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("readonly variable", result.stderr, "argument validation was never reached")
        self.assertNotIn("unbound variable", result.stderr)
        self.assertFalse((self.work / "capture").exists())
        return result.stderr

    def test_every_standalone_create_entry_point_and_profile(self):
        profiles = {
            "opencode": ("review", "dev", "automation", "interactive", "pr-review"),
            "codex": ("review", "dev", "automation", "interactive"),
            "openclaw": ("review", "dev", "automation", "interactive"),
        }
        for harness, harness_profiles in profiles.items():
            for profile in harness_profiles:
                with self.subTest(harness=harness, profile=profile):
                    policy = self.create(harness, profile)
                    source = ROOT / f"openshell/harnesses/{harness}/profiles/{profile}/policy.yaml"
                    self.assertEqual(policy, yaml.safe_load(source.read_text()))
                    for rule in policy["network_policies"].values():
                        for endpoint in rule["endpoints"]:
                            self.assertIs(type(endpoint["port"]), int)

    def test_integrated_policy_has_numeric_port_and_provider_json_escapes_model(self):
        chat = [{"method": "GET", "path": "/v1/models"},
                {"method": "POST", "path": "/v1/chat/completions"}]
        for profile in ("review", "dev", "automation", "interactive", "pr-review"):
            policy = self.create("opencode", profile, integrated=True)
            endpoint = policy["network_policies"]["praxis_gateway"]["endpoints"][0]
            self.assertIs(type(endpoint["port"]), int)
            self.assertEqual(endpoint["port"], 18080)
            self.assertNotIn("access", endpoint)
            # pr-review renders the native OpenAI adapter, so its gateway also
            # admits the Responses surface that adapter speaks.
            expected_rules = chat + ([{"method": "POST", "path": "/v1/responses"}]
                                     if profile == "pr-review" else [])
            self.assertEqual([rule["allow"] for rule in endpoint["rules"]], expected_rules)
            self.assertEqual({b["path"] for b in policy["network_policies"]["praxis_gateway"]["binaries"]},
                             {"/usr/bin/node-26", "/usr/local/bin/opencode"})
            config = json.loads((self.work / "capture.provider").read_text())
            model = self.env["OPENSHELL_MODEL_ID"]
            self.assertEqual(config["model"], f"praxis/{model}")
            provider = config["provider"]["praxis"]
            self.assertEqual(set(provider["models"]), {model})
            self.assertEqual(provider["options"]["baseURL"], "http://host.openshell.internal:18080/v1")
            if profile == "pr-review":
                # Current OpenAI model families reject max_tokens; the native
                # adapter with forceReasoning sends max_completion_tokens.
                self.assertEqual(provider["npm"], "@ai-sdk/openai")
                self.assertEqual(provider["models"][model]["options"], {"forceReasoning": True})
            else:
                self.assertEqual(provider["npm"], "@ai-sdk/openai-compatible")
                self.assertNotIn("options", provider["models"][model])

    def test_llm_d_sc_harness_uses_catalog_template_and_strict_routes(self):
        self.env.pop("OPENSHELL_MODEL_ID", None)
        policy = self.create("opencode", "dev", integrated=True, config_dir="configs/llm-d-sc")
        endpoint = policy["network_policies"]["praxis_gateway"]["endpoints"][0]
        self.assertEqual(endpoint["port"], 18080)
        self.assertEqual([rule["allow"] for rule in endpoint["rules"]], [
            {"method": "GET", "path": "/v1/models"},
            {"method": "POST", "path": "/v1/chat/completions"},
        ])
        self.assertNotIn("access", endpoint)
        binaries = policy["network_policies"]["praxis_gateway"]["binaries"]
        self.assertEqual({binary["path"] for binary in binaries},
                         {"/usr/bin/node-26", "/usr/local/bin/opencode"})
        provider = json.loads((self.work / "capture.provider").read_text())["provider"]["praxis"]
        self.assertEqual(provider["options"]["baseURL"], "http://host.openshell.internal:18080/v1")
        model = provider["models"]["Semantic-Qwen"]
        self.assertEqual(model["name"], "Semantic-Qwen (complexity routed)")
        self.assertEqual(model["limit"], {"context": 32768, "output": 4096})
        self.assertTrue(model["reasoning"])
        self.assertNotIn("interleaved", model)
        args = json.loads((self.work / "capture.args").read_text())
        template = json.loads((self.work / "capture.templates").read_text())[args[args.index("--template") + 1]]
        self.assertEqual(template["labels"]["backend"], "llm-d-sc")

    def test_explicit_model_replaces_environment_default(self):
        self.create("opencode", "pr-queue", integrated=True, model="approved/model.v2")
        config = json.loads((self.work / "capture.provider").read_text())
        self.assertEqual(config["model"], "openai/approved/model.v2")
        self.assertEqual(set(config["provider"]["openai"]["models"]), {"approved/model.v2"})
        self.assertNotIn("npm", config["provider"]["openai"])

    def test_model_requires_integrated_configuration(self):
        (self.work / "capture.templates").unlink(missing_ok=True)
        error = self.create("opencode", "dev", model="approved-model", success=False)
        self.assertIn("model selection requires --config", error)
        self.assertFalse((self.work / "capture.templates").exists())

    def test_invalid_ports_fail_before_sandbox_creation(self):
        for port in ("0", "65536", "abc", "8080\nfoo: bar"):
            with self.subTest(port=port):
                self.env["PRAXIS_PORT"] = port
                error = self.create("opencode", "dev", integrated=True, success=False)
                self.assertIn("PRAXIS_PORT must be an integer", error)

    def test_qwen_route_prefix_is_rendered_without_changing_host_policy(self):
        self.env["PRAXIS_API_PREFIX"] = "/vllm"
        policy = self.create("opencode", "dev", integrated=True)
        config = json.loads((self.work / "capture.provider").read_text())
        self.assertEqual(config["provider"]["praxis"]["options"]["baseURL"],
                         "http://host.openshell.internal:18080/vllm/v1")
        self.assertEqual(config["provider"]["praxis"]["models"][self.env["OPENSHELL_MODEL_ID"]]["limit"],
                         {"context": 16384, "output": 4096})
        model = config["provider"]["praxis"]["models"][self.env["OPENSHELL_MODEL_ID"]]
        self.assertTrue(model["reasoning"])
        self.assertEqual(model["interleaved"], {"field": "reasoning"})
        # The vLLM path keeps the classic adapter and parameter surface.
        self.assertEqual(config["provider"]["praxis"]["npm"], "@ai-sdk/openai-compatible")
        self.assertNotIn("options", model)
        endpoint = policy["network_policies"]["praxis_gateway"]["endpoints"][0]
        self.assertEqual(endpoint["host"], "host.openshell.internal")
        self.assertEqual(endpoint["port"], 18080)
        self.assertEqual([rule["allow"]["path"] for rule in endpoint["rules"]],
                         ["/vllm/v1/models", "/vllm/v1/chat/completions"])

    def test_every_praxis_profile_has_explicit_rest_rules(self):
        sources = list((ROOT / "configs/openshell-praxis/profiles").glob("*/policy.yaml"))
        sources += [ROOT / "configs/openshell-praxis/openclaw/profiles/dev/policy.yaml"]
        sources += [ROOT / "configs/vllm/harness/profiles/dev/policy.yaml"]
        sources += [ROOT / "configs/vllm/openclaw/profiles/dev/policy.yaml"]
        sources += [ROOT / "configs/llm-d-sc/profiles/dev/policy.yaml"]
        chat = [{"method": "GET", "path": "/v1/models"},
                {"method": "POST", "path": "/v1/chat/completions"}]
        responses = chat + [{"method": "POST", "path": "/v1/responses"}]
        for source in sorted(sources):
            with self.subTest(source=source.relative_to(ROOT)):
                policy = yaml.safe_load(source.read_text().replace("@@PRAXIS_PORT@@", "18080")
                                        .replace("@@PRAXIS_API_PREFIX@@", ""))
                endpoint = policy["network_policies"]["praxis_gateway"]["endpoints"][0]
                self.assertNotIn("access", endpoint)
                self.assertIn([rule["allow"] for rule in endpoint["rules"]], (chat, responses))

    def test_github_git_rules_permit_clone_fetch_and_deny_push(self):
        sources = list(ROOT.glob("openshell/harnesses/*/profiles/*/policy.yaml"))
        sources += list(ROOT.glob("configs/openshell-praxis/*/profiles/*/policy.yaml"))
        sources += list(ROOT.glob("configs/openshell-praxis/profiles/*/policy.yaml"))
        expected = [{"method": "GET", "path": "/**"},
                    {"method": "HEAD", "path": "/**"},
                    {"method": "OPTIONS", "path": "/**"},
                    {"method": "POST", "path": "/**/git-upload-pack"}]
        checked = 0
        for source in sorted(sources):
            policy = yaml.safe_load(source.read_text()
                                    .replace("@@PRAXIS_PORT@@", "18080")
                                    .replace("@@PRAXIS_API_PREFIX@@", ""))
            rule = policy.get("network_policies", {}).get("github_git")
            if rule is None:
                continue
            checked += 1
            with self.subTest(source=source.relative_to(ROOT)):
                endpoint = rule["endpoints"][0]
                self.assertEqual(endpoint["host"], "github.com")
                self.assertEqual(endpoint["port"], 443)
                self.assertEqual(endpoint["protocol"], "rest")
                self.assertEqual(endpoint["enforcement"], "enforce")
                self.assertNotIn("access", endpoint)
                self.assertEqual([item["allow"] for item in endpoint["rules"]], expected)
        self.assertGreaterEqual(checked, 9)

    def test_resource_limits_reach_every_harness_create(self):
        for cpu, memory in (("2", "4Gi"), ("500m", "512Mi")):
            self.env.update(OPENSHELL_SANDBOX_CPU=cpu, OPENSHELL_SANDBOX_MEMORY=memory)
            for harness in ("opencode", "codex", "openclaw"):
                self.create(harness, "dev")
                args = json.loads((self.work / "capture.args").read_text())
                self.assertIn("--template", args)
                for flag in ("--from", "--cpu", "--memory", "--env", "--gpu"):
                    self.assertNotIn(flag,args)
                template=json.loads((self.work / "capture.templates").read_text())[args[args.index("--template")+1]]
                self.assertEqual(template["resources"],{"cpu":cpu,"memory":memory})
                self.assertIn("managed-by=secure-single-server",args)
                self.assertIn("--no-auto-providers", args)

    def test_arbitrary_api_prefix_is_rejected_before_creation(self):
        for prefix in ("/v1", "//example.org", "/vllm?secret=bad", "/../", "vllm"):
            self.env["PRAXIS_API_PREFIX"] = prefix
            self.assertIn("PRAXIS_API_PREFIX", self.create("opencode", "dev", integrated=True, success=False))

    def test_unsupported_integrated_harnesses_reject_config(self):
        for harness in ("codex",):
            for profile in ("review", "dev", "automation", "interactive"):
                with self.subTest(harness=harness, profile=profile):
                    error = self.create(harness, profile, integrated=True, success=False)
                    self.assertIn("--config", error)

    def test_openclaw_praxis_config_and_credential_isolation(self):
        for folder, prefix in (("configs/openshell-praxis/openclaw", ""),
                               ("configs/vllm/openclaw", ""),
                               ("configs/openshell-praxis/openclaw", "/vllm"),
                               ("configs/openshell-praxis/openclaw", "/providers/team")):
            with self.subTest(folder=folder, prefix=prefix):
                self.env["PRAXIS_API_PREFIX"] = prefix
                policy = self.create("openclaw", "dev", integrated=True, config_dir=folder)
                config = json.loads((self.work / "capture.provider").read_text())
                provider = config["models"]["providers"]["praxis"]
                self.assertEqual(provider["baseUrl"], f"http://host.openshell.internal:18080{prefix}/v1")
                self.assertEqual(provider["apiKey"], "local-placeholder")
                self.assertEqual(config["tools"]["allow"], ["read", "write"])
                self.assertEqual(provider["api"], "openai-completions")
                self.assertEqual(provider["models"][0]["id"], self.env["OPENSHELL_MODEL_ID"])
                self.assertEqual(config["agents"]["defaults"]["model"]["primary"],
                                 "praxis/" + self.env["OPENSHELL_MODEL_ID"])
                self.assertEqual(config["agents"]["defaults"]["workspace"], "/home/node/.openclaw/workspace")
                self.assertFalse(policy["filesystem_policy"]["include_workdir"])
                self.assertIn('/app', policy["filesystem_policy"]["read_only"])
                self.assertNotIn('/app', policy["filesystem_policy"]["read_write"])
                if folder == "configs/vllm/openclaw":
                    self.assertEqual(config["agents"]["defaults"]["models"]["praxis/" + self.env["OPENSHELL_MODEL_ID"]],
                                     {"params": {"chat_template_kwargs": {"enable_thinking": False}}})
                else:
                    self.assertNotIn("models", config["agents"]["defaults"])
                args = json.loads((self.work / "capture.args").read_text())
                self.assertIn("--no-auto-providers", args)
                self.assertNotIn("--provider", args)
                rule = policy["network_policies"]["praxis_gateway"]
                self.assertEqual(rule["endpoints"][0]["port"], 18080)
                self.assertEqual([item["allow"]["path"] for item in rule["endpoints"][0]["rules"]],
                                 [f"{prefix}/v1/models", f"{prefix}/v1/chat/completions"])
                self.assertEqual({b["path"] for b in rule["binaries"]},
                                 {"/usr/local/bin/node", "/usr/local/bin/openclaw"})
                hosts = {e["host"] for r in policy["network_policies"].values() for e in r["endpoints"]}
                self.assertNotIn("api.openai.com", hosts)
                self.assertNotIn("api.anthropic.com", hosts)
                if folder == "configs/vllm/openclaw":
                    self.assertEqual(hosts, {"host.openshell.internal"})

    def test_openclaw_invalid_configuration_fails_before_creation(self):
        folder = "configs/openshell-praxis/openclaw"
        for port in ("0", "65536", "not-a-port"):
            self.env["PRAXIS_PORT"] = port
            self.create("openclaw", "dev", integrated=True, success=False, config_dir=folder)
        self.env["PRAXIS_PORT"] = "8080"
        self.create("openclaw", "dev", integrated=True, success=False,
                    config_dir=folder, provider="direct-key")
        for profile in ("review", "automation", "interactive"):
            self.create("openclaw", profile, integrated=True, success=False, config_dir=folder)
        for model in ("", "model\nmalformed"):
            self.env["OPENSHELL_MODEL_ID"] = model
            self.create("openclaw", "dev", integrated=True, success=False, config_dir=folder)
        self.env["OPENSHELL_MODEL_ID"] = "test-model"
        for prefix in ("/elsewhere", "/providers/", "/providers/TEAM", "/providers/team/../openai", "/providers/a" + "b" * 32):
            self.env["PRAXIS_API_PREFIX"] = prefix
            self.create("openclaw", "dev", integrated=True, success=False, config_dir=folder)

    def test_integrated_policy_ports(self):
        for source in (ROOT / "configs/openshell-praxis/profiles").glob("*/policy.yaml"):
            with self.subTest(profile=source.parent.name):
                policy = yaml.safe_load(source.read_text().replace("@@PRAXIS_PORT@@", "18080"))
                port = policy["network_policies"]["praxis_gateway"]["endpoints"][0]["port"]
                self.assertIs(type(port), int, "OpenShell schema requires an unsigned integer")

    def test_bootc_local_backend_owns_model_and_port_from_catalog(self):
        for backend in ("vllm", "remote-vllm"):
            self.env["OPENSHELL_BOOTC_BACKEND"] = backend
            for harness in ("opencode", "openclaw"):
                self.create(harness, "dev")
                config = json.loads((self.work / "capture.provider").read_text())
                if harness == "opencode":
                    provider = config["provider"]["praxis"]
                    self.assertEqual(config["model"], "praxis/Qwen/Qwen3-8B")
                    self.assertEqual(provider["options"]["baseURL"], "http://host.openshell.internal:8080/v1")
                else:
                    self.assertEqual(config["agents"]["defaults"]["model"]["primary"], "praxis/Qwen/Qwen3-8B")
                    self.assertEqual(config["models"]["providers"]["praxis"]["baseUrl"], "http://host.openshell.internal:8080/v1")
                args = json.loads((self.work / "capture.args").read_text())
                self.assertIn("backend=" + backend, args)
                self.assertNotIn("--provider", args)
                for forbidden in ("--provider", "--config"):
                    self.create(harness, "dev", success=False,
                                provider="direct" if forbidden == "--provider" else None,
                                integrated=forbidden == "--config")

    def test_catalog_only_profile_reaches_existing_entry_point(self):
        catalog = self.work / "catalog"
        catalog.mkdir()
        data = json.loads((ROOT / "configs/templates/opencode.json").read_text())
        entry = next(item.copy() for item in data["templates"] if item["backend"] == "standalone")
        entry.update(profile="tiny", cpu="500m", memory="512Mi")
        (catalog / "opencode.json").write_text(json.dumps({"version":1,"templates":[entry]}))
        self.env["OPENSHELL_TEMPLATE_DIR"] = str(catalog)
        self.env.pop("OPENSHELL_SANDBOX_CPU")
        self.env.pop("OPENSHELL_SANDBOX_MEMORY")
        self.create("opencode", "tiny")
        args = json.loads((self.work / "capture.args").read_text())
        template = json.loads((self.work / "capture.templates").read_text())[args[args.index("--template")+1]]
        self.assertEqual(template["resources"], {"cpu":"500m","memory":"512Mi"})
        self.assertIn("profile=tiny", args)

    def test_all_connect_entry_points_propagate_ssh_failure(self):
        # A missing executable or failed SSH session must not look successful.
        (self.work / "ssh").write_text('#!/bin/sh\nprintf called > "$CAPTURE.ssh"\nexit 255\n')
        for harness in ("opencode", "codex", "openclaw"):
            with self.subTest(harness=harness):
                marker = self.work / "capture.ssh"
                marker.unlink(missing_ok=True)
                result = subprocess.run(["bash", str(ROOT / f"openshell/harnesses/{harness}/connect.sh"),
                    "--name", "test"], env=self.env, capture_output=True, text=True, timeout=10)
                self.assertTrue(marker.exists(), "connect failed before invoking SSH")
                self.assertEqual(result.returncode, 255, result.stderr)

    def test_connect_entry_points_reject_invalid_sandbox_names(self):
        # The sandbox name flows into the OpenShell CLI and the ssh ProxyCommand,
        # which runs through a shell; reject anything that is not a plain
        # identifier before connecting.
        for harness in ("opencode", "openclaw", "codex"):
            for name in ("bad name", "sandbox;rm -rf /", "--force", "Uppercase_bad!", "",
                         "12345678901234567890"):
                with self.subTest(harness=harness, name=name):
                    marker = self.work / "capture.ssh"
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", str(ROOT / f"openshell/harnesses/{harness}/connect.sh"), "--name", name],
                        env=self.env, capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("invalid", result.stderr.lower())
                    self.assertFalse(marker.exists(), "invalid sandbox name reached ssh")

    def test_connect_entry_points_reject_invalid_gateway_name(self):
        # The gateway name also reaches the ProxyCommand; a rejected value must
        # abort before ssh instead of launching it with an empty ProxyCommand.
        for harness in ("opencode", "openclaw"):
            with self.subTest(harness=harness):
                marker = self.work / "capture.ssh"
                marker.unlink(missing_ok=True)
                result = subprocess.run(
                    ["bash", str(ROOT / f"openshell/harnesses/{harness}/connect.sh"), "--name", "test"],
                    env={**self.env, "OPENSHELL_GATEWAY_NAME": "bad name"},
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("invalid", result.stderr.lower())
                self.assertFalse(marker.exists(), "invalid gateway name reached ssh")

    def test_connect_entry_points_accept_remote_command(self):
        for harness, default_name in (("opencode", "opencode-dev"), ("codex", "codex-dev"),
                                      ("openclaw", "openclaw-dev")):
            for arguments, sandbox in ((["bash"], default_name),
                                       (["--name", "test", "bash"], "test")):
                with self.subTest(harness=harness, arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(ROOT / f"openshell/harnesses/{harness}/connect.sh"),
                         *arguments],
                        env=self.env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    ssh_arguments = (self.work / "capture.ssh").read_text().splitlines()
                    self.assertEqual(ssh_arguments[-2:], [f"sandbox@{sandbox}", "bash"])

    def test_connect_remote_command_preserves_argument_boundaries(self):
        (self.work / "ssh").write_text(
            '#!/bin/sh\ncommand=\nfor argument do\n  command=$argument\ndone\nexec sh -c "$command"\n')
        result = subprocess.run(
            ["bash", str(ROOT / "openshell/harnesses/opencode/connect.sh"),
             "--name", "test", "printf", "%s\\n", "a b"],
            env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "a b\n")

    def test_connect_command_boundary_allows_leading_options(self):
        defaults = {"opencode": "opencode-dev", "codex": "codex-dev",
                    "openclaw": "openclaw-dev"}
        for harness in ("opencode", "codex", "openclaw"):
            with self.subTest(harness=harness):
                result = subprocess.run(
                    ["bash", str(ROOT / f"openshell/harnesses/{harness}/connect.sh"),
                     "--", "--name", "remote-command"],
                    env=self.env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                ssh_arguments = (self.work / "capture.ssh").read_text().splitlines()
                self.assertEqual(
                    ssh_arguments[-2:],
                    [f"sandbox@{defaults[harness]}", "--name remote-command"])

    def test_openclaw_waits_for_initial_policy_before_uploading_config(self):
        cli = self.work / "openshell"
        source = cli.read_text().replace('print("Acknowledged initial policy revision as loaded")',
            'marker = pathlib.Path(os.environ["CAPTURE"] + ".polls")\n'
            '    count = int(marker.read_text()) + 1 if marker.exists() else 1\n'
            '    marker.write_text(str(count))\n'
            '    if count >= 2: print("Acknowledged initial policy revision as loaded")')
        cli.write_text(source)
        self.create("openclaw", "dev", integrated=True, config_dir="configs/vllm/openclaw")
        self.assertEqual((self.work / "capture.polls").read_text(), "2")
        self.assertTrue((self.work / "capture.provider").exists())
        cli.write_text(source.replace('if count >= 2: print("Acknowledged initial policy revision as loaded")', 'sys.exit(42)'))
        (self.work / "capture.provider").unlink()
        result = subprocess.run(["bash", str(ROOT / "openshell/harnesses/openclaw/create.sh"),
                                 "--profile", "dev", "--name", "test", "--config", str(ROOT / "configs/vllm/openclaw")],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 42)
        self.assertFalse((self.work / "capture.provider").exists())

    def test_openclaw_run_transmits_prompt_over_stdin_and_propagates_failure(self):
        prompt = "Write a file; $(touch should-not-exist)\nThen read it."
        result = subprocess.run(["bash", str(ROOT / "openshell/harnesses/openclaw/run.sh"),
                                 "--name", "test", "--message", prompt], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / "capture.provider").read_text(), prompt + "\n")
        self.assertIn("SQLITE_TMPDIR=/tmp", (self.work / "capture.ssh").read_text())
        self.assertFalse((ROOT / "should-not-exist").exists())
        (self.work / "ssh").write_text('#!/bin/sh\ncat >/dev/null\nexit 42\n')
        result = subprocess.run(["bash", str(ROOT / "openshell/harnesses/openclaw/run.sh"),
                                 "--name", "test", "--message", "hello"], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 42)

    def test_invalid_create_arguments_fail_with_an_argument_error(self):
        for harness in ("opencode", "codex", "openclaw"):
            for args in (["--profile"], ["--profile", "missing"], ["--unknown"]):
                with self.subTest(harness=harness, args=args):
                    result = subprocess.run(["bash", str(ROOT / f"openshell/harnesses/{harness}/create.sh"),
                        *args], env=self.env, capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("readonly variable", result.stderr)
                    self.assertNotIn("unbound variable", result.stderr)
                    self.assertFalse((self.work / "capture").exists())


# The UBI9 static lane runs this suite in a container without git; the sync
# script itself targets an operator workstation, which always has it.
@unittest.skipUnless(shutil.which("git"), "git is required")
class SyncBranchTest(unittest.TestCase):
    def test_sync_transfers_every_diff_entry(self):
        # sync-branch.sh feeds the git diff to its read loop through a
        # process substitution; ssh and scp inside the loop inherit that
        # stdin and drain the stream, so the loop saw EOF after the first
        # entry and printed "sync complete" having synced 1 of N files.
        # The fake ssh drains stdin like the real one; the fake scp records
        # the local path it was asked to transfer.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()

            def git(*args):
                subprocess.run(["git", "-C", repo, *args], check=True,
                               capture_output=True)

            git("init", "-b", "main")
            git("config", "user.email", "sync@example.com")
            git("config", "user.name", "sync test")
            git("config", "commit.gpgsign", "false")
            (repo / "keep.txt").write_text("base\n")
            git("add", ".")
            git("commit", "-m", "base")
            git("checkout", "-b", "feature")
            for name in ("alpha.txt", "beta.txt", "gamma.txt"):
                (repo / name).write_text(name + "\n")
            git("mv", "keep.txt", "moved.txt")
            git("add", ".")
            git("commit", "-m", "changes")
            shims = root / "shims"
            shims.mkdir()
            log = root / "scp.log"
            for name, source in {
                "ssh": '#!/bin/sh\n[ "$1" = "-n" ] && exec </dev/null\ncat > /dev/null\nexit 0\n',
                "scp": '#!/bin/sh\nwhile [ $# -gt 2 ]; do shift; done\nprintf "%s\\n" "$1" >> "$SCP_LOG"\nexit 0\n',
            }.items():
                script = shims / name
                script.write_text(source)
                script.chmod(0o755)
            env = dict(os.environ, PATH=f"{shims}:{os.environ['PATH']}",
                       SCP_LOG=str(log))
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/dev/sync-branch.sh"),
                 "--host", "user@fake", "--base", "main"],
                cwd=repo, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sync complete", result.stdout)
            transferred = sorted(log.read_text().split())
            # Sources are passed as ./PATH so a leading-dash filename cannot be
            # parsed as an scp option.
            self.assertEqual(
                transferred,
                ["./alpha.txt", "./beta.txt", "./gamma.txt", "./moved.txt"])


if __name__ == "__main__":
    unittest.main()
