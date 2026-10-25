#!/usr/bin/env python3
"""Exercise llm-d-sc routing without OpenShift, KServe, or Compose."""

import argparse
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/common"))
from evidence import save

ENGINE = os.environ.get("CONTAINER_ENGINE", "podman")


def pinned_images():
    values = {}
    for line in (ROOT / "configs/llm-d-sc/images.env").read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return {key: os.environ.get(key, value) for key, value in values.items()}


IMAGES = pinned_images()
PRAXIS_IMAGE = IMAGES["LLM_D_SC_PRAXIS_IMAGE"]
CLASSIFIER_IMAGE = IMAGES["LLM_D_SC_CLASSIFIER_IMAGE"]
MODELCAR_IMAGE = IMAGES["LLM_D_SC_MODELCAR_IMAGE"]
MOCK_IMAGE = IMAGES["LLM_D_SC_TRACE_IMAGE"]
OPENWEBUI_IMAGE = IMAGES["LLM_D_SC_OPENWEBUI_IMAGE"]

BACKEND_SOURCE = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            data = b"OK"
            content_type = "text/plain"
        elif self.path == "/v1/models":
            data = json.dumps({
                "object": "list",
                "data": [{"id": "Semantic-Qwen", "object": "model"}],
            }).encode()
            content_type = "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = json.loads(self.rfile.read(length) or b"{}")
        if self.headers.get("X-Test-Fail-Backend") == os.environ["BACKEND_NAME"]:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        request_headers = {
            key.lower(): value
            for key, value in self.headers.items()
            if key.lower().startswith("x-llm-d-sc-")
        }
        payload = {
            "backend": os.environ["BACKEND_NAME"],
            "request_headers": request_headers,
            "request_model": request_body.get("model"),
        }
        response = {
            "id": "chatcmpl-llm-d-sc-test",
            "object": "chat.completion",
            "created": 0,
            "model": request_body.get("model", "unknown"),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(payload, sort_keys=True),
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        if request_body.get("stream"):
            chunks = [
                {
                    "id": response["id"],
                    "object": "chat.completion.chunk",
                    "created": response["created"],
                    "model": response["model"],
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "content": response["choices"][0]["message"]["content"],
                        },
                        "finish_reason": None,
                    }],
                },
                {
                    "id": response["id"],
                    "object": "chat.completion.chunk",
                    "created": response["created"],
                    "model": response["model"],
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop",
                    }],
                },
            ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
            return
        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        return

server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
server.serve_forever()
'''


def run(*args, capture=True, timeout=300):
    result = subprocess.run(
        [str(item) for item in args],
        capture_output=capture,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        output = result.stderr if capture and result.stderr else result.stdout if capture else ""
        raise RuntimeError(output or f"command failed: {' '.join(map(str, args))}")
    return result.stdout.strip() if capture else ""


def container_logs(name):
    result = subprocess.run(
        [ENGINE, "logs", name],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return (result.stdout + result.stderr).strip()


def inspect(image, format_string):
    return run(ENGINE, "image", "inspect", image, "--format", format_string)


def vllm_images():
    values = {}
    for line in (ROOT / "configs/vllm/images.env").read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return {key: os.environ.get(key, value) for key, value in values.items()}


def model_settings(model):
    if model == "qwen3-8b":
        images = vllm_images()
        return {
            "model": images["VLLM_MODEL"],
            "revision": images["VLLM_REVISION"],
            "context": 16384,
            "tool_parser": "hermes",
            "model_args": "",
            "chat_template": ROOT / "configs/vllm/qwen3.jinja",
        }
    if model != "qwen3.8-27b-int4":
        raise ValueError("unsupported real model preset")
    values = {}
    path = ROOT / "configs/vllm/qwen3.8-27b-int4.env"
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip("'\"")
    return {
        "model": values["VLLM_MODEL"],
        "revision": values["VLLM_REVISION"],
        "context": int(values["VLLM_CONTEXT"]),
        "tool_parser": values["VLLM_TOOL_PARSER"],
        "model_args": values["VLLM_MODEL_ARGS"],
        "chat_template": None,
    }


def vllm_command(mode, settings):
    command = [
        settings["model"], "--revision", settings["revision"],
        "--served-model-name", "Semantic-Qwen",
        "--host", "0.0.0.0", "--port", "8000", "--dtype", "bfloat16",
        "--tensor-parallel-size", "1", "--max-model-len", str(settings["context"]),
        "--max-num-seqs", "1", "--enforce-eager", "--enable-auto-tool-choice",
        "--tool-call-parser", settings["tool_parser"],
        "--reasoning-parser", "qwen3",
        "--default-chat-template-kwargs", '{"enable_thinking":true}',
    ]
    if settings["chat_template"]:
        command += ["--chat-template", "/template.jinja"]
    if settings["model_args"]:
        command += shlex.split(settings["model_args"])
    if mode == "gpu":
        command += ["--gpu-memory-utilization", "0.90"]
    return command


def prepare_images(real=False, remote_gpu=False, gpu_only=False):
    images = [PRAXIS_IMAGE, CLASSIFIER_IMAGE, MODELCAR_IMAGE, MOCK_IMAGE,
              OPENWEBUI_IMAGE]
    if real:
        if not gpu_only:
            images.append(vllm_images()["VLLM_CPU_IMAGE"])
        if not remote_gpu:
            images.append(vllm_images()["VLLM_GPU_IMAGE"])
    for image in images:
        available = subprocess.run(
            [ENGINE, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if available.returncode:
            run(ENGINE, "pull", image, timeout=3600)
        architecture = inspect(image, "{{.Architecture}}")
        if architecture != "amd64":
            raise AssertionError(f"{image} is linux/{architecture}, expected linux/amd64")
    praxis_user = inspect(PRAXIS_IMAGE, "{{.Config.User}}")
    if not praxis_user or praxis_user in ("0", "0:0", "root"):
        raise AssertionError(f"Praxis image must declare a non-root user, found {praxis_user!r}")


def bind(source, target):
    return ["--volume", f"{source}:{target}:ro,Z"]


def wait_for_classifier(name, attempts=120):
    last_log = ""
    for attempt in range(attempts):
        state = run(ENGINE, "container", "inspect", "--format", "{{.State.Status}}", name)
        if state != "running":
            raise AssertionError(f"classifier is {state}, expected running")
        last_log = container_logs(name)
        if "READY" in last_log:
            return
        time.sleep(1)
    raise AssertionError(f"classifier did not report readiness; logs:\n{last_log}")


def request(port, prompt, max_tokens=16, timeout=10, headers=None):
    body = json.dumps({
        "model": "Semantic-Qwen",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 16,
    }).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    ).open(request, timeout=timeout) as response:
        if response.status != 200:
            raise AssertionError(f"gateway returned HTTP {response.status}")
        completion = json.load(response)
    content = completion["choices"][0]["message"]["content"]
    return json.loads(content)


def raw_request(port, prompt, max_tokens=128, timeout=600,
                chat_template_kwargs=None):
    body = json.dumps({
        "model": "Semantic-Qwen",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        **({"chat_template_kwargs": chat_template_kwargs}
           if chat_template_kwargs is not None else {}),
    }).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    ).open(request, timeout=timeout) as response:
        if response.status != 200:
            raise AssertionError(f"gateway returned HTTP {response.status}")
        completion = json.load(response)
    return completion["choices"][0]["message"]["content"]


def wait_for_gateway(port, attempts=60):
    last_error = None
    for _ in range(attempts):
        try:
            with urllib.request.build_opener(
                urllib.request.ProxyHandler({})
            ).open(f"http://127.0.0.1:{port}/v1/models", timeout=2) as response:
                models = json.load(response)
            assert [item["id"] for item in models["data"]] == ["Semantic-Qwen"]
            return
        except (OSError, urllib.error.URLError, AssertionError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(0.5)
    raise AssertionError(f"gateway did not become ready: {last_error}")


def wait_for_http(port, path, attempts=300):
    last_error = None
    for _ in range(attempts):
        try:
            with urllib.request.build_opener(
                urllib.request.ProxyHandler({})
            ).open(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
                if response.status == 200:
                    return
                raise AssertionError(f"HTTP endpoint returned {response.status}")
        except (OSError, urllib.error.URLError, AssertionError) as error:
            last_error = error
            time.sleep(1)
    raise AssertionError(f"HTTP endpoint did not become ready: {last_error}")


def trace_records(port):
    with urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    ).open(f"http://127.0.0.1:{port}/_trace/api/traces", timeout=5) as response:
        if response.status != 200:
            raise AssertionError(f"trace API returned HTTP {response.status}")
        return json.load(response)["traces"]


def json_request(url, payload, headers=None, timeout=30):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    ).open(request, timeout=timeout) as response:
        if response.status != 200:
            raise AssertionError(f"Open WebUI returned HTTP {response.status}")
        return json.load(response)


def webui_session(port):
    session = json_request(
        f"http://127.0.0.1:{port}/api/v1/auths/signin",
        {"email": "admin@localhost", "password": "admin"},
    )
    token = session.get("token")
    assert token, f"Open WebUI did not return a session token: {session.keys()}"
    return token


def webui_models(port, token):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    ).open(request, timeout=30) as response:
        if response.status != 200:
            raise AssertionError(f"Open WebUI models returned HTTP {response.status}")
        models = json.load(response)["data"]
    ids = [item["id"] for item in models]
    assert "Semantic-Qwen" in ids, f"Semantic-Qwen missing from Open WebUI models: {ids}"
    return ids


def webui_request(port, token, prompt, max_tokens=16, timeout=30,
                  chat_template_kwargs=None):
    completion = json_request(
        f"http://127.0.0.1:{port}/api/chat/completions",
        {
            "model": "Semantic-Qwen",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "stream": False,
            **({"chat_template_kwargs": chat_template_kwargs}
               if chat_template_kwargs is not None else {}),
        },
        {"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    return completion["choices"][0]["message"]["content"]


def start_real_backend(name, alias, mode, network, cache_volume, settings,
                       publish_host="127.0.0.1", publish_port=None):
    images = vllm_images()
    image = images["VLLM_CPU_IMAGE"] if mode == "cpu" else images["VLLM_GPU_IMAGE"]
    options = [
        ENGINE, "run", "--detach", "--name", name,
        "--network", network, "--network-alias", alias,
        "--read-only", "--cap-drop", "all",
        "--security-opt", "no-new-privileges",
        "--user", "0:0", "--tmpfs", "/tmp", "--shm-size", "4g",
        "--volume", f"{cache_volume}:/cache",
        "--env", "HOME=/cache",
        "--env", "HF_HOME=/cache/huggingface",
        "--env", "VLLM_CACHE_ROOT=/cache/vllm",
        "--env", "VLLM_NO_USAGE_STATS=1",
        "--env", "DO_NOT_TRACK=1",
        "--publish",
        f"{publish_host}:{publish_port}:8000" if publish_port is not None
        else f"{publish_host}::8000",
    ]
    if settings["chat_template"]:
        options += bind(settings["chat_template"], "/template.jinja")
    if mode == "cpu":
        options += [
            "--env", "VLLM_CPU_KVCACHE_SPACE=4",
            "--env", "VLLM_CPU_OMP_THREADS_BIND=nobind",
        ]
    else:
        options += [
            "--security-opt", "label=disable",
            "--device", "nvidia.com/gpu=0",
        ]
    run(*options, image, *vllm_command(mode, settings))
    return run(ENGINE, "port", name, "8000/tcp")


def wait_for_backend(name, endpoint, attempts=None):
    attempts = attempts or int(os.environ.get("LLM_D_SC_BACKEND_TIMEOUT", "360"))
    last_log = ""
    last_error = None
    for _ in range(attempts):
        state = run(ENGINE, "container", "inspect", "--format", "{{.State.Status}}", name)
        if state != "running":
            last_log = container_logs(name)
            raise AssertionError(f"{name} is {state}; logs:\n{last_log}")
        try:
            with urllib.request.build_opener(
                urllib.request.ProxyHandler({})
            ).open(f"http://{endpoint}/v1/models", timeout=5) as response:
                models = json.load(response)
            assert "Semantic-Qwen" in [item["id"] for item in models["data"]]
            return
        except (OSError, urllib.error.URLError, AssertionError,
                json.JSONDecodeError) as error:
            last_error = error
            time.sleep(5)
    last_log = container_logs(name)
    raise AssertionError(
        f"{name} did not become ready; last error: {last_error}; logs:\n{last_log}"
    )


def wait_for_remote_backend(endpoint, attempts=None):
    attempts = attempts or int(os.environ.get("LLM_D_SC_BACKEND_TIMEOUT", "360"))
    last_error = None
    url = f"http://{endpoint}:8000/v1/models"
    for _ in range(attempts):
        try:
            with urllib.request.build_opener(
                urllib.request.ProxyHandler({})
            ).open(url, timeout=5) as response:
                models = json.load(response)
            assert "Semantic-Qwen" in [item["id"] for item in models["data"]]
            return
        except (OSError, urllib.error.URLError, AssertionError,
                json.JSONDecodeError) as error:
            last_error = error
            time.sleep(5)
    raise AssertionError(f"remote GPU backend {endpoint} did not become ready: {last_error}")


def assert_trace(records, label, backend, fallback=False):
    row = next(
        (item for item in records
         if item.get("route") == backend
         and (item.get("fallback") if fallback else item.get("label") == label)),
        None,
    )
    available = [
        (item.get("label"), item.get("route"), item.get("status"), item.get("path"))
        for item in records
    ]
    assert row is not None, f"trace API has no {label} record; records={available}"
    assert row["route"] == backend, f"expected {backend}, received {row['route']}"
    assert row["status"] == 200, f"expected HTTP 200, received {row['status']}"
    if label is not None:
        assert row["score"], f"trace API has no classifier score for {label}"
    return {
        "label": row["label"],
        "route": row["route"],
        "status": row["status"],
        "duration_ms": row["duration_ms"],
        "fallback": bool(row["fallback"]),
        "hops": [{"route": hop["route"], "status": hop["status"]}
                 for hop in row["hops"]],
    }


def assert_route(result, label, backend, minimum_score):
    headers = result["request_headers"]
    actual_label = headers.get("x-llm-d-sc-label")
    actual_status = headers.get("x-llm-d-sc-status")
    actual_score = float(headers.get("x-llm-d-sc-score", "-1"))
    assert actual_label == label, f"expected {label}, received {actual_label}"
    assert actual_status == "OK", f"expected OK status, received {actual_status}"
    assert actual_score >= minimum_score, f"{label} score {actual_score} is below {minimum_score}"
    assert result["backend"] == backend, f"expected {backend}, received {result['backend']}"
    return {
        "label": actual_label,
        "score": actual_score,
        "status": actual_status,
        "backend": result["backend"],
    }


def diagnostics(*containers):
    for container in containers:
        if not container:
            continue
        state = subprocess.run(
            [ENGINE, "container", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        logs = subprocess.run(
            [ENGINE, "logs", container],
            capture_output=True,
            text=True,
            check=False,
        )
        print(f"--- {container} ({state or 'absent'}) ---", flush=True)
        print(logs.stdout[-12000:] or logs.stderr[-12000:], flush=True)


def main(real=False, model="qwen3.8-27b-int4", keep=False, remote_gpu=None,
         gpu_only=False, gpu_publish_host="127.0.0.1",
         cache_volume_name=None):
    os.environ.setdefault("TEST_EVIDENCE_DIR", "evidence/llm-d-sc")
    if real and Path(ENGINE).name != "podman":
        raise ValueError("real Qwen mode requires rootless Podman")
    if remote_gpu and not real:
        raise ValueError("--remote-gpu requires --real")
    if gpu_only and not real:
        raise ValueError("--gpu-only requires --real")
    if gpu_only and remote_gpu:
        raise ValueError("--gpu-only cannot use --remote-gpu")
    prefix = "llm-d-sc-test-" + uuid.uuid4().hex[:12]
    network = prefix + "-network"
    model_volume = prefix + "-model"
    classifier = prefix + "-classifier"
    praxis = prefix + "-praxis"
    trace_ui = prefix + "-trace-ui"
    open_webui = prefix + "-open-webui"
    cpu_backend = prefix + "-cpu"
    gpu_backend = prefix + "-gpu"
    webui_volume = prefix + "-webui"
    cache_volume = cache_volume_name or prefix + "-cache"
    owns_cache_volume = cache_volume_name is None
    settings = model_settings(model) if real else None
    result = {
        "engine": ENGINE,
        "mode": "real-gpu-only" if gpu_only else "real" if real else "mock",
        "model": model if real else "mock",
        "images": {
            "praxis": PRAXIS_IMAGE,
            "classifier": CLASSIFIER_IMAGE,
            "modelcar": MODELCAR_IMAGE,
            "mock": MOCK_IMAGE,
            "trace_ui": MOCK_IMAGE,
            "open_webui": OPENWEBUI_IMAGE,
        },
        "status": "running",
        "routes": [],
    }
    if gpu_only:
        result["gpu_publish_host"] = gpu_publish_host
    if remote_gpu:
        result["remote_gpu"] = remote_gpu
    if real:
        result["images"]["vllm_cpu"] = vllm_images()["VLLM_CPU_IMAGE"]
        result["images"]["vllm_gpu"] = vllm_images()["VLLM_GPU_IMAGE"]
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        backend = work / "backend.py"
        backend.write_text(BACKEND_SOURCE)
        backend.chmod(0o644)
        try:
            prepare_images(real, bool(remote_gpu), gpu_only)
            run(ENGINE, "network", "create", network)
            if real:
                existing_cache = subprocess.run(
                    [ENGINE, "volume", "inspect", cache_volume],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if existing_cache.returncode:
                    run(ENGINE, "volume", "create", cache_volume)
            if gpu_only:
                gpu_port = start_real_backend(
                    gpu_backend, "vllm-gpu", "gpu", network, cache_volume,
                    settings, gpu_publish_host, 8000,
                )
                wait_for_backend(gpu_backend, gpu_port)
                result["backend_ports"] = {"gpu": gpu_port}
                if keep:
                    result["resources"] = {
                        "prefix": prefix,
                        "network": network,
                        "cache_volume": cache_volume,
                    }
                result["status"] = "passed"
                print(json.dumps(result, indent=2))
                return 0
            run(ENGINE, "volume", "create", model_volume)
            run(
                ENGINE, "run", "--rm",
                "--volume", f"{model_volume}:/shared",
                "--user", "0:0",
                "--read-only",
                "--cap-drop", "all",
                "--security-opt", "no-new-privileges",
                MODELCAR_IMAGE,
                "/bin/sh", "-c", "cp -R /models/. /shared/",
            )

            if real:
                if remote_gpu:
                    wait_for_remote_backend(remote_gpu)
                else:
                    gpu_port = start_real_backend(
                        gpu_backend, "vllm-gpu", "gpu", network, cache_volume, settings
                    )
                    wait_for_backend(gpu_backend, gpu_port)
                cpu_port = start_real_backend(
                    cpu_backend, "vllm-cpu", "cpu", network, cache_volume, settings
                )
                wait_for_backend(cpu_backend, cpu_port)
                result["backend_ports"] = {"cpu": cpu_port}
                if not remote_gpu:
                    result["backend_ports"]["gpu"] = gpu_port
            else:
                for name, backend_name, alias in (
                    (cpu_backend, "vllm-cpu", "vllm-cpu"),
                    (gpu_backend, "vllm-gpu", "vllm-gpu"),
                ):
                    run(
                        ENGINE, "run", "--detach", "--name", name,
                        "--network", network, "--network-alias", alias,
                        "--read-only", "--cap-drop", "all",
                        "--security-opt", "no-new-privileges",
                        "--user", "1001:1001", "--tmpfs", "/tmp",
                        "--env", "PYTHONDONTWRITEBYTECODE=1",
                        "--env", f"BACKEND_NAME={backend_name}",
                        *bind(backend, "/backend.py"),
                        MOCK_IMAGE, "python3", "/backend.py",
                    )

            run(
                ENGINE, "run", "--detach", "--name", classifier,
                "--network", network, "--network-alias", "llm-d-sc",
                "--read-only", "--cap-drop", "all",
                "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp",
                "--mount", f"type=volume,source={model_volume},target=/models,readonly",
                "--env", "LLM_D_SC_MODEL_DIR=/models",
                "--env", "LLM_D_SC_CLASSIFIER=complexity",
                "--env", "LLM_D_SC_LISTEN=0.0.0.0:50051",
                CLASSIFIER_IMAGE,
            )
            wait_for_classifier(classifier)

            run(
                ENGINE, "run", "--detach", "--name", praxis,
                "--network", network, "--network-alias", "praxis",
                "--read-only", "--cap-drop", "all",
                "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp",
                "--env", "PRAXIS_CONFIG=/etc/praxis/config.yaml",
                "--health-cmd", "wget -qO- http://127.0.0.1:9902/healthy || exit 1",
                *bind(ROOT / "configs/llm-d-sc/praxis.yaml", "/etc/praxis/config.yaml"),
                PRAXIS_IMAGE,
            )
            run(
                ENGINE, "run", "--detach", "--name", trace_ui,
                "--network", network, "--network-alias", "trace-ui",
                "--read-only", "--cap-drop", "all",
                "--security-opt", "no-new-privileges",
                "--user", "1001:1001", "--tmpfs", "/tmp",
                "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--env", "PRAXIS_UPSTREAM=http://praxis:8080",
                "--env", "TRACE_DB_PATH=/tmp/traces.db",
                *(["--env", f"GPU_UPSTREAM=http://{remote_gpu}:8000"] if remote_gpu else []),
                "--publish", "127.0.0.1::8080",
                *bind(ROOT / "apps/llm-d-sc/trace-ui/server.py", "/server.py"),
                MOCK_IMAGE, "python3", "/server.py",
            )
            port = run(ENGINE, "port", trace_ui, "8080/tcp").rsplit(":", 1)[1]
            wait_for_gateway(port)

            run(
                ENGINE, "volume", "create", webui_volume,
            )
            run(
                ENGINE, "run", "--detach", "--name", open_webui,
                "--network", network, "--network-alias", "open-webui",
                "--cap-drop", "all",
                "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp",
                "--env", "WEBUI_AUTH=false",
                "--env", "ENABLE_OLLAMA_API=false",
                "--env", "ENABLE_OPENAI_API=true",
                "--env", "ENABLE_BASE_MODELS_CACHE=false",
                "--env", "WEBUI_SECRET_KEY_FILE=/app/backend/data/.webui_secret_key",
                "--env", "OPENAI_API_BASE_URL=http://trace-ui:8080/v1",
                "--env", "OPENAI_API_KEY=llm-d-sc-test",
                "--env", "RAG_EMBEDDING_ENGINE=openai",
                "--env", "RAG_OPENAI_API_BASE_URL=http://trace-ui:8080/v1",
                "--env", "RAG_OPENAI_API_KEY=llm-d-sc-test",
                "--env", "ANONYMIZED_TELEMETRY=false",
                "--volume", f"{webui_volume}:/app/backend/data",
                "--publish", "127.0.0.1::8080",
                OPENWEBUI_IMAGE,
            )
            open_webui_port = run(
                ENGINE, "port", open_webui, "8080/tcp"
            ).rsplit(":", 1)[1]
            wait_for_http(open_webui_port, "/health")
            webui_token = webui_session(open_webui_port)
            webui_model_ids = webui_models(open_webui_port, webui_token)

            if real:
                simple_content = webui_request(
                    open_webui_port,
                    webui_token,
                    "What is the capital of France? Answer in one short sentence.",
                    max_tokens=32,
                    timeout=600,
                    chat_template_kwargs={"enable_thinking": False},
                )
                reasoning_content = raw_request(
                    port,
                    "Analyze a multi-step proof, identify every invalid inference, "
                    "and justify a corrected formal argument in one paragraph.",
                    chat_template_kwargs={"enable_thinking": False},
                )
                assert simple_content.strip(), "CPU generation returned empty content"
                assert reasoning_content.strip(), "GPU generation returned empty content"
                records = trace_records(port)
                simple = assert_trace(records, "SIMPLE", "vllm-cpu")
                reasoning = assert_trace(records, "REASONING", "vllm-gpu")
                simple["generation"] = "passed"
                reasoning["generation"] = "passed"
                result["routes"] = [simple, reasoning]
            else:
                simple = assert_route(
                    json.loads(webui_request(
                        open_webui_port,
                        webui_token,
                        "What is the capital of France?",
                    )),
                    "SIMPLE", "vllm-cpu", 0.99,
                )
                reasoning = assert_route(
                    request(
                        port,
                        "Analyze a multi-step proof, identify every invalid inference, "
                        "and justify a corrected formal argument.",
                    ),
                    "REASONING", "vllm-gpu", 0.99,
                )
                failover_response = request(
                    port,
                    "What is the capital of France?",
                    headers={"X-Test-Fail-Backend": "vllm-cpu"},
                )
                assert failover_response["backend"] == "vllm-gpu", (
                    f"expected failover to vllm-gpu, received "
                    f"{failover_response['backend']}"
                )
                failover = {
                    "label": failover_response["request_headers"].get(
                        "x-llm-d-sc-label"
                    ),
                    "backend": failover_response["backend"],
                }
                result["routes"] = [simple, reasoning, failover]
                records = trace_records(port)
                simple = assert_trace(records, "SIMPLE", "vllm-cpu")
                reasoning = assert_trace(records, "REASONING", "vllm-gpu")
                failover = assert_trace(records, None, "vllm-gpu", fallback=True)
                assert failover["fallback"], "failover response did not include fallback metadata"
                assert failover["hops"] == [
                    {"route": "vllm-cpu", "status": 503},
                    {"route": "vllm-gpu", "status": 200},
                ], f"unexpected failover trace: {failover['hops']}"
            result["traces"] = [simple, reasoning] + ([failover] if not real else [])
            result["trace_ui"] = {"url": f"http://127.0.0.1:{port}"}
            result["webui"] = {
                "url": f"http://127.0.0.1:{open_webui_port}",
                "health": "passed",
                "models": webui_model_ids,
                "chat": "passed",
            }
            if keep:
                result["resources"] = {
                    "prefix": prefix,
                    "network": network,
                    "cache_volume": cache_volume,
                    "model_volume": model_volume,
                    "webui_volume": webui_volume,
                }
            result["status"] = "passed"
            print(json.dumps(result, indent=2))
            return 0
        except Exception as error:
            result["status"] = "failed"
            result["error"] = str(error)
            diagnostics(praxis, classifier, trace_ui, open_webui,
                        cpu_backend, gpu_backend)
            print(json.dumps(result, indent=2), file=sys.stderr)
            return 1
        finally:
            if not keep:
                for container in (praxis, classifier, trace_ui, open_webui,
                                  cpu_backend, gpu_backend):
                    subprocess.run(
                        [ENGINE, "rm", "--force", container],
                        capture_output=True,
                        check=False,
                    )
                subprocess.run(
                    [ENGINE, "volume", "rm", model_volume],
                    capture_output=True,
                    check=False,
                )
                subprocess.run(
                    [ENGINE, "volume", "rm", webui_volume],
                    capture_output=True,
                    check=False,
                )
                if owns_cache_volume:
                    subprocess.run(
                        [ENGINE, "volume", "rm", cache_volume],
                        capture_output=True,
                        check=False,
                    )
                subprocess.run(
                    [ENGINE, "network", "rm", network],
                    capture_output=True,
                    check=False,
                )
            save("integration", result)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real", action="store_true",
                        help="run pinned Qwen CPU and GPU vLLM backends")
    parser.add_argument("--model", choices=("qwen3-8b", "qwen3.8-27b-int4"),
                        default="qwen3.8-27b-int4")
    parser.add_argument("--keep", action="store_true",
                        help="keep the successful stack for browser inspection")
    parser.add_argument("--remote-gpu", metavar="HOST",
                        help="use an existing real GPU backend at HOST:8000")
    parser.add_argument("--gpu-only", action="store_true",
                        help="start only the real GPU backend")
    parser.add_argument("--gpu-publish-host", default="127.0.0.1",
                        help="host address used by --gpu-only (default: loopback)")
    parser.add_argument("--cache-volume", dest="cache_volume_name",
                        help="reuse or create a named Podman cache volume")
    return parser.parse_args()


if __name__ == "__main__":
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise SystemExit("Run tests without Python -O/PYTHONOPTIMIZE")
    raise SystemExit(main(**vars(parse_args())))
