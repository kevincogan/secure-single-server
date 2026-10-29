#!/usr/bin/env python3
"""Private, deterministic OpenAI/Anthropic fixtures. No external dependencies.

Inference binds loopback by default. The separate control listener must never be
included in sandbox policies. Records retain booleans, never request headers.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

PATHS = ("/v1/chat/completions", "/v1/responses", "/v1/messages")
MODES = ("ok", "missing_usage", "http429", "http500", "timeout", "delayed", "cancelled")
ARGUMENTS = '{"a":2,"b":3}'


def openai_error(path, body):
    """Two cloud contracts missed by permissive mocks; not a full API validator."""
    if (path == '/v1/chat/completions' and 'max_tokens' in body
            and str(body.get('model', '')).startswith(('gpt-5', 'gpt-6'))):
        return {'message': "Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead.",
                'type': 'invalid_request_error', 'param': 'max_tokens', 'code': 'unsupported_parameter'}
    if path == '/v1/responses' and isinstance(body.get('input'), list):
        for index, item in enumerate(body['input']):
            if (isinstance(item, dict) and item.get('type') == 'reasoning'
                    and isinstance(item.get('content'), list) and item['content']):
                param = f'input[{index}].content'
                return {'message': f"Invalid '{param}': array too long. Expected maximum length 0.",
                        'type': 'invalid_request_error', 'param': param, 'code': 'array_above_max_length'}
    return None


def continuation(path, body):
    if path == "/v1/responses":
        items = body.get("input", [])
        return body.get("previous_response_id") == "resp_fixture" and isinstance(items, list) and any(
            i.get("type") == "function_call_output" and i.get("call_id") == "call_fixture"
            and i.get("output") == "5" for i in items)
    for item in body.get("messages", []):
        if item.get("role") == "tool" and item.get("tool_call_id") == "call_fixture":
            return item.get("content") == "5"
        content = item.get("content", [])
        if isinstance(content, list) and any(
            i.get("type") == "tool_result" and i.get("tool_use_id") == "call_fixture"
            and i.get("content") == "5" for i in content):
            return True
    return False


def completion(path, body, missing_usage=False, declared_tools_only=False):
    """Two input + three output tokens; add(2, 3), followed by result '5'."""
    continued = continuation(path, body)
    tool = bool(body.get("tools")) and not continued
    if declared_tools_only:
        # Interactive harnesses advertise their own tools. Never invent add()
        # unless it was declared; legacy protocol fixtures retain their mode.
        tool = tool and any(isinstance(item, dict) and (
            item.get('name') == 'add' or
            isinstance(item.get('function'), dict) and item['function'].get('name') == 'add'
        ) for item in body.get('tools', []))
    text = "5" if continued else "mock answer"
    model = body.get("model", "fixture")
    if path == "/v1/chat/completions":
        message = {"role": "assistant", "content": None if tool else text}
        if tool:
            message["tool_calls"] = [{"id": "call_fixture", "type": "function", "function": {
                "name": "add", "arguments": ARGUMENTS}}]
        result = {"id": "chatcmpl-fixture", "object": "chat.completion", "created": 1,
                  "model": model, "choices": [{"index": 0, "message": message,
                  "finish_reason": "tool_calls" if tool else "stop"}],
                  "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}
    elif path == "/v1/responses":
        output = {"id": "fc_fixture", "type": "function_call", "call_id": "call_fixture",
                  "name": "add", "arguments": ARGUMENTS, "status": "completed"} if tool else {
                  "id": "msg_fixture", "type": "message", "role": "assistant", "status": "completed",
                  "content": [{"type": "output_text", "text": text, "annotations": []}]}
        result = {"id": "resp_fixture_continued" if continued else "resp_fixture", "object": "response", "created_at": 1,
                  "status": "completed", "error": None, "incomplete_details": None,
                  "model": model, "output": [output], "parallel_tool_calls": False,
                  "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}}
    else:
        content = {"type": "tool_use", "id": "call_fixture", "name": "add",
                   "input": {"a": 2, "b": 3}} if tool else {"type": "text", "text": text}
        result = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": model,
                  "content": [content], "stop_reason": "tool_use" if tool else "end_turn",
                  "stop_sequence": None, "usage": {"input_tokens": 2, "output_tokens": 3}}
    if missing_usage:
        result.pop("usage")
    return result


def events(path, result):
    """Yield complete SSE frames, including the protocol's terminal event."""
    def frame(data, event=None):
        return ((f"event: {event}\n" if event else "") + "data: " +
                (data if isinstance(data, str) else json.dumps(data)) + "\n\n").encode()

    if path == "/v1/chat/completions":
        base = {k: result[k] for k in ("id", "created", "model")}
        base["object"] = "chat.completion.chunk"
        message = dict(result["choices"][0]["message"])
        if "tool_calls" in message:
            message["tool_calls"] = [{"index": 0, **message["tool_calls"][0]}]
        yield frame({**base, "choices": [{"index": 0, "delta": message, "finish_reason": None}]})
        yield frame({**base, "choices": [{"index": 0, "delta": {},
                    "finish_reason": result["choices"][0]["finish_reason"]}]})
        if "usage" in result:
            yield frame({**base, "choices": [], "usage": result["usage"]})
        yield frame("[DONE]")
    elif path == "/v1/responses":
        sequence = 0

        def response_event(kind, **data):
            nonlocal sequence
            data = {"type": kind, "sequence_number": sequence, **data}
            sequence += 1
            return frame(data, kind)

        initial = {key: value for key, value in result.items() if key != "usage"}
        yield response_event("response.created", response={**initial, "output": [], "status": "in_progress"})
        item = result["output"][0]
        tool = item["type"] == "function_call"
        initial = {**item, "status": "in_progress", **({"arguments": ""} if tool else {"content": []})}
        yield response_event("response.output_item.added", output_index=0, item=initial)
        if tool:
            yield response_event("response.function_call_arguments.delta", output_index=0,
                                 item_id=item["id"], delta=item["arguments"])
            yield response_event("response.function_call_arguments.done", output_index=0,
                                 item_id=item["id"], arguments=item["arguments"])
        else:
            part = item["content"][0]
            common = {"output_index": 0, "item_id": item["id"], "content_index": 0}
            yield response_event("response.content_part.added", **common, part={**part, "text": ""})
            yield response_event("response.output_text.delta", **common, delta=part["text"])
            yield response_event("response.output_text.done", **common, text=part["text"])
            yield response_event("response.content_part.done", **common, part=part)
        yield response_event("response.output_item.done", output_index=0, item=item)
        yield response_event("response.completed", response=result)
    else:
        initial = {**result, "content": [], "stop_reason": None}
        if "usage" in result:
            initial["usage"] = {"input_tokens": 2, "output_tokens": 0}
        yield frame({"type": "message_start", "message": initial}, "message_start")
        block = result["content"][0]
        tool = block["type"] == "tool_use"
        empty = {**block, **({"input": {}} if tool else {"text": ""})}
        yield frame({"type": "content_block_start", "index": 0, "content_block": empty}, "content_block_start")
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])} if tool else {
                 "type": "text_delta", "text": block["text"]}
        yield frame({"type": "content_block_delta", "index": 0, "delta": delta}, "content_block_delta")
        yield frame({"type": "content_block_stop", "index": 0}, "content_block_stop")
        final = {"type": "message_delta", "delta": {"stop_reason": result["stop_reason"], "stop_sequence": None}}
        if "usage" in result:
            final["usage"] = {"output_tokens": 3}
        yield frame(final, "message_delta")
        yield frame({"type": "message_stop"}, "message_stop")


class Provider:
    def __init__(self, ports=(18080, 18081, 19000), host="127.0.0.1", control_host="127.0.0.1",
                 openai_authorization="Bearer synthetic-openai", model="fixture", local=False, strict_openai=False,
                 declared_tools_only=False, request_backlog=5, record_limit=None):
        # None requires the local profile to remove Authorization completely.
        self.openai_authorization = openai_authorization
        self.model = model
        self.local = local
        self.strict_openai = strict_openai
        self.declared_tools_only = declared_tools_only
        self.records = []
        self.record_limit = record_limit
        self.mode = "ok"
        self.delay = 1.0
        self.lock = threading.Lock()
        self.servers = []
        self.threads = []
        for index, port in enumerate(ports):
            fixture = self

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

                def do_GET(self):
                    self.path = self.path.split("?", 1)[0]
                    if self.server.provider_index == 2:
                        if self.path == "/state":
                            with fixture.lock:
                                self.reply(200, {"records": list(fixture.records), "mode": fixture.mode})
                        else:
                            self.reply(404, {"error": "unsupported control path"})
                        return
                    self.record({})
                    if self.path == "/v1/models":
                        self.reply(200, {"object": "list", "data": [{"id": fixture.model, "object": "model"}]})
                    else:
                        self.reply(404, {"error": "unsupported path"})

                def reply(self, status, body):
                    data = json.dumps(body).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

                def record(self, body):
                    anthropic = self.path.startswith("/v1/messages") if fixture.local else self.server.provider_index == 1
                    credential_ok = (self.headers.get("x-api-key") is None and self.headers.get("Authorization") is None) if fixture.local else (
                                     (self.headers.get("x-api-key") == "synthetic-anthropic"
                                     and self.headers.get("Authorization") is None) if anthropic else (
                                     self.headers.get("Authorization") == fixture.openai_authorization))
                    clean = not any(self.headers.get(key) for key in
                                    ("X-Model", "X-Cluster", "X-Tier", "X-Selected-Model", "X-Route"))
                    with fixture.lock:
                        fixture.records.append({"path": self.path, "model": body.get("model"), "method": self.command,
                            "provider": "anthropic" if anthropic else "openai",
                            "credential_ok": credential_ok, "classification_clean": clean,
                            "stream": bool(body.get("stream")), "continuation": continuation(self.path, body)})
                        if isinstance(body.get('include_reasoning'), bool):
                            fixture.records[-1]['include_reasoning'] = body['include_reasoning']
                        if fixture.record_limit is not None:
                            del fixture.records[:-fixture.record_limit]
                    return credential_ok and clean

                def do_POST(self):
                    self.path = self.path.split("?", 1)[0]
                    try:
                        self.post()
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # Client cancellation is an intentional fixture case.

                def post(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    if length > 2 * 1024 * 1024:
                        return self.reply(413, {"error": "fixture request too large"})
                    body = json.loads(self.rfile.read(length) or b"{}")
                    if self.server.provider_index == 2:
                        if self.path != "/scenario" or body.get("mode", "ok") not in MODES:
                            return self.reply(400, {"error": "invalid scenario"})
                        with fixture.lock:
                            fixture.mode = body.get("mode", "ok")
                            fixture.delay = min(10, max(0, float(body.get("delay", 1))))
                            if body.get("reset"):
                                fixture.records.clear()
                        return self.reply(200, {"ok": True})
                    anthropic = self.path.startswith("/v1/messages") if fixture.local else self.server.provider_index == 1
                    valid = self.record(body)
                    with fixture.lock:
                        mode, delay = fixture.mode, fixture.delay
                    if not valid:
                        return self.reply(403, {"error": "credential or classification mismatch"})
                    error = openai_error(self.path, body) if fixture.strict_openai else None
                    if error:
                        return self.reply(400, {"error": error})
                    if fixture.local and body.get("model") != fixture.model:
                        return self.reply(404, {"error": "unknown local model"})
                    if self.path == "/v1/messages/count_tokens" and anthropic:
                        return self.reply(200, {"input_tokens": 2})
                    if self.path not in PATHS or (self.path == "/v1/messages") != anthropic:
                        return self.reply(404, {"error": "unsupported path"})
                    if mode in ("http429", "http500"):
                        return self.reply(int(mode[4:]), {"error": {"type": "fixture_error", "message": mode}})
                    if mode == "timeout":
                        time.sleep(delay)
                    if fixture.declared_tools_only:
                        result = completion(self.path, body, mode == "missing_usage", declared_tools_only=True)
                    else:
                        result = completion(self.path, body, mode == "missing_usage")
                    if not body.get("stream"):
                        return self.reply(200, result)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    for index, event in enumerate(events(self.path, result)):
                        if index and mode in ("delayed", "cancelled"):
                            time.sleep(delay)
                        if index and mode == "cancelled":
                            break
                        self.wfile.write(event)
                        self.wfile.flush()
                    self.close_connection = True

            class FixtureServer(ThreadingHTTPServer):
                request_queue_size = request_backlog

            server = FixtureServer((control_host if index == 2 else host, port), Handler)
            server.provider_index = index
            self.servers.append(server)
        self.ports = [server.server_port for server in self.servers]

    def start(self):
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--control-host", default="127.0.0.1")
    args = parser.parse_args()
    fixture = Provider(host=args.host, control_host=args.control_host)
    fixture.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        fixture.close()
