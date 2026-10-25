#!/usr/bin/env python3
"""Small OpenAI-compatible relay and trace dashboard for llm-d-sc."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import json
import os
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import Request, urlopen


DATABASE = Path(os.environ.get("TRACE_DB_PATH", "/tmp/traces.db"))
UPSTREAM = os.environ.get("PRAXIS_UPSTREAM", "http://praxis:8080").rstrip("/")
CPU_UPSTREAM = os.environ.get("CPU_UPSTREAM", "http://vllm-cpu:8000").rstrip("/")
GPU_UPSTREAM = os.environ.get("GPU_UPSTREAM", "http://vllm-gpu:8000").rstrip("/")
MAX_TRACES = int(os.environ.get("TRACE_MAX_TRACES", "250"))
RESPONSE_MAX_CHARS = int(os.environ.get("TRACE_RESPONSE_MAX_CHARS", "16000"))
DB_LOCK = threading.Lock()
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}
GPU_LABELS = {"COMPLEX", "REASONING"}
MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024


@contextmanager
def connection():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(DATABASE)
    try:
        with database:
            database.execute(
                """CREATE TABLE IF NOT EXISTS traces (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            request_id TEXT,
            status INTEGER,
            label TEXT,
            route TEXT,
            score TEXT,
            duration_ms INTEGER,
            error TEXT,
            question TEXT,
            fallback INTEGER NOT NULL DEFAULT 0,
            response TEXT,
            response_tokens INTEGER,
            response_tokens_est INTEGER,
            response_reasoning_tokens INTEGER
                )"""
            )
            database.execute(
                """CREATE TABLE IF NOT EXISTS hops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT NOT NULL,
            route TEXT NOT NULL,
            arrived_at REAL,
            ttfb_ms INTEGER,
            total_ms INTEGER,
            status INTEGER,
            classifier_us INTEGER,
            error TEXT
                )"""
            )
            for table, columns in (
                ("traces", (("fallback", "INTEGER NOT NULL DEFAULT 0"), ("response", "TEXT"),
                            ("response_tokens", "INTEGER"), ("response_tokens_est", "INTEGER"),
                            ("response_reasoning_tokens", "INTEGER"))),
                ("hops", (("arrived_at", "REAL"), ("ttfb_ms", "INTEGER"), ("total_ms", "INTEGER"),
                          ("classifier_us", "INTEGER"))),
            ):
                existing = {row[1] for row in database.execute(f"PRAGMA table_info({table})")}
                for column, kind in columns:
                    if column not in existing:
                        database.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
            yield database
    finally:
        database.close()


def create_trace(trace_id: str, method: str, path: str, question: str | None) -> None:
    started = datetime.now(timezone.utc).isoformat()
    with DB_LOCK, connection() as database:
        database.execute(
            """INSERT INTO traces
               (id, started_at, method, path, request_id, label, route, score,
                duration_ms, question)
               VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?)""",
            (trace_id, started, method, path, question),
        )


def note_route(trace_id: str, route: str, label: str | None, score: str | None) -> None:
    """Show the destination, label and score while the request is still in flight.

    The backend relay knows all three before the model answers. The first values
    win, so a failover shows the backend it tried first until the trace completes.
    """
    with DB_LOCK, connection() as database:
        database.execute(
            """UPDATE traces SET label = COALESCE(label, ?), route = COALESCE(route, ?),
               score = COALESCE(score, ?)
               WHERE id = ? AND completed_at IS NULL""",
            (label, route, score, trace_id),
        )


def record_hop(trace_id: str, route: str, label: str | None, status: int | None,
               error: str | None = None, score: str | None = None, *,
               arrived_at: float | None = None, ttfb_ms: int | None = None,
               total_ms: int | None = None, classifier_us: str | None = None) -> None:
    try:
        classifier = int(classifier_us) if classifier_us else None
    except ValueError:
        classifier = None
    with DB_LOCK, connection() as database:
        database.execute(
            """INSERT INTO hops (trace_id, route, arrived_at, ttfb_ms, total_ms, status,
                                 classifier_us, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (trace_id, route, arrived_at, ttfb_ms, total_ms, status, classifier, error),
        )
        database.execute(
            """UPDATE traces SET label = COALESCE(label, ?), route = COALESCE(route, ?),
               score = COALESCE(score, ?)
               WHERE id = ? AND completed_at IS NULL""",
            (label, route, score, trace_id),
        )


def complete_trace(trace_id: str, status: int | None, headers, duration_ms: int,
                   error: str | None = None,
                   response: tuple[str | None, int | None, bool, int | None] = (None, None, False, None),
                   ) -> None:
    response_text, response_tokens, tokens_estimated, response_reasoning = response
    completed = datetime.now(timezone.utc).isoformat()
    lowered = {key.lower(): value for key, value in headers.items()} if headers else {}
    request_id = lowered.get("x-request-id")
    label = lowered.get("x-demo-classification")
    route = lowered.get("x-demo-route")
    score = lowered.get("x-llm-d-sc-score")
    fallback = lowered.get("x-praxis-fallback", "").lower() in {"true", "1", "yes"}
    with DB_LOCK, connection() as database:
        if label is None or route is None or score is None:
            saved = database.execute(
                "SELECT label, route, score FROM traces WHERE id = ?", (trace_id,)
            ).fetchone()
            if saved:
                label = label or saved[0]
                route = route or saved[1]
                score = score or saved[2]
        if route is None and label:
            route = "vllm-gpu" if label.upper() in GPU_LABELS else "vllm-cpu"
        if label and route and (label.upper() in GPU_LABELS) != ("gpu" in route.lower()):
            fallback = True
        database.execute(
            """UPDATE traces SET completed_at = ?, request_id = ?, status = ?,
               label = ?, route = ?, score = ?, duration_ms = ?, error = ?,
               fallback = ?, response = ?, response_tokens = ?, response_tokens_est = ?,
               response_reasoning_tokens = ?
               WHERE id = ?""",
            (completed, request_id, status, label, route, score, duration_ms,
             error, int(fallback), response_text, response_tokens,
             int(tokens_estimated), response_reasoning, trace_id),
        )
        if MAX_TRACES >= 0:
            database.execute(
                """DELETE FROM traces WHERE id NOT IN (
                       SELECT id FROM traces ORDER BY started_at DESC LIMIT ?
                   )""",
                (MAX_TRACES,),
            )
            database.execute("DELETE FROM hops WHERE trace_id NOT IN (SELECT id FROM traces)")


def traces() -> list[dict[str, object]]:
    with DB_LOCK, connection() as database:
        database.row_factory = sqlite3.Row
        rows = database.execute(
            "SELECT * FROM traces ORDER BY started_at DESC LIMIT ?",
            (MAX_TRACES if MAX_TRACES >= 0 else -1,),
        ).fetchall()
        hops = database.execute(
            """SELECT trace_id, route, arrived_at, ttfb_ms, total_ms, status,
                      classifier_us, error FROM hops ORDER BY id"""
        ).fetchall()
    result = [dict(row, hops=[]) for row in rows]
    by_id = {row["id"]: row for row in result}
    for hop in hops:
        trace = by_id.get(hop["trace_id"])
        if trace is None:
            continue
        started = datetime.fromisoformat(trace["started_at"]).timestamp()
        arrived = hop["arrived_at"]
        classifier = hop["classifier_us"]
        trace["hops"].append({
            "route": hop["route"],
            "offset_ms": round((arrived - started) * 1000) if arrived is not None else None,
            "ttfb_ms": hop["ttfb_ms"],
            "total_ms": hop["total_ms"],
            "status": hop["status"],
            "classifier_ms": round(classifier / 1000) if classifier is not None else None,
            "error": hop["error"],
        })
    for row in result:
        if len({hop["route"] for hop in row["hops"]}) > 1:
            row["fallback"] = 1
    return result


def clear_traces() -> None:
    with DB_LOCK, connection() as database:
        database.execute("DELETE FROM traces")
        database.execute("DELETE FROM hops")


def question_from(body: bytes) -> str | None:
    try:
        messages = json.loads(body or b"{}").get("messages", [])
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return None
    for message in reversed(messages if isinstance(messages, list) else []):
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content.strip()[:RESPONSE_MAX_CHARS]
        if isinstance(content, list):
            parts = [
                item.get("text", "").strip()
                for item in content
                if isinstance(item, dict) and isinstance(item.get("text"), str)
            ]
            if parts:
                return "\n".join(parts)[:RESPONSE_MAX_CHARS]
    return None


def with_usage(body: bytes) -> bytes:
    try:
        request = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(request, dict) or request.get("stream") is not True:
        return body
    options = request.get("stream_options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or "include_usage" in options:
        return body
    request["stream_options"] = {**options, "include_usage": True}
    return json.dumps(request).encode()


def reasoning_tokens(usage) -> int | None:
    details = usage.get("completion_tokens_details") if isinstance(usage, dict) else None
    value = details.get("reasoning_tokens") if isinstance(details, dict) else None
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def extract_response(path: str, headers, raw: bytes
                     ) -> tuple[str | None, int | None, bool, int | None]:
    none = (None, None, False, None)
    if path.split("?", 1)[0] != "/v1/chat/completions" or not raw:
        return none
    lowered = {key.lower(): value for key, value in headers.items()}
    if lowered.get("content-encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError):
            return none
    text = raw.decode("utf-8", errors="replace")
    answer = None
    tokens = None
    thinking = None
    try:
        body = json.loads(text)
        message = body["choices"][0]["message"]
        answer = message.get("content")
        if not answer and message.get("tool_calls"):
            answer = json.dumps(message["tool_calls"])
        usage = body.get("usage")
        if isinstance(usage, dict):
            tokens = usage.get("completion_tokens")
            thinking = reasoning_tokens(usage)
    except (json.JSONDecodeError, KeyError, IndexError, TypeError, AttributeError):
        parts = []
        for line in text.splitlines():
            if not line.startswith("data:") or line[5:].strip() == "[DONE]":
                continue
            try:
                chunk = json.loads(line[5:])
            except json.JSONDecodeError:
                continue
            if not isinstance(chunk, dict):
                continue
            usage = chunk.get("usage")
            if isinstance(usage, dict) and usage.get("completion_tokens") is not None:
                tokens = usage["completion_tokens"]
                thinking = reasoning_tokens(usage)
            try:
                delta = chunk["choices"][0].get("delta", {})
            except (KeyError, IndexError, TypeError, AttributeError):
                continue
            if isinstance(delta.get("content"), str):
                parts.append(delta["content"])
        answer = "".join(parts)
    exact = isinstance(tokens, int) and not isinstance(tokens, bool) and tokens > 0
    answer = answer.strip() if isinstance(answer, str) else ""
    if not answer:
        return (None, tokens, False, thinking) if exact else none
    if not exact:
        tokens, thinking = max(1, round(len(answer) / 4)), None
    if len(answer) > RESPONSE_MAX_CHARS:
        answer = answer[:RESPONSE_MAX_CHARS] + "…"
    return answer, tokens, not exact, thinking


PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>llm-d-sc routing traces</title>
  <style>
    :root { color-scheme: dark; --muted: #9ca3af; --blue: #93c5fd; --amber: #fbbf24; }
    body { margin: 2rem; font: 15px/1.5 system-ui, sans-serif; background: #111827; color: #e5e7eb; }
    h1 { margin: 0 0 .75rem; font-size: 1.5rem; }
    h1 small { margin-left: .4rem; font-size: .8rem; font-weight: 400; color: var(--muted); }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #374151; padding: .5rem; text-align: left; vertical-align: top; }
    th { background: #1f2937; }
    code { color: var(--blue); }
    .failover { color: var(--amber); font-weight: 600; }
    .muted { color: var(--muted); font-size: 12px; }
    tbody tr[data-trace-id] { cursor: pointer; }
    tbody tr[data-trace-id]:hover { background: #1a2332; }
    tbody tr.selected-row, tbody tr.selected-row:hover { background: #1e3a5f; }
    tbody tr.selected-row td:first-child { box-shadow: inset 3px 0 0 #60a5fa; }
    .detail-row td { padding: .6rem .8rem; background: #0f172a; border-top: 0; cursor: default; }
    .chip { margin-left: .4rem; padding: 1px 8px; border: 1px solid #4b5563; border-radius: 7px;
            background: #1f2937; color: var(--blue); font: inherit; font-size: 12px; cursor: pointer; white-space: nowrap; }
    .chip:hover { background: #273449; }
    td.nowrap { white-space: nowrap; }
    .tl { display: flex; height: 10px; margin: 2px 0 8px; border-radius: 4px; overflow: hidden; background: #13243a; }
    .tl i { min-width: 2px; }
    .tl-line { display: block; color: var(--muted); font-size: 13px; }
    .tl-line b { color: #e5e7eb; }
    .sw { display: inline-block; width: 9px; height: 9px; margin-right: 6px; border-radius: 2px; }
    .k-classify { background: #ad9cff; }
    .k-praxis { background: #64b5ff; }
    .k-backend { background: #55e6d0; }
    .k-fail { background: #f87171; }
    .k-gap { background: #ffc76a; }
    .drawer-backdrop { position: fixed; inset: 0; z-index: 20; background: #02071199; opacity: 0;
                       pointer-events: none; transition: opacity .2s; }
    .drawer-backdrop.open { opacity: 1; pointer-events: auto; }
    .drawer { position: fixed; top: 0; right: 0; z-index: 21; width: min(480px, 92vw); height: 100vh;
              padding: 26px; background: #0b1929; border-left: 1px solid #31516f;
              box-shadow: -24px 0 70px #0009; transform: translateX(102%);
              transition: transform .24s ease; overflow: auto; }
    .drawer.open { transform: translateX(0); }
    .drawer-header { display: flex; align-items: center; justify-content: space-between; gap: 16px;
                     padding-bottom: 18px; border-bottom: 1px solid #203b55; }
    .drawer-header h2 { margin: 0; font-size: 21px; }
    .drawer-close { width: 36px; height: 36px; padding: 0; border: 1px solid #4b5563; border-radius: 8px;
                    background: #1f2937; color: inherit; font-size: 22px; cursor: pointer; }
    .drawer-meta { margin: 16px 0; color: var(--muted); font-size: 12px; }
    .drawer-text { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.55; }
    @media (prefers-reduced-motion: reduce) { .drawer, .drawer-backdrop { transition: none; } }
  </style>
</head>
<body>
  <h1>llm-d-sc routing traces <small id="count"></small></h1>
  <table>
    <thead><tr><th>Started</th><th>Request</th><th>Label</th><th>Route</th><th>Score</th><th>Status</th><th>ms</th><th>Response</th></tr></thead>
    <tbody id="traces"><tr><td colspan="8">Loading…</td></tr></tbody>
  </table>
  <div id="drawer-backdrop" class="drawer-backdrop"></div>
  <aside id="drawer" class="drawer" aria-hidden="true" aria-labelledby="drawer-title">
    <div class="drawer-header"><h2 id="drawer-title">Question</h2><button id="drawer-close" class="drawer-close" type="button" aria-label="Close">×</button></div>
    <div id="drawer-meta" class="drawer-meta"></div>
    <p id="drawer-text" class="drawer-text"></p>
  </aside>
<script>
const $ = id => document.getElementById(id);
const esc = x => String(x ?? '—').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const drawer = $('drawer'), backdrop = $('drawer-backdrop');
const openTraces = new Set();
let traceItems = [], selectedId = '', last = '';

function timelineHtml(t) {
  const hops = t.hops || [];
  if (!hops.length || !t.duration_ms) return '<span class="tl-line">No timing recorded yet.</span>';
  const segs = [];
  let cursor = 0;
  hops.forEach((h, i) => {
    const offset = h.offset_ms ?? cursor;
    const gap = Math.max(0, offset - cursor);
    if (i === 0) {
      const c = h.classifier_ms != null ? Math.min(h.classifier_ms, gap) : 0;
      if (c) segs.push({k: 'classify', l: 'classifier', ms: c});
      segs.push({k: 'praxis', l: c ? 'Praxis' : 'Praxis + classifier', ms: gap - c});
    } else {
      segs.push({k: 'gap', l: 'failover gap', ms: gap});
    }
    const bad = h.status == null || h.status >= 500 || h.status === 429;
    segs.push({k: bad ? 'fail' : 'backend', l: h.route + (bad ? ' (failed)' : ''), ms: h.total_ms || 0,
               note: h.ttfb_ms != null ? 'first byte ' + h.ttfb_ms + ' ms' : (h.error || 'no response')});
    cursor = offset + (h.total_ms || 0);
  });
  segs.push({k: 'praxis', l: 'Praxis return', ms: Math.max(0, t.duration_ms - cursor)});
  const bar = segs.map(x => `<i class="k-${x.k}" style="flex:${Math.max(x.ms, 0)}" title="${esc(x.l)} ${x.ms} ms"></i>`).join('');
  const lines = segs.map(x => `<span class="tl-line"><i class="sw k-${x.k}"></i>${esc(x.l)} <b>${x.ms} ms</b>${x.note ? ' · ' + esc(x.note) : ''}</span>`).join('');
  const error = t.error ? `<span class="tl-line"><b>Error:</b> ${esc(t.error)}</span>` : '';
  return `<div class="tl">${bar}</div>${lines}${error}`;
}

function rowHtml(t) {
  const isChat = String(t.path).split('?')[0] === '/v1/chat/completions';
  const open = isChat && openTraces.has(t.id);
  const question = t.question
    ? `<button class="chip" type="button" data-question-id="${esc(t.id)}">View question</button>`
    : '<span class="muted"> question unavailable</span>';
  const trace = isChat
    ? `<button class="chip" type="button" data-trace-toggle="${esc(t.id)}" aria-expanded="${open}">Trace ${open ? '▴' : '▾'}</button>`
    : '';
  const thinking = !t.response_tokens_est && t.response_reasoning_tokens ? ` (${esc(t.response_reasoning_tokens)} thinking)` : '';
  const tokens = t.response || t.response_tokens
    ? `<button class="chip" type="button" data-response-id="${esc(t.id)}">${t.response_tokens ? (t.response_tokens_est ? '~' : '') + esc(t.response_tokens) + ' tokens' + thinking : 'View'}</button>`
    : '<span class="muted">—</span>';
  const failover = t.fallback ? ' <small class="failover">failover</small>' : '';
  const main = `<tr data-trace-id="${esc(t.id)}" class="${t.id === selectedId ? 'selected-row' : ''}">`
    + `<td class="nowrap">${esc(new Date(t.started_at).toLocaleTimeString())}</td>`
    + `<td><code>${esc(t.method)}</code> ${esc(t.path)} ${question} ${trace}</td>`
    + `<td>${esc(t.label ?? '')}</td>`
    + `<td>${esc(t.route ?? '')}${failover}</td>`
    + `<td>${esc(t.score ?? '')}</td>`
    + `<td>${esc(t.status ?? 'in flight')}</td>`
    + `<td>${t.duration_ms != null ? esc(t.duration_ms) : '—'}</td>`
    + `<td class="nowrap">${tokens}</td></tr>`;
  const detail = open ? `<tr class="detail-row"><td colspan="8">${timelineHtml(t)}</td></tr>` : '';
  return main + detail;
}

function render() {
  $('count').textContent = `(${traceItems.length} saved)`;
  $('traces').innerHTML = traceItems.length
    ? traceItems.map(rowHtml).join('')
    : '<tr><td colspan="8">No requests recorded.</td></tr>';
}

function syncSelection() {
  document.querySelectorAll('tr[data-trace-id]').forEach(row =>
    row.classList.toggle('selected-row', row.dataset.traceId === selectedId));
}

function selectTrace(id) {
  selectedId = selectedId === id ? '' : id;
  syncSelection();
}

function toggleTrace(id) {
  if (openTraces.has(id)) openTraces.delete(id); else openTraces.add(id);
  selectedId = id;
  render();
}

function openDrawer(id, field, title) {
  const t = traceItems.find(item => item.id === id);
  if (!t) return;
  let text = t[field];
  if (!text && field === 'response' && t.response_tokens) {
    text = t.response_reasoning_tokens >= t.response_tokens
      ? `No answer text was returned: all ${t.response_tokens} tokens were thinking, so there is no answer to show.`
      : 'No answer text was returned.';
  }
  if (!text) return;
  selectedId = id;
  syncSelection();
  $('drawer-title').textContent = title;
  $('drawer-meta').textContent = `${new Date(t.started_at).toLocaleString()} · trace ${t.id.slice(0, 8)}`;
  $('drawer-text').textContent = text;
  drawer.classList.add('open');
  backdrop.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  $('drawer-close').focus();
}

function closeDrawer() {
  drawer.classList.remove('open');
  backdrop.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
}

async function load() {
  try {
    const data = await fetch('/_trace/api/traces', {cache: 'no-store'}).then(r => r.json());
    traceItems = data.traces;
    const key = traceItems.map(t => [t.id, t.status, t.label, t.route, t.score, t.fallback,
                                     t.duration_ms, t.hops.length, t.response_tokens ?? 0, t.response_reasoning_tokens ?? 0].join(':')).join();
    if (key !== last) { last = key; render(); }
  } catch (e) {
    $('traces').innerHTML = '<tr><td colspan="8">Trace API unavailable.</td></tr>';
    last = '';
  }
}

$('traces').addEventListener('click', event => {
  const question = event.target.closest('[data-question-id]');
  if (question) { openDrawer(question.dataset.questionId, 'question', 'Question'); return; }
  const answer = event.target.closest('[data-response-id]');
  if (answer) { openDrawer(answer.dataset.responseId, 'response', 'Response'); return; }
  const toggle = event.target.closest('[data-trace-toggle]');
  if (toggle) { toggleTrace(toggle.dataset.traceToggle); return; }
  if (event.target.closest('.detail-row')) return;
  const row = event.target.closest('tr[data-trace-id]');
  if (row) selectTrace(row.dataset.traceId);
});
document.addEventListener('click', event => {
  if (!selectedId || event.target.closest('tr[data-trace-id]') || event.target.closest('.detail-row') || event.target.closest('#drawer')) return;
  selectedId = '';
  syncSelection();
});
$('drawer-close').addEventListener('click', closeDrawer);
backdrop.addEventListener('click', closeDrawer);
document.addEventListener('keydown', event => { if (event.key === 'Escape' && drawer.classList.contains('open')) closeDrawer(); });

load();
setInterval(load, 2000);
</script>
</body>
</html>
"""


def dashboard() -> bytes:
    return PAGE.encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "llm-d-sc-trace-ui/1"

    def log_message(self, format_string, *args):
        print(json.dumps({"event": "http", "message": format_string % args}), flush=True)

    def send_bytes(self, status: int, content_type: str, body: bytes,
                   extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.send_bytes(200, "text/html; charset=utf-8", dashboard())
            return
        if self.path == "/_trace/api/traces":
            body = json.dumps({"traces": traces()}, separators=(",", ":")).encode()
            self.send_bytes(200, "application/json", body)
            return
        self.relay("GET")

    def do_POST(self):
        self.relay("POST")

    def do_DELETE(self):
        if self.path == "/_trace/api/traces":
            clear_traces()
            self.send_bytes(200, "application/json", b'{"status":"cleared"}')
            return
        self.relay("DELETE")

    def do_PUT(self):
        self.relay("PUT")

    def do_PATCH(self):
        self.relay("PATCH")

    def relay(self, method: str):
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_bytes(400, "application/json",
                            b'{"error":"invalid request target"}')
            return
        trace_id = uuid.uuid4().hex
        raw_length = self.headers.get("Content-Length", "0")
        if not raw_length.isascii() or not raw_length.isdigit():
            self.send_bytes(400, "application/json", b'{"error":"invalid Content-Length"}')
            return
        normalized_length = raw_length.lstrip("0") or "0"
        limit = str(MAX_REQUEST_BODY_BYTES)
        if (len(normalized_length) > len(limit)
                or (len(normalized_length) == len(limit) and normalized_length > limit)):
            self.send_bytes(413, "application/json", b'{"error":"request body too large"}')
            return
        length = int(normalized_length)
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self.send_bytes(400, "application/json", b'{"error":"incomplete request body"}')
            return
        if self.server.route is None and self.path.startswith("/ws/"):
            self.send_bytes(404, "application/json", b'{"error":"not found"}')
            return
        question = question_from(body) if self.path.startswith("/v1/chat/completions") else None
        if (self.server.route is None and method == "POST"
                and self.path.split("?", 1)[0] == "/v1/chat/completions"):
            body = with_usage(body)
        if self.server.route is None:
            create_trace(trace_id, method, self.path, question)
        started = time.monotonic()
        headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP
        }
        path, hop_trace_id, hop_recorded = self.path, None, False
        if self.server.route is None and method == "POST":
            path += ("&" if "?" in path else "?") + "_trace=" + trace_id
        elif self.server.route is not None and "_trace=" in path:
            parts = urlsplit(path)
            query = parse_qsl(parts.query, keep_blank_values=True)
            hop_trace_id = next((value for key, value in reversed(query) if key == "_trace"), None)
            query = [(key, value) for key, value in query if key != "_trace"]
            path = parts.path + ("?" + urlencode(query) if query else "")
        request = Request(
            self.server.upstream + path,
            data=body if method != "GET" else None,
            headers=headers,
            method=method,
        )
        arrived_at = time.time()
        classifier_us = self.headers.get("X-Llm-D-Sc-Latency-Us")

        def elapsed_ms():
            return round((time.monotonic() - started) * 1000)

        trace_completed = False
        if hop_trace_id:
            note_route(hop_trace_id, self.server.route,
                       self.headers.get("X-Llm-D-Sc-Label"), self.headers.get("X-Llm-D-Sc-Score"))

        response_started = False
        try:
            with urlopen(request, timeout=600) as response:
                ttfb_ms = elapsed_ms()
                response_headers = {
                    key: value for key, value in response.headers.items()
                    if key.lower() not in HOP_BY_HOP
                }
                classification = None
                score = None
                if self.server.route is not None:
                    response_headers["X-Demo-Route"] = self.server.route
                    classification = self.headers.get("X-Llm-D-Sc-Label")
                    if classification:
                        response_headers["X-Demo-Classification"] = classification
                    score = self.headers.get("X-Llm-D-Sc-Score")
                    if score:
                        response_headers["X-Llm-D-Sc-Score"] = score

                streaming = "text/event-stream" in response_headers.get(
                    "Content-Type", ""
                ).lower()
                if streaming:
                    self.send_response(response.status)
                    for key, value in response_headers.items():
                        self.send_header(key, value)
                    # The handler uses HTTP/1.0, so a closed connection frames
                    # the stream without buffering it or inventing a length.
                    self.send_header("Connection", "close")
                    self.close_connection = True
                    self.end_headers()
                    response_started = True

                    chunks = []
                    client_disconnected = False
                    while chunk := response.read1(65536):
                        chunks.append(chunk)
                        if not client_disconnected:
                            try:
                                self.wfile.write(chunk)
                                self.wfile.flush()
                            except OSError:
                                client_disconnected = True
                    response_body = b"".join(chunks)
                else:
                    response_body = response.read()

                if self.server.route is not None:
                    if hop_trace_id:
                        record_hop(hop_trace_id, self.server.route, classification,
                                   response.status, score=score, arrived_at=arrived_at,
                                   ttfb_ms=ttfb_ms, total_ms=elapsed_ms(),
                                   classifier_us=classifier_us)
                        hop_recorded = True
                else:
                    complete_trace(trace_id, response.status, response_headers,
                                   int((time.monotonic() - started) * 1000),
                                   response=extract_response(self.path, response_headers,
                                                             response_body))
                    trace_completed = True
                if not streaming:
                    response_started = True
                    self.send_response(response.status)
                    for key, value in response_headers.items():
                        self.send_header(key, value)
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body)
        except HTTPError as error:
            ttfb_ms = elapsed_ms()
            try:
                response_body = error.read()
            except IncompleteRead:
                message = f"{error}; upstream response ended early"
                error.close()
                if self.server.route is None:
                    complete_trace(trace_id, 502, {}, elapsed_ms(), message)
                    trace_completed = True
                elif hop_trace_id:
                    record_hop(hop_trace_id, self.server.route,
                               self.headers.get("X-Llm-D-Sc-Label"), error.code,
                               message, self.headers.get("X-Llm-D-Sc-Score"),
                               arrived_at=arrived_at, ttfb_ms=ttfb_ms,
                               total_ms=elapsed_ms(), classifier_us=classifier_us)
                if not response_started:
                    self.send_bytes(502, "application/json",
                                    b'{"error":"upstream response ended early"}')
                return
            error.close()
            if self.server.route is None:
                complete_trace(trace_id, error.code, error.headers,
                               int((time.monotonic() - started) * 1000), str(error))
                trace_completed = True
            elif hop_trace_id:
                record_hop(hop_trace_id, self.server.route,
                           self.headers.get("X-Llm-D-Sc-Label"), error.code, str(error),
                           self.headers.get("X-Llm-D-Sc-Score"), arrived_at=arrived_at,
                           ttfb_ms=ttfb_ms, total_ms=elapsed_ms(), classifier_us=classifier_us)
            self.send_bytes(error.code, error.headers.get_content_type(),
                            response_body)
        except IncompleteRead:
            message = "upstream response ended early"
            if self.server.route is None:
                complete_trace(trace_id, 502, {}, elapsed_ms(), message)
                trace_completed = True
            elif hop_trace_id and not hop_recorded:
                record_hop(hop_trace_id, self.server.route,
                           self.headers.get("X-Llm-D-Sc-Label"), None, message,
                           self.headers.get("X-Llm-D-Sc-Score"), arrived_at=arrived_at,
                           total_ms=elapsed_ms(), classifier_us=classifier_us)
            if not response_started:
                self.send_bytes(502, "application/json",
                                b'{"error":"upstream response ended early"}')
        except (OSError, URLError) as error:
            if self.server.route is None and not trace_completed:
                complete_trace(trace_id, None, {},
                               int((time.monotonic() - started) * 1000), str(error))
            elif hop_trace_id and not hop_recorded:
                record_hop(hop_trace_id, self.server.route,
                           self.headers.get("X-Llm-D-Sc-Label"), None, str(error),
                           self.headers.get("X-Llm-D-Sc-Score"), arrived_at=arrived_at,
                           total_ms=elapsed_ms(), classifier_us=classifier_us)
            if not response_started:
                self.send_bytes(502, "application/json",
                                json.dumps({"error": "upstream unavailable"}).encode())


class RelayServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], upstream: str,
                 route: str | None = None):
        super().__init__(address, Handler)
        self.upstream = upstream
        self.route = route


if __name__ == "__main__":
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise SystemExit("Run without Python -O/PYTHONOPTIMIZE")
    with connection():
        pass
    for port, upstream, route in (
        (8081, CPU_UPSTREAM, "vllm-cpu"),
        (8082, GPU_UPSTREAM, "vllm-gpu"),
    ):
        threading.Thread(
            target=RelayServer(("0.0.0.0", port), upstream, route).serve_forever,
            daemon=True,
        ).start()
    RelayServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), UPSTREAM).serve_forever()
