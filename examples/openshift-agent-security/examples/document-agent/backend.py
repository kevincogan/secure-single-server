# SPDX-License-Identifier: Apache-2.0
"""Separate HTTPS document fixture. Only the trusted host holds write credentials."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import sqlite3

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from agent_security_runtime import Denied, strict_json, prepare_storage
from contract import DOCUMENTS, normalize


class RevisionStore:
    """Append-only committed revisions, separate from the security run database."""

    def __init__(self, path):
        self.path = Path(path)
        try:
            prepare_storage(self.path)
        except ValueError as error:
            raise ValueError("Private backend storage required") from error
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS revisions (
                    reference TEXT PRIMARY KEY, operation TEXT NOT NULL UNIQUE,
                    effects TEXT NOT NULL, digest TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS immutable_update BEFORE UPDATE ON revisions
                    BEGIN SELECT RAISE(ABORT, 'immutable revision'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON revisions
                    BEGIN SELECT RAISE(ABORT, 'immutable revision'); END;
            """)
        self.path.chmod(0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def publish(self, effects):
        effects = normalize(effects)
        if "operation_id" not in effects:
            raise Denied("missing_operation")
        payload, digest = DOCUMENTS.canonical(effects)
        reference = effects["collection"] + "/runbook@" + str(effects["revision"])
        try:
            with self.connection() as db:
                db.execute("INSERT INTO revisions VALUES (?, ?, ?, ?)",
                    (reference, effects["operation_id"], payload, digest))
        except sqlite3.IntegrityError:
            raise Denied("immutable_revision") from None
        return reference

    def observe(self, reference):
        if (not isinstance(reference, str) or "/" not in reference
                or not DOCUMENTS.valid_scope(reference.split("/", 1)[0])):
            raise Denied("backend_reference")
        DOCUMENTS.check_reference(reference.split("/", 1)[0], reference)
        with self.connection() as db:
            row = db.execute("SELECT effects, digest FROM revisions WHERE reference = ?", (reference,)).fetchone()
        if row is None or DOCUMENTS.canonical(strict_json(row[0]))[1] != row[1]:
            raise Denied("backend_observation")
        return strict_json(row[0])

    def inventory(self):
        with self.connection() as db:
            return [{"reference": r, "operation_id": o, "digest": d}
                for r, o, d in db.execute("SELECT reference, operation, digest FROM revisions ORDER BY reference")]


def application(store, write_key, observe_key, *, lose_response_revision=None):
    if lose_response_revision not in (None, 3):
        raise ValueError("Only the bounded third synthetic revision may lose its response")
    if (not all(isinstance(k, str) and len(k) >= 32 for k in (write_key, observe_key))
            or secrets.compare_digest(write_key, observe_key)):
        raise ValueError("Distinct private write and read-only observation credentials required")

    def respond(status, value):
        return JSONResponse(value, status_code=status, headers={"Cache-Control": "no-store"})

    def authorized(request, expected):
        values = request.headers.getlist("authorization")
        return len(values) == 1 and secrets.compare_digest(values[0].encode(), ("Bearer " + expected).encode())

    async def read(request):
        if not (authorized(request, observe_key) or authorized(request, write_key)):
            return respond(403, {"error": "backend_credential"})
        try:
            if request.url.path == "/revisions":
                value = store.inventory()
            elif request.url.path.startswith("/revisions/"):
                value = store.observe(request.path_params["reference"])
            elif DOCUMENTS.valid_scope(request.path_params.get("collection")):
                value = {"instruction": "Record observations separately from hypotheses."}
            else:
                raise Denied("backend_resource")
            return respond(200, value)
        except (Denied, ValueError, TypeError):
            return respond(403, {"error": "backend_resource"})

    async def publish(request):
        if not authorized(request, write_key):
            return respond(403, {"error": "backend_credential"})
        try:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 16384:
                    raise Denied("backend_request")
            effects = strict_json(bytes(body))
            reference = store.publish(effects)
            if effects["revision"] == lose_response_revision:
                async def lost():
                    # Deliberate proof-fixture fault after durable commit. The
                    # client sees an incomplete response and must not retry.
                    yield b"{"
                    raise OSError("synthetic committed response loss")
                return StreamingResponse(lost(), status_code=201,
                    headers={"Content-Length": "100", "Cache-Control": "no-store"})
            return respond(201, {"reference": reference})
        except (Denied, ValueError, TypeError, KeyError):
            return respond(403, {"error": "backend_request"})

    return Starlette(routes=[Route("/revisions", read), Route("/revisions", publish, methods=["POST"]),
        Route("/revisions/{reference:path}", read), Route("/context/{collection}", read)])


def main():
    os.umask(0o077)
    config = strict_json(Path(os.environ["DOCUMENT_BACKEND_CONFIG"]).read_bytes())
    store = RevisionStore(config["database"])
    app = application(store,
        Path(config["write_key_file"]).read_text().strip(),
        Path(config["observe_key_file"]).read_text().strip(),
        lose_response_revision=config.get("lose_response_revision"))
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config["port"], ssl_certfile=config["certificate"],
        ssl_keyfile=config["private_key"], limit_concurrency=32, timeout_keep_alive=2, access_log=False)


if __name__ == "__main__":
    main()
