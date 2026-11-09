# SPDX-License-Identifier: Apache-2.0
"""Protected adapter HTTP operations; no presentation dependencies."""
from __future__ import annotations
import hashlib
import time
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from identity_demo_run_store import Denied, create_call, read_call, strict_json
import identity_demo_http as http

async def history_ticket(self, request: Request) -> Response:
    """A one-use historical read capability grants no execution or mutation."""
    http.internal(request, self.config.adapter_secret)
    data = strict_json(await self.body(request, 1024))
    if set(data) != {'decision_ticket'} or not isinstance(data['decision_ticket'], str):
        raise Denied('history_ticket')
    ticket = self.tickets.get(data['decision_ticket'])
    if not ticket or ticket.get('purpose') != 'history' or ticket['expires'] <= time.time():
        raise Denied('history_ticket')
    del self.tickets[data['decision_ticket']]
    return JSONResponse({'allowed': True, 'issue_key': ticket['issue_key']},
                        headers={'Cache-Control': 'no-store'})


async def observation_ticket(self, request: Request) -> Response:
    from identity_demo_backend_observation import redeem
    return await redeem(self, request)


async def authorize(self, request: Request) -> Response:
    """Authorize the actual body from the gateway; do not consume approval."""
    http.internal(request, self.config.gateway_secret)
    context = strict_json(await self.body(request))
    return JSONResponse(await self.context_decision(context))


async def identity(self, request: Request) -> Response:
    """Check live identity before MCP routing; writes still require full body authorization."""
    http.internal(request, self.config.gateway_secret)
    context = strict_json(await self.body(request))
    return JSONResponse(await self.context_decision(context, identity_only=True))


async def adapter_ticket(self, request: Request) -> tuple[dict, str]:
    """Resolve an expiring decision and match the actual upstream body."""
    http.internal(request, self.config.adapter_secret)
    data = await http.json_fields(self, request, {'decision_ticket', 'actual_body'},
        limit=65_536, reason='adapter_fields')
    if not isinstance(data["decision_ticket"], str):
        raise Denied("decision_expired")
    ticket = self.tickets.get(data["decision_ticket"])
    if ticket is None or ticket.get('purpose') is not None or ticket["expires"] <= time.time():
        raise Denied("decision_expired")
    body = data["actual_body"]
    if not isinstance(body, str):
        raise Denied("complete_body_required")
    if hashlib.sha256(body.encode()).hexdigest() != ticket["body_hash"]:
        raise Denied("action_binding")
    return ticket, body


async def claim(self, request: Request) -> Response:
    """Claim a verified create without passing human tokens to the adapter."""
    ticket, body = await adapter_ticket(self, request)
    run, action, arguments = create_call(body.encode(), tool_name="createJiraIssue")
    if run != ticket["run"] or action != ticket["action"]:
        raise Denied("action_binding")
    return JSONResponse(
        self.store.decision(
            run, action, ticket["user"], ticket["workload"], arguments, claim=True
        )
    )


async def preview(self, request: Request) -> Response:
    """Recheck an approved create at the adapter without claiming or writing."""
    ticket, body = await adapter_ticket(self, request)
    run, action, arguments = create_call(body.encode(), tool_name="createJiraIssue")
    if run != ticket["run"] or action != ticket["action"]:
        raise Denied("action_binding")
    return JSONResponse(
        self.store.decision(
            run, action, ticket["user"], ticket["workload"], arguments
        )
    )


async def adapter_read(self, request: Request) -> Response:
    """Recheck project permission and cancellation before returning backend data."""
    ticket, body = await adapter_ticket(self, request)
    run, project, _ = read_call(body.encode(), tool_name="readJiraProject")
    if run != ticket["run"] or ticket["action"] is not None:
        raise Denied("action_binding")
    return JSONResponse(
        self.store.read_decision(
            run, ticket["user"], ticket["workload"], project, ticket["body_hash"]
        )
    )


async def finish(self, request: Request) -> Response:
    """Only the scoped adapter may record a claimed backend result."""
    http.internal(request, self.config.adapter_secret)
    data = await http.json_fields(self, request, {'run_id', 'action_id', 'execution_id', 'state', 'issue_key'},
        limit=8192, reason='adapter_fields')
    self.store.finish(
        data["run_id"],
        data["action_id"],
        data["execution_id"],
        state=data["state"],
        issue_key=data["issue_key"],
    )
    return JSONResponse({"recorded": True})


async def reconciliation(self, request: Request) -> Response:
    """Allow only the scoped trusted adapter to inspect uncertain dispatch state."""
    http.internal(request, self.config.adapter_secret)
    data = await http.json_fields(self, request, {'run_id', 'action_id'},
        limit=8192, reason='adapter_fields')
    return JSONResponse(
        self.store.reconciliation(data["run_id"], data["action_id"])
    )


async def reconcile(self, request: Request) -> Response:
    """Record a positive backend read; cancellation never authorizes another write."""
    http.internal(request, self.config.adapter_secret)
    data = await http.json_fields(self, request, {'run_id', 'action_id', 'execution_id', 'issue_key', 'arguments'},
        limit=16384, reason='adapter_fields')
    self.store.reconcile(
        data["run_id"],
        data["action_id"],
        data["execution_id"],
        data["issue_key"],
        data["arguments"],
    )
    return JSONResponse({"recorded": True})
