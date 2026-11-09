# SPDX-License-Identifier: Apache-2.0
"""Browser interaction for operator qualification of the shared native workflow."""

from html import unescape
from http.cookiejar import CookieJar
import json
from pathlib import Path
from urllib.request import HTTPCookieProcessor, build_opener

from identity_demo_action_policy import DRIVER
from identity_demo_control_transport import configured_transport, driver_request
from identity_demo_fixture_http import LoginForm, NoRedirect
from openshift_security.artifacts import write_evidence


class BrowserRunSession:
    """Initiate and approve a run through the authenticated operator rehearsal."""

    def __init__(self, flow, secrets_file: Path) -> None:
        flow.passwords = json.loads(Path(flow.args.credentials_file).read_text())
        flow.keys = json.loads(secrets_file.read_text())
        flow.client = build_opener(HTTPCookieProcessor(CookieJar()), NoRedirect())
        flow.operator_transport = configured_transport()

    def progress(self, flow, stage: str, evidence: dict | None = None) -> None:
        """Qualification has no console progress transport."""


    def http(self, flow, url, fields=None, value=None, operator=False):
        return driver_request(flow.client, url, fields=fields, value=value,
            operator_secret=flow.keys['operator_secret'] if operator else None,
            operator_transport=getattr(flow, 'operator_transport', None))

    def authenticate(self, flow) -> None:
        """Establish a real browser session without allocating an execution run."""
        status, headers, _ = flow.http(DRIVER + "/login")
        assert status == 302
        status, headers, body = flow.http(headers["Location"])
        if status == 200:
            form = LoginForm()
            form.feed(body.decode())
            status, headers, _ = flow.http(
                form.action,
                fields={
                    **form.fields,
                    "username": flow.username,
                    "password": flow.passwords[flow.username],
                    "credentialId": "",
                },
            )
        assert status == 302 and headers["Location"].startswith(DRIVER + "/callback?")
        status, _, _ = flow.http(headers["Location"])
        assert status == 303
        status, _, body = flow.http(DRIVER + "/")
        assert status == 200
        form = LoginForm()
        form.feed(body.decode())
        flow.csrf = form.fields["csrf"]

    def login(self, flow, context: object) -> dict:
        """Authenticate, submit a CVE and release credentials only to coordination."""
        flow.authenticate()
        status, headers, _ = flow.http(
            DRIVER + "/submit",
            fields={"csrf": flow.csrf, "role": context.role, **flow.submission},
        )
        assert status == 303 and headers["Location"].startswith("/runs/")
        flow.run_id = headers["Location"].split("/")[-1]
        status, _, body = flow.http(
            DRIVER + "/internal/operator/credentials/" + flow.run_id, operator=True
        )
        assert status == 200
        credential = json.loads(body)
        assert credential["workload"] == context.workload
        flow.user = credential["user"]
        write_evidence(
            flow.args.output_dir / (flow.args.label + ".driver-association.json"),
            {
                "run_id": flow.run_id,
                "user": flow.user,
                "workload": context.workload,
                "real_browser_login": True,
                "expires_at": credential["expires_at"],
            },
        )
        return {"access_token": credential["access_token"]}

    def approve_proposal(self, flow, report: dict) -> None:
        """Keep the original authenticated approval flow overridable by a human-driven coordinator."""
        status, _, displayed = flow.http(DRIVER + "/runs/" + flow.run_id)
        assert status == 200 and report["assessment"] in unescape(displayed.decode())
        assert flow.proposal["digest"] in displayed.decode()
        status, _, _ = flow.http(
            DRIVER + "/runs/" + flow.run_id + "/approve",
            fields={
                "csrf": flow.csrf,
                "action": flow.proposal["action_id"],
                "digest": flow.proposal["digest"],
            },
        )
        assert status == 303

    def close(self, flow) -> None:
        """Cancel through the owner's CSRF-protected UI; never reset or reassign identity."""
        if not flow.run_id:
            return
        status, _, _ = flow.http(
            DRIVER + "/runs/" + flow.run_id + "/cancel", fields={"csrf": flow.csrf}
        )
        assert status == 303
