# SPDX-License-Identifier: Apache-2.0
"""Package verified synthetic rehearsal snapshots; never impersonate a live UI."""

import argparse
import base64
import hashlib
from html import escape
import json
import os
from pathlib import Path

from identity_demo_runtime_cli import private_path


def receipt(directory: Path, suffix: str) -> tuple[dict, Path]:
    """Require one explicit successful receipt from a private rehearsal directory."""
    paths = list(directory.glob('*' + suffix))
    if len(paths) != 1:
        raise ValueError('Exactly one matching evidence receipt required')
    return json.loads(paths[0].read_text()), paths[0]


def page(title: str, body: str, seconds: int) -> str:
    """Escape titles; body is built only from escaped fields and fixed markup."""
    return (f'<section data-seconds="{seconds}"><header>Agent identity and controlled tools'
            f' · Recorded lab evidence</header><h1>{escape(title)}</h1>{body}'
            '<footer>Synthetic data · Development demonstration · Snapshot, not a live dashboard</footer></section>')


def bullets(values: list[str]) -> str:
    """Render evidence and narration as text, never executable model output."""
    return '<ul>' + ''.join('<li>' + escape(v) + '</li>' for v in values) + '</ul>'


def build(allow_dir: Path, deny_dir: Path, jira: Path, tui: Path | None = None) -> tuple[str, dict]:
    """Select actual outcomes/configuration, with no secrets or raw private logs."""
    allow, allow_path = receipt(allow_dir, '.walkthrough.summary.json')
    deny, deny_path = receipt(deny_dir, '.walkthrough.summary.json')
    gateway, gateway_path = receipt(allow_dir, '.gateway.summary.json')
    inference, inference_path = receipt(allow_dir, '.inference.summary.json')
    if not (allow.get('passed') and deny.get('passed') and gateway.get('passed')
            and allow.get('workload_messages_inference_proven')
            and allow.get('verified_issue_key') and deny.get('username') == 'viewer'
            and deny.get('verified_issue_key') is None
            and deny.get('backend_before') == deny.get('backend_after')
            and inference.get('http_status') == 200):
        raise ValueError('Passing model analyst, viewer and gateway evidence required')
    label = allow_path.name.removesuffix('.walkthrough.summary.json')
    deny_label = deny_path.name.removesuffix('.walkthrough.summary.json')
    association_path = allow_dir / (label + '.driver-association.json')
    association = json.loads(association_path.read_text())
    if not association.get('real_browser_login') or not association.get('workload', '').startswith(
        'spiffe://agents.example.test/openshell/sandbox/'
    ):
        raise ValueError('Actual authenticated run association required')
    assets = []
    def screenshot(path: Path, position: str = 'top') -> str:
        raw = path.read_bytes()
        if not raw.startswith(b'\x89PNG\r\n\x1a\n') or len(raw) > 20_000_000:
            raise ValueError('Bounded reviewed PNG required')
        assets.append(path)
        encoded = base64.b64encode(raw).decode()
        return f'<div class="shot"><img style="object-position:{position}" src="data:image/png;base64,{encoded}" alt="Actual synthetic demo screenshot"></div>'
    sections = [page('A user and an agent act together', bullets([
        'The logged-in user and attested workload jointly determine permission.',
        'The model proposes content. Trusted services fix identity, project and approval.',
        'This recording shows verified lab snapshots; the runbook provides the live rehearsal.']), 15)]
    tui_path = None
    if tui is not None:
        tui_path = tui / 'tui.summary.json'
        terminal = json.loads(tui_path.read_text())
        if not terminal.get('passed') or not terminal.get('read_only_navigation'):
            raise ValueError('Passing read-only TUI receipt required')
        sections.append(page('OpenShell isolation and settings', bullets([
            'Actual owned native runtime, captured through read-only terminal navigation.',
            'This restored configuration is a snapshot; active run policies are temporary.'])
            + screenshot(tui / 'settings.png'), 20))
    sections.append(page('A verified workload acts for the logged-in user', bullets([
        'Authenticated demonstration role: analyst',
        'Actual attested workload: ' + association['workload'],
        'Trusted run: ' + association['run_id'],
        'The protected call uses the accepted certificate-bound native transport.',
        'The agent cannot select another user, workload or run by adding headers.']), 15))
    # Four 30-second pages provide a dedicated two-minute gateway introduction.
    sections.append(page('MCP Gateway: one place to manage tool access', bullets([
        'Actual gateway: ' + gateway['gateway'],
        'Registered Jira MCP server: ' + gateway['registered_server'],
        'Registration ready: ' + str(gateway['registration_ready']),
        'Calls route through the gateway to: ' + ', '.join(gateway['backend_services']),
        'This is a view of captured management configuration, not an installed gateway dashboard.']), 30))
    schemas = gateway['published_tool_schemas']
    sections.append(page('Discover tools and inspect their schemas', bullets([
        t['name'] + ': ' + ', '.join(a['name'] + (' (required)' if a['required'] else '')
        for a in t['arguments']) for t in schemas]), 30))
    sections.append(page('Authenticate each call and check its run', bullets([
        'Keycloak authenticates the user and workload through the accepted exchange path.',
        'The gateway checks the live trusted run association and the presented certificate binding.',
        'Captured live-run configuration: ' + str(gateway['live_run_identity_check']),
        'A copied token or a caller-supplied identity header is not authorization.']), 30))
    sections.append(page('Authorize the action and protect backend credentials', bullets([
        'Actual arguments and explicit approval are checked before a write.',
        'Captured approval check: ' + str(gateway['actual_arguments_and_approval_check']),
        'Scoped backend service-token delivery: ' + str(gateway['scoped_adapter_service_token_delivery']),
        'The gateway centralizes policy and routing; the adapter validates the protected call.',
        'The next screens show actual approval, backend outcome and a permission denial.']), 30))
    sections.append(page('Real model inference, followed by human review', bullets([
        'Actual controlled OpenShift workload · Messages API · HTTP 200',
        'Requested model: ' + inference['model'],
        'TLS verified; redirects disabled; key retained by the native supervisor.'])
        + screenshot(allow_dir / (label + '.proposal-review.png'), 'center'), 20))
    sections.append(page('The approved action succeeded once', bullets([
        'Verified Jira issue: ' + allow['verified_issue_key'],
        f"Project issue count: {allow['backend_before']} → {allow['backend_after']}",
        'Backend fields, approval digest and user/workload/run/action correlation matched.'])
        + screenshot(jira), 20))
    sections.append(page('Approval cannot override viewer permissions', bullets([
        'The viewer approved the exact proposal and still received a deliberate permission denial.',
        f"Project issue count unchanged: {deny['backend_before']} → {deny['backend_after']}"])
        + screenshot(deny_dir / (deny_label + '.outcome.png'), 'bottom'), 20))
    sections.append(page('Proven boundaries and remaining work', bullets([
        'Agent direct sockets to public IP, cluster API, direct Jira and private broker were denied.',
        'Unavailable inference produced no proposal or backend write; final-token renewal passed.',
        'Trusted supervisor, DNS, image pulls and operator traffic are explicit network exceptions.',
        'External inference dependency remains. Full disconnected installation and separate-cluster proof are deferred.',
        'Formal reviews, provenance/scans and production approval remain separate.']), 20))
    style = '''body{margin:0;font:26px system-ui;background:#101827;color:#f4f6fa}section{box-sizing:border-box;height:100vh;padding:35px 65px;position:relative;overflow:hidden;page-break-after:always}header,footer{font-size:17px;color:#a9c4d8}footer{position:absolute;bottom:18px}h1{font-size:39px;color:#87d5ce;margin:25px 0}li{margin:18px 0;line-height:1.5}.shot{height:480px;background:white;overflow:hidden;border-radius:8px}.shot img{width:100%;height:100%;object-fit:cover}section:has(.shot) li{font-size:22px;margin:8px 0}'''
    html = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'">'
            '<title>Agent identity and controlled tools</title><style>' + style + '</style>'
            + ''.join(sections) + '</html>')
    paths = [allow_path, deny_path, gateway_path, inference_path, association_path, *assets]
    if tui_path is not None:
        paths.append(tui_path)
    manifest = {'snapshot_presentation': True, 'live_gateway_dashboard_claimed': False,
        'gateway_introduction_seconds': 120, 'neutral_branding': True,
        'evidence': [{'name': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]}
    return html, manifest


def main() -> None:
    """Write a private offline presentation and optionally record its paced playback."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('allow-dir', 'deny-dir', 'jira-screenshot', 'tui-dir', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--record', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    allow, deny = (private_path(p, directory=True) for p in (args.allow_dir, args.deny_dir))
    jira = private_path(args.jira_screenshot)
    html, manifest = build(allow, deny, jira, private_path(args.tui_dir, directory=True))
    out = Path(args.output_dir)
    private_path(str(out.parent), directory=True)
    out.mkdir(mode=0o700)
    (out / 'presentation.html').write_text(html)
    if args.record:
        from playwright.sync_api import sync_playwright
        from browser_permission_flow import CHROME
        with sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path=CHROME, chromium_sandbox=True)
            context = browser.new_context(viewport={'width': 1440, 'height': 1000},
                record_video_dir=str(out / 'video'), record_video_size={'width': 1440, 'height': 1000})
            view = context.new_page()
            view.set_content(html)
            for section in view.locator('section').all():
                section.scroll_into_view_if_needed()
                view.wait_for_timeout(int(section.get_attribute('data-seconds')) * 1000)
            view.screenshot(path=str(out / 'final-frame.png'))
            context.close()
            browser.close()
        manifest['recording_created'] = len(list((out / 'video').glob('*.webm'))) == 1
    (out / 'presentation.summary.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: v for k, v in manifest.items() if k != 'evidence'}))


if __name__ == '__main__':
    main()
