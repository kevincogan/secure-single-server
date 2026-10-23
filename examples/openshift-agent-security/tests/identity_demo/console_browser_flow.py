#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the deployed console through genuine browser login, Start and consent.

Requires the private operator coordinator already running and a fresh prepared
context. Screenshots exclude login. A successful write requires explicit
--enable-create; this is live synthetic acceptance, never a mocked UI test.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import time

from playwright.sync_api import sync_playwright, Error as BrowserError

from browser_permission_flow import CHROME
from deployment_profile import active_profile
from identity_demo_action_policy import DRIVER
from identity_demo_runtime_cli import private_path


def main() -> None:
    """Retain bounded UI evidence while the existing worker verifies native/backend behavior."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials-file', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--username', choices=('analyst', 'viewer'), required=True)
    parser.add_argument('--workflow', choices=('cve', 'service-request', 'incident-triage'), required=True)
    parser.add_argument('--role', choices=('triage', 'reader'), default='triage')
    parser.add_argument('--expect', choices=('create', 'user_permission', 'workload_permission', 'cancel', 'reject', 'inference_failure'), required=True)
    parser.add_argument('--enable-create', action='store_true')
    parser.add_argument('--headed', action='store_true')
    args = parser.parse_args()
    if args.expect not in ('cancel', 'reject', 'inference_failure') and not args.enable_create:
        parser.error('Explicit --enable-create required for a real approved tool attempt')
    os.umask(0o077)
    output = Path(args.output_dir)
    private_path(str(output.parent), directory=True)
    output.mkdir(mode=0o700)
    credentials = json.loads(private_path(args.credentials_file).read_text())
    if credentials['namespace'] != active_profile().core_namespace:
        raise ValueError('Exact selected fixture namespace required')
    summary = {'passed': False, 'username': args.username, 'workflow': args.workflow,
               'workload_role': args.role, 'expected': args.expect, 'real_browser': True}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, headless=not args.headed, chromium_sandbox=True)
        context = browser.new_context(viewport={'width': 1586, 'height': 1050})
        page = context.new_page()
        page.set_default_timeout(20_000)

        def capture(name: str) -> None:
            if not page.url.startswith(DRIVER + '/runs/') or '/callback' in page.url:
                return
            page.screenshot(path=str(output / (name + '.png')), full_page=True)

        def wait_for(predicate: object, seconds: int = 300) -> str:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    text = page.locator('body').inner_text()
                    if predicate(text):
                        return text
                    if args.expect not in ('cancel', 'reject', 'inference_failure') and any(v in text for v in ('Execution stopped', 'Outcome uncertain', 'Run expired')):
                        raise RuntimeError('Console recorded a terminal failure; inspect private evidence')
                    page.wait_for_timeout(1000)
                except BrowserError:
                    page.wait_for_timeout(500)
            raise TimeoutError('Console state not observed; inspect private evidence')

        try:
            page.goto(DRIVER + '/')
            page.get_by_role('link', name='Sign in', exact=True).first.click()
            page.locator('#username').fill(args.username)
            page.locator('#password').fill(credentials[args.username])
            page.locator('#kc-login').click()
            page.wait_for_url(DRIVER + '/')
            page.get_by_text('Signed in as', exact=False).wait_for()
            name = {'cve': 'Start assessment', 'service-request': 'Start remediation request', 'incident-triage': 'Start incident triage'}[args.workflow]
            form = page.locator('form').filter(has=page.get_by_role('button', name=name, exact=True))
            if args.workflow == 'cve':
                form.locator('select[name="role"]').select_option(args.role)
            form.get_by_role('button', name=name, exact=True).click()
            page.wait_for_url(re.compile(re.escape(DRIVER) + r'/runs/[a-f0-9]{32}'))
            summary['run_id'] = page.url.rsplit('/', 1)[-1]
            capture('submitted')
            if args.expect in ('cancel', 'reject'):
                if args.expect == 'reject':
                    wait_for(lambda t: 'Awaiting your approval' in t)
                    capture('proposal-before-rejection')
                name = 'Cancel run' if args.expect == 'cancel' else 'Reject proposal and close run'
                page.get_by_role('button', name=name, exact=True).click()
                wait_for(lambda t: 'Final recorded state' in t and
                         ('Proposal rejected' in t if args.expect == 'reject' else 'Run cancelled' in t))
                assert page.get_by_role('button', name='Approve this exact proposal').count() == 0
                summary['manual_browser_' + args.expect] = True
            elif args.expect == 'inference_failure':
                wait_for(lambda t: 'Final recorded state' in t and ('Model request failed' in t or 'Agent stopped: model unavailable' in t))
                assert page.get_by_role('button', name='Approve this exact proposal').count() == 0
            else:
                wait_for(lambda t: 'Awaiting your approval' in t)
                capture('proposal')
                # Real owner consent must remain pending until this browser click.
                page.wait_for_timeout(1500)
                approve = page.get_by_role('button', name='Approve this exact proposal', exact=True)
                assert approve.is_visible()
                approval_form = page.locator('form').filter(has=approve)
                consent = {key: approval_form.locator('input[name="' + key + '"]').input_value()
                           for key in ('csrf', 'action', 'digest')}
                if args.expect == 'create' and args.workflow == 'cve':
                    url = page.url + '/approve'
                    wrong = context.request.post(url, form={**consent, 'digest': '0' * 64}, headers={'Origin': DRIVER})
                    assert wrong.status == 403 and wrong.json()['reason'] == 'approval_binding'
                    cross = context.request.post(url, form=consent, headers={'Origin': 'https://untrusted.example'})
                    assert cross.status == 403 and cross.json()['reason'] == 'csrf_origin'
                    invalid = context.request.post(DRIVER + '/submit', form={
                        'csrf': consent['csrf'], 'role': 'triage', 'cve': 'CVE-2099-0001', 'project': 'OTHER'},
                        headers={'Origin': DRIVER})
                    assert invalid.status == 403 and invalid.json()['reason'] == 'unapproved_source'
                    summary['invalid_inputs_rejected'] = True
                approve.click()
                if args.expect == 'create' and args.workflow == 'cve':
                    replay = context.request.post(page.url + '/approve', form=consent, headers={'Origin': DRIVER})
                    assert replay.status == 403 and replay.json()['reason'] == 'approval_binding'
                    summary['duplicate_approval_rejected'] = True
                text = wait_for(lambda t: 'Final recorded state' in t and 'Independently checked project count:' in t)
                if args.expect == 'create':
                    assert 'Protected action succeeded' in text
                    assert 'Independent backend field verification passed.' in text
                    issue = re.search(r'Verified issue: ([A-Z][A-Z0-9]+-[1-9][0-9]*)', text)
                    assert issue
                    summary['verified_issue_key'] = issue.group(1)
                else:
                    assert 'Protected action denied: ' + args.expect.replace('_', ' ') in text
                    assert 'Verified issue:' not in text
                    summary['verified_issue_key'] = None
                counts = re.search(r'Independently checked project count:\s*(\d+)\s*→\s*(\d+)', text)
                assert counts
                before, after = map(int, counts.groups())
                assert after == before + int(args.expect == 'create')
                summary.update(backend_before=before, backend_after=after, manual_browser_approval=True)
            capture('outcome')
            html = page.content()
            assert credentials[args.username] not in html
            assert not re.search(r'eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]+\.', html)
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            if args.expect == 'create' and args.workflow == 'cve':
                page.set_viewport_size({'width': 390, 'height': 844})
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                capture('outcome-mobile')
                summary['mobile_overflow'] = False
            summary.update(passed=True, credentials_absent_from_ui=True)
        except Exception as error:
            capture('failure')
            summary.update(failure_kind=type(error).__name__, details_withheld=True)
            raise
        finally:
            (output / 'console-browser.summary.json').write_text(json.dumps(summary, indent=2))
            print(json.dumps(summary), flush=True)
            context.close()
            browser.close()


if __name__ == '__main__':
    main()
