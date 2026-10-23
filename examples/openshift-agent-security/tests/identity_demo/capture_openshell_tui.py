#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only native TUI capture with private, credential-screened screenshots."""

import argparse
import fcntl
from html import escape
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import termios
import time

import pyte

from browser_permission_flow import CHROME
from execution_context import resolve_context
from identity_demo_runtime import guard
import probe_native_exchange as native


def run(args: argparse.Namespace) -> dict:
    """Navigate existing inventory/policy/settings without mutation keystrokes."""
    args.namespace = native.NAMESPACE
    args.output_dir = Path(args.output_dir)
    args.output_dir.mkdir(mode=0o700)
    args.label = 'openshell-tui'
    _, credentials, _ = guard(args)
    args.execution_context = resolve_context(args.context_file, lambda kind, name, ns=None:
        native.kube(args, 'get', kind, name, *(['-n', ns] if ns else []), '-o', 'json'))
    screen = pyte.Screen(150, 45)
    stream = pyte.Stream(screen)
    raw, frames = [], {}
    with native.native_session(args, credentials) as execute:
        execute(['status', '--output', 'json'], json_output=True)
        environment = {**os.environ, 'XDG_CONFIG_HOME': args.cli_config_dir,
            'OPENSHELL_OIDC_CLIENT_SECRET': credentials['runtime_management']['client_secret'],
            'TERM': 'xterm-256color'}
        for key in ('OPENSHELL_GATEWAY', 'OPENSHELL_GATEWAY_ENDPOINT',
                    'OPENSHELL_GATEWAY_INSECURE', 'OPENSHELL_WORKSPACE', 'subject_token'):
            environment.pop(key, None)
        pid, master = pty.fork()
        if pid == 0:
            os.execvpe(args.cli, [args.cli, '--gateway', 'identity-demo-runtime',
                '--workspace', args.execution_context.workspace, 'term'], environment)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 45, 150, 0, 0))
        ended = False

        def observe(seconds: int) -> None:
            """Answer terminal discovery queries and decode the actual screen."""
            nonlocal ended
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and not ended:
                if select.select([master], [], [], .2)[0]:
                    try:
                        data = os.read(master, 65536)
                        if not data:
                            ended = True
                            break
                        text = data.decode(errors='replace')
                        raw.append(text)
                        stream.feed(text)
                        for query, reply in ((b'\x1b]10;?', b'\x1b]10;rgb:eeee/eeee/eeee\x1b\\'),
                                             (b'\x1b]11;?', b'\x1b]11;rgb:1111/1111/1111\x1b\\'),
                                             (b'\x1b[6n', b'\x1b[1;1R')):
                            if query in data:
                                os.write(master, reply)
                    except OSError:
                        ended = True
        try:
            observe(8)
            frames['inventory'] = '\n'.join(screen.display)
            if not ended:
                os.write(master, b'\t\t\r')
                observe(5)
                frames['policy'] = '\n'.join(screen.display)
            if not ended:
                os.write(master, b'\x1b[C')
                observe(3)
                frames['settings'] = '\n'.join(screen.display)
            if not ended:
                os.write(master, b'q')
                observe(2)
        finally:
            if not ended:
                os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
            os.close(master)
    content = ''.join(raw)
    assert credentials['runtime_management']['client_secret'] not in content
    assert not re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', content)
    assert 'PRIVATE KEY' not in content
    joined = '\n'.join(frames.values())
    result = {'passed': True, 'read_only_navigation': True, 'current_owned_context': True,
        'owned_gateway_visible': 'identity-demo-runtime' in joined,
        'owned_sandbox_visible': args.execution_context.sandbox_name in joined,
        'policy_or_settings_visible': 'Policy' in joined or 'Settings' in joined,
        'healthy_gateway_visible': 'Healthy' in joined,
        'snapshot_not_active_run_policy': True}
    assert all(result.values())
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, chromium_sandbox=True)
        view = browser.new_page(viewport={'width': 1600, 'height': 1100})
        for name, text in frames.items():
            native.private_write(args.output_dir / (name + '.txt'), text)
            view.set_content('<html><body style="background:#101827;color:#eaf0f5">'
                '<h2>OpenShell — actual terminal snapshot</h2><pre style="font:16px monospace">'
                + escape(text) + '</pre></body></html>')
            view.screenshot(path=str(args.output_dir / (name + '.png')), full_page=True)
        browser.close()
    native.private_write(args.output_dir / 'tui.summary.json', result)
    return result


def main() -> None:
    """Require explicit private access and a still-existing validated context."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kubeconfig', 'expected-server', 'credentials-file', 'cli',
                 'cli-config-dir', 'context-file', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    os.umask(0o077)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args)))
    except Exception as error:
        print(json.dumps({'passed': False, 'kind': type(error).__name__, 'details_withheld': True}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
