# SPDX-License-Identifier: Apache-2.0
"""Shared components integration-test inputs; actual tests remain collected."""
from __future__ import annotations
import base64
import hashlib
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener
import jwt
import pytest
from deployment_profile import active_profile
from identity_demo_fixture_http import KEYCLOAK, JIRA, ISSUER, NoRedirect, LoginForm, request, login, verify




def fixture_credentials():
    """Load the explicit owned fixture once per integration test class."""
    filename = os.environ.get('IDENTITY_DEMO_CREDENTIALS_FILE')
    if not filename:
        raise unittest.SkipTest('Explicit owned-fixture credentials required')
    path = Path(filename)
    if path.stat().st_mode & 0o077:
        raise RuntimeError('Fixture credential file is not private')
    credentials = json.loads(path.read_text())
    if credentials['namespace'] != 'demo-core':
        raise RuntimeError('Unexpected fixture namespace')
    return credentials
