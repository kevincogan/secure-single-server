# SPDX-License-Identifier: Apache-2.0
"""Offline checks for exact scope of the explicitly authorized cluster grants."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
import identity_demo_runtime_grants as grants  # noqa: E402


class RuntimeGrantTests(unittest.TestCase):
    """Only the reviewed rules and dedicated ServiceAccount may be accepted."""

    def test_exact_existing_grant_accepted(self) -> None:
        """An identical owned grant can be reused without a patch."""
        for item in grants.desired():
            grants.check_existing(deepcopy(item), item)

    def test_unowned_grant_refused(self) -> None:
        """A matching cluster-object name does not establish ownership."""
        expected, _ = grants.desired()
        value = deepcopy(expected)
        value["metadata"]["labels"] = {}
        with self.assertRaises(ValueError):
            grants.check_existing(value, expected)

    def test_broad_namespace_access_refused(self) -> None:
        """The own-namespace resourceNames restriction cannot disappear."""
        expected, _ = grants.desired()
        value = deepcopy(expected)
        del value["rules"][1]["resourceNames"]
        with self.assertRaises(ValueError):
            grants.check_existing(value, expected)

    def test_extra_subject_refused(self) -> None:
        """No other user or ServiceAccount can receive this binding."""
        _, expected = grants.desired()
        value = deepcopy(expected)
        value["subjects"].append({"kind": "User", "name": "someone-else"})
        with self.assertRaises(ValueError):
            grants.check_existing(value, expected)

    def test_aggregated_permissions_refused(self) -> None:
        """External role aggregation cannot silently broaden the grant."""
        expected, _ = grants.desired()
        value = deepcopy(expected)
        value["aggregationRule"] = {"clusterRoleSelectors": [{}]}
        with self.assertRaises(ValueError):
            grants.check_existing(value, expected)
