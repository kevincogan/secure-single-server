# SPDX-License-Identifier: Apache-2.0
"""An unrelated agent: proposes document content and has no security authority."""


def draft(context: dict) -> dict:
    return {"collection": "engineering", "document": "runbook", "revision": 1,
            "content": "Review the synthetic service health before proceeding. "
                       + context["instruction"]}
