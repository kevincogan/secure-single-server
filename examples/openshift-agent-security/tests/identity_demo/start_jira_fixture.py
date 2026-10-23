# SPDX-License-Identifier: Apache-2.0
"""Start the strict HTTPS emulator with seeded tokens revoked before serving."""

from contextlib import asynccontextmanager
import logging
from collections.abc import AsyncIterator

from sqlalchemy import update
from fastapi import FastAPI
import uvicorn

from jira_emulator.app import create_app
from jira_emulator.database import get_session_factory
from jira_emulator.models.api_token import ApiToken

logging.basicConfig(level=logging.WARNING)
app = create_app()
original_lifespan = app.router.lifespan_context


@asynccontextmanager
async def isolated_lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Revoke seeded tokens before the fixture accepts any API traffic."""
    async with original_lifespan(application):
        async with get_session_factory()() as session:
            await session.execute(update(ApiToken).values(active=False))
            await session.commit()
        yield


app.router.lifespan_context = isolated_lifespan

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning", access_log=False,
                ssl_certfile="/rest-tls/tls.crt", ssl_keyfile="/rest-tls/tls.key")
