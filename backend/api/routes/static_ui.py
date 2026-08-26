from __future__ import annotations

import os
from pathlib import Path

from fastapi.staticfiles import StaticFiles


def ui_dist_dir() -> Path:
    # Expected location where a build pipeline copies the frontend export output.
    return Path(
        os.getenv(
            "TESHT_UI_DIST",
            os.path.join(os.path.dirname(__file__), "..", "..", "static-ui"),
        )
    ).resolve()


def mount_ui(app) -> None:
    dist = ui_dist_dir()
    if not dist.exists():
        return

    # Mount at / so /issue, /verify, etc resolve as static exported pages.
    # IMPORTANT: mount this AFTER registering API routes like /health and /v1/*
    # so those routes take precedence.
    app.mount("/", StaticFiles(directory=str(dist), html=True), name="ui")
