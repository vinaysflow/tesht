from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from api.middleware.limits import MaxBodySizeMiddleware
from api.middleware.rate_limit import SimpleRateLimitMiddleware

from api.routes.agents import router as agents_router
from api.routes.admin import router as admin_router
from api.routes.audit import router as audit_router
from api.routes.auth import router as auth_router
from api.routes.workflows import router as workflows_router
from api.routes.keys import router as keys_router
from api.routes.demo import router as demo_router
from api.routes.credentials import router as credentials_router
from api.routes.delegations import router as delegations_router
from api.routes.dids import router as dids_router
from api.routes.revoke import router as revoke_router
from api.routes.status import router as status_router
from api.routes.verify import router as verify_router
from api.routes.requirement_intents import router as requirement_intents_router
from api.routes.commerce import router as commerce_router
from api.routes.trust import router as trust_router
from api.routes.webhooks import router as webhooks_router
from api.routes.spiffe_bridge import router as spiffe_bridge_router
from api.routes.compliance import router as compliance_router
from api.routes.marketplace import router as marketplace_router
from api.routes.sessions import router as sessions_router
from api.routes.storefront import router as storefront_router
from api.routes.static_ui import mount_ui
from core.settings import settings
from core.startup import init_db

app = FastAPI(
    title="Tesht (Pramana) API",
    description=(
        "Portable identity and scoped authorization for AI agents. "
        "W3C DIDs, verifiable credentials, narrowing delegation, instant revocation."
    ),
    version="0.1.0",
)

def _get_request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id") or request.headers.get("X-Request-ID")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    import uuid

    return uuid.uuid4().hex[:12]


@app.middleware("http")
async def _request_id_middleware(request: Request, call_next):
    rid = _get_request_id(request)
    request.state.request_id = rid
    try:
        response = await call_next(request)
    except HTTPException as e:
        # Let the exception handler format this.
        raise e
    except Exception as e:
        # Always return structured error with request id (no tracebacks).
        body = {"error": "internal_error", "request_id": rid}
        # In demo mode, include a short message + exception type for faster iteration.
        if settings.demo_mode:
            body["type"] = e.__class__.__name__
            msg = str(e)
            body["message"] = msg[:300] if isinstance(msg, str) else "error"
        return JSONResponse(status_code=500, content=body, headers={"x-request-id": rid})

    response.headers["x-request-id"] = rid
    return response


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException):
    rid = getattr(request.state, "request_id", None) or _get_request_id(request)
    detail = exc.detail
    if isinstance(detail, dict):
        body = {**detail, "request_id": rid}
    else:
        body = {"error": str(detail), "request_id": rid}
    return JSONResponse(status_code=exc.status_code, content=body, headers={"x-request-id": rid})

def _add_ui_trailing_slash_redirects(app: FastAPI) -> None:
    # Next static export serves routes as /route/index.html. Ensure /route redirects to /route/
    # so users don't hit Next's 404 page when requesting without the trailing slash.
    ui_paths = [
        "/demo",
        "/issue",
        "/verify",
        "/revoke",
        "/audit",
        "/login",
        "/auth/callback",
    ]

    for path in ui_paths:
        async def _redir(request: Request, _path: str = path):
            target = f"{_path}/"
            if request.url.query:
                target = f"{target}?{request.url.query}"
            return RedirectResponse(url=target, status_code=307)

        app.add_api_route(path, _redir, methods=["GET", "HEAD"], include_in_schema=False)

def _add_demo_mode_ui_overrides(app: FastAPI) -> None:
    # In demo mode there is no Keycloak. Protect users from the /login page even if
    # an older cached UI build still links to it.
    if not settings.demo_mode:
        return

    async def _to_demo(request: Request):
        target = "/demo/"
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(url=target, status_code=307)

    # Redirect both with and without trailing slash.
    app.add_api_route("/login", _to_demo, methods=["GET", "HEAD"], include_in_schema=False)
    app.add_api_route("/login/", _to_demo, methods=["GET", "HEAD"], include_in_schema=False)
    app.add_api_route("/auth/callback", _to_demo, methods=["GET", "HEAD"], include_in_schema=False)
    app.add_api_route("/auth/callback/", _to_demo, methods=["GET", "HEAD"], include_in_schema=False)

if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_body_bytes)
if settings.rate_limit_enabled:
    app.add_middleware(SimpleRateLimitMiddleware, max_requests=settings.rate_limit_per_minute, window_seconds=60)

app.include_router(agents_router)
app.include_router(admin_router)
app.include_router(dids_router)
app.include_router(credentials_router)
app.include_router(delegations_router)
app.include_router(status_router)
app.include_router(verify_router)
app.include_router(revoke_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(workflows_router)
app.include_router(keys_router)
app.include_router(demo_router)
app.include_router(requirement_intents_router)
app.include_router(commerce_router)
app.include_router(trust_router)
app.include_router(webhooks_router)
app.include_router(spiffe_bridge_router)
app.include_router(compliance_router)
app.include_router(marketplace_router)
app.include_router(sessions_router)
app.include_router(storefront_router)


@app.on_event("startup")
async def _startup():
    init_db()


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/ready")
async def ready():
    try:
        from core.db import engine
        from sqlalchemy import text as _text

        with engine.connect() as conn:
            conn.execute(_text("SELECT 1"))

            # migrations applied?
            try:
                conn.execute(_text("SELECT version_num FROM alembic_version"))
            except Exception:
                return {"ready": False, "error": "missing alembic_version (migrations not applied?)"}

            # writable?
            try:
                # works on sqlite and postgres
                conn.execute(_text("CREATE TABLE IF NOT EXISTS _tesht_readycheck (id INTEGER PRIMARY KEY)"))
                conn.execute(_text("INSERT INTO _tesht_readycheck(id) VALUES (1)"))
                conn.execute(_text("DELETE FROM _tesht_readycheck WHERE id=1"))
            except Exception as e:
                return {"ready": False, "error": f"db not writable: {e}"}

        return {"ready": True}
    except Exception as e:
        return {"ready": False, "error": str(e)}


@app.get("/api")
async def api_root():
    return {
        "name": "Tesht (Pramana)",
        "version": "0.1.0",
        "description": "Portable identity and scoped authorization for AI agents",
        "standards": [
            "W3C DID Core 1.0",
            "W3C VC 2.0",
            "VC-JOSE",
            "Bitstring Status List",
        ],
    }


# Mount UI last so API routes take precedence.
_add_ui_trailing_slash_redirects(app)
_add_demo_mode_ui_overrides(app)
mount_ui(app)
