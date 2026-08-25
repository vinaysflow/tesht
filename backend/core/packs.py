"""
Pack framework — optional policy modules on the Session decide path.

Phase 1 ships shells only. Vertical packs (sca_continuity, eu_ai_act, secops)
are added when a design partner commits.

Hook points:
  - on_handoff  — after session create
  - on_action   — before/after decide
  - on_step_up  — when step-up is required / completed
  - on_revoke   — when session is revoked
  - on_export   — evidence export
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

KNOWN_PACKS = frozenset({"core", "commerce"})
DEFAULT_PACKS = ["core"]


@dataclass
class PackContext:
    """Shared context passed to pack hooks."""

    session_id: str
    tenant_id: str
    agent_did: str
    human_did: Optional[str] = None
    scope: dict[str, Any] = field(default_factory=dict)
    packs: list[str] = field(default_factory=list)
    action: Optional[dict[str, Any]] = None
    decision: Optional[dict[str, Any]] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PackHookResult:
    """Optional mutation / veto from a pack hook."""

    ok: bool = True
    error_code: Optional[str] = None
    reason: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


PackHook = Callable[[PackContext], PackHookResult]


def normalize_packs(packs: Optional[list[str]]) -> list[str]:
    """Ensure core is present; drop unknown packs in Phase 1 (shells only)."""
    requested = list(packs or [])
    out: list[str] = []
    for p in requested:
        name = str(p).strip().lower()
        if not name:
            continue
        if name not in KNOWN_PACKS:
            # Phase 1: ignore unknown packs rather than fail hard
            continue
        if name not in out:
            out.append(name)
    if "core" not in out:
        out.insert(0, "core")
    return out


def _core_on_action(ctx: PackContext) -> PackHookResult:
    """Core pack: no-op pass-through (enforcement lives in Session decide)."""
    return PackHookResult(ok=True, extra={"pack": "core"})


HOOKS: dict[str, dict[str, PackHook]] = {
    "core": {
        "on_handoff": lambda ctx: PackHookResult(ok=True, extra={"pack": "core"}),
        "on_action": _core_on_action,
        "on_step_up": lambda ctx: PackHookResult(ok=True, extra={"pack": "core"}),
        "on_revoke": lambda ctx: PackHookResult(ok=True, extra={"pack": "core"}),
        "on_export": lambda ctx: PackHookResult(ok=True, extra={"pack": "core"}),
    },
    # Agentic-commerce pack. The heavy enforcement (cumulative budget, merchant
    # allowlist, AP2 spend ledger) lives inline in the Session decide path where
    # DB access is available; these hooks are pass-through markers.
    "commerce": {
        "on_handoff": lambda ctx: PackHookResult(ok=True, extra={"pack": "commerce"}),
        "on_action": lambda ctx: PackHookResult(ok=True, extra={"pack": "commerce"}),
        "on_step_up": lambda ctx: PackHookResult(ok=True, extra={"pack": "commerce"}),
        "on_revoke": lambda ctx: PackHookResult(ok=True, extra={"pack": "commerce"}),
        "on_export": lambda ctx: PackHookResult(ok=True, extra={"pack": "commerce"}),
    },
}


def run_pack_hooks(
    packs: list[str],
    hook_name: str,
    ctx: PackContext,
) -> PackHookResult:
    """Run *hook_name* for each enabled pack; first failure short-circuits."""
    aggregated: dict[str, Any] = {}
    for pack_name in normalize_packs(packs):
        pack_hooks = HOOKS.get(pack_name) or {}
        hook = pack_hooks.get(hook_name)
        if hook is None:
            continue
        result = hook(ctx)
        aggregated[pack_name] = result.extra or {}
        if not result.ok:
            return PackHookResult(
                ok=False,
                error_code=result.error_code,
                reason=result.reason,
                extra=aggregated,
            )
    return PackHookResult(ok=True, extra=aggregated)
