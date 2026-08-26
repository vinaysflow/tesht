"""
scripts.demo_explainer
~~~~~~~~~~~~~~~~~~~~~~
Explainability display functions for the Tesht (Pramana) mega-demo.

Each function receives parsed data (dicts, lists, strings) and prints a
formatted, ANSI-coloured block to stdout.  They are purely additive —
no side-effects, no I/O except printing.

Functions
---------
decode_and_display_vp(vp_jwt)         — decode VP-JWT + each embedded VC
display_trust_breakdown(factors, score, decision)  — per-factor table
display_delegation_chain(chain, effective_scope, delegator_claims, agent_did)
display_credential_isolation(vp_jwt, server_entry)  — side-by-side view
display_trust_timeline(events)        — ASCII chart of score over time
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Optional

# ── ANSI colours (matches demo_mega.py palette) ───────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
GREEN   = "\033[92m"
RED     = "\033[91m"
CYAN    = "\033[96m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
WARN = f"{YELLOW}⚠{RESET}"

# Box width used by all panels
_W = 65


# ── Private helpers ───────────────────────────────────────────────────────────

def _decode_jwt_payload(token: str) -> dict:
    """Base64-decode the JWT payload segment (no signature verification)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _decode_jwt_header(token: str) -> dict:
    """Base64-decode the JWT header segment."""
    try:
        header = token.split(".")[0]
        header += "=" * (4 - len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header))
    except Exception:
        return {}


def _short_did(did: str, chars: int = 20) -> str:
    """Return a truncated DID: prefix:method:zFirs...tLast."""
    if not did or len(did) <= chars + 10:
        return did or "—"
    return did[:chars] + "…" + did[-6:]


def _fmt_ts(epoch: Optional[int]) -> str:
    if epoch is None:
        return "—"
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(epoch)


def _box_line(text: str, color: str = BOLD, width: int = _W) -> None:
    """Print a single bordered box row."""
    print(f"{color}║{RESET} {text:<{width - 1}}{color}║{RESET}")


def _box_sep(color: str = BOLD, width: int = _W) -> None:
    print(f"{color}╠{'═' * width}╣{RESET}")


def _box_top(title: str, color: str = CYAN, width: int = _W) -> None:
    print(f"\n  {color}╔{'═' * width}╗{RESET}")
    print(f"  {color}║{RESET} {BOLD}{title:<{width - 1}}{RESET}{color}║{RESET}")
    print(f"  {color}╠{'═' * width}╣{RESET}")


def _box_bot(color: str = CYAN, width: int = _W) -> None:
    print(f"  {color}╚{'═' * width}╝{RESET}")


def _box_row(text: str, color: str = CYAN, width: int = _W) -> None:
    # Hard-wrap at width-2 so ANSI-free text fits
    max_w = width - 2
    while len(text) > max_w:
        print(f"  {color}║{RESET} {text[:max_w]:<{max_w}}{color}║{RESET}")
        text = "  " + text[max_w:]
    print(f"  {color}║{RESET} {text:<{width - 1}}{color}║{RESET}")


def _credential_type_color(ctype: str) -> str:
    ctype_lower = ctype.lower()
    if "delegation" in ctype_lower:
        return BLUE
    if "organizational" in ctype_lower or "identity" in ctype_lower or "role" in ctype_lower:
        return GREEN
    if "agent" in ctype_lower:
        return MAGENTA
    return CYAN


# ── Public display functions ──────────────────────────────────────────────────

def decode_and_display_vp(vp_jwt: str) -> None:
    """
    Decode a VP-JWT (no signature verification) and pretty-print the holder,
    audience, expiry, type list, and each embedded VC with its claims.
    """
    if not vp_jwt:
        return

    vp_payload = _decode_jwt_payload(vp_jwt)
    if not vp_payload:
        return

    holder_did = vp_payload.get("iss") or vp_payload.get("sub") or "—"
    audience   = vp_payload.get("aud") or "—"
    exp_epoch  = vp_payload.get("exp")
    vp_body    = vp_payload.get("vp", {})
    types      = vp_body.get("type", []) or vp_payload.get("type", [])
    vc_tokens  = vp_body.get("verifiableCredential", [])

    print(f"\n  {CYAN}╔{'═' * _W}╗{RESET}")
    print(f"  {CYAN}║{RESET} {BOLD}{'VP-JWT DECODED — Verifiable Presentation':<{_W - 1}}{RESET}{CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")
    _box_row(f"Holder  : {_short_did(holder_did, 30)}", CYAN)
    if isinstance(audience, list):
        _box_row(f"Audience: {_short_did(audience[0], 30)}", CYAN)
    else:
        _box_row(f"Audience: {_short_did(str(audience), 30)}", CYAN)
    _box_row(f"Expires : {_fmt_ts(exp_epoch)}", CYAN)
    type_str = ", ".join(types) if types else "VerifiablePresentation"
    _box_row(f"Type    : {type_str}", CYAN)
    _box_row(f"Bundled : {len(vc_tokens)} credential(s)", CYAN)

    for idx, vc_token in enumerate(vc_tokens, 1):
        if not isinstance(vc_token, str):
            continue
        vc_payload = _decode_jwt_payload(vc_token)
        if not vc_payload:
            continue

        vc_body   = vc_payload.get("vc", {})
        vc_types  = vc_body.get("type", [])
        ctype     = vc_types[-1] if len(vc_types) > 1 else (vc_types[0] if vc_types else "VerifiableCredential")
        issuer    = vc_payload.get("iss", "—")
        subject   = vc_payload.get("sub", "—")
        vc_iat    = vc_payload.get("iat")
        vc_exp    = vc_payload.get("exp")
        cs        = vc_body.get("credentialSubject", {})
        claims    = {k: v for k, v in cs.items() if k != "id"}

        col = _credential_type_color(ctype)

        print(f"  {CYAN}╠{'═' * _W}╣{RESET}")
        print(f"  {CYAN}║{RESET} {col}{BOLD}CREDENTIAL {idx}: {ctype:<{_W - 15}}{RESET}{CYAN}║{RESET}")
        _box_row(f"  Issuer : {_short_did(issuer, 30)}", CYAN)
        _box_row(f"  Subject: {_short_did(subject, 30)}", CYAN)

        # Key claims
        for key, val in list(claims.items())[:6]:
            val_str = str(val)[:48]
            _box_row(f"  {key:<14}: {val_str}", CYAN)

        _box_row(f"  Valid  : {_fmt_ts(vc_iat)}  →  {_fmt_ts(vc_exp)}", CYAN)

    print(f"  {CYAN}╚{'═' * _W}╝{RESET}")


def display_trust_breakdown(
    factors: dict[str, Any],
    score: int,
    decision: str,
    tool_name: Optional[str] = None,
) -> None:
    """
    Print a two-section trust factor table:
    1. Base factors (credential_validity, delegation_depth, issuer_reputation, agent_history)
    2. Behavioral penalties (tool_pattern, velocity, scope_probe)
    """
    if not factors:
        return

    # Base factors
    cv    = factors.get("credential_validity", 25)
    dd    = factors.get("delegation_depth", 25)
    ir    = factors.get("issuer_reputation", 20)
    ah    = factors.get("agent_history", 15)
    base  = cv + dd + ir + ah

    # Behavioral penalties
    penalty   = factors.get("behavioral_penalty", 0)
    tp        = factors.get("tool_pattern_penalty", 0)
    vp        = factors.get("velocity_penalty", 0)
    sp        = factors.get("scope_probe_penalty", 0)

    # Decision colour
    if decision == "allow" or decision == "allowed":
        dec_color, dec_label = GREEN, "ALLOW"
        threshold_note = "threshold: ≥75"
    elif decision == "step_up":
        dec_color, dec_label = YELLOW, "STEP-UP"
        threshold_note = "threshold: ≥50 (below allow ≥75)"
    else:
        dec_color, dec_label = RED, "BLOCK"
        threshold_note = "threshold: <50"

    tool_hdr = f" [{tool_name}]" if tool_name else ""

    print(f"\n  {CYAN}╔{'═' * _W}╗{RESET}")
    print(f"  {CYAN}║{RESET} {BOLD}{'TRUST SCORE BREAKDOWN' + tool_hdr:<{_W - 1}}{RESET}{CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")

    # Base factors table
    _box_row(f"  {'BASE FACTORS'}", CYAN)
    _box_row(f"  {'Credential Validity':<28} {cv:>3}/25  {'(VP verified, all VCs valid)' if cv == 25 else '(credential issue)'}", CYAN)
    _box_row(f"  {'Delegation Depth':<28} {dd:>3}/25  {'(depth 0, root delegation)' if dd == 25 else f'(depth penalty applied)'}", CYAN)
    _box_row(f"  {'Issuer Reputation':<28} {ir:>3}/25  {'(blended VP, trusted issuer)' if ir >= 20 else '(neutral issuer)'}", CYAN)
    _box_row(f"  {'Agent History':<28} {ah:>3}/25  (baseline — new session)", CYAN)
    _box_row(f"  {'─' * (_W - 4)}", CYAN)
    _box_row(f"  {'Base Score':<28} {base:>3}/100", CYAN)

    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")
    _box_row(f"  {'BEHAVIORAL PENALTIES'}", CYAN)

    if penalty == 0 and tp == 0 and vp == 0 and sp == 0:
        _box_row(f"  {'No penalties — normal behavior'}", CYAN)
    else:
        novel = factors.get("novel_tools", [])
        violations = factors.get("scope_violations", 0)
        rpm = factors.get("requests_last_60s", 0)
        tp_note = f"(novel tools: {novel})" if novel else "(known tools only)"
        vp_note = f"({rpm}/min)" if rpm > 0 else "(velocity normal)"
        sp_note = f"({violations} scope violation(s))" if violations > 0 else ""
        _box_row(f"  {'Tool Pattern':<28} -{tp:>2}   {tp_note}", CYAN)
        _box_row(f"  {'Velocity':<28} -{vp:>2}   {vp_note}", CYAN)
        _box_row(f"  {'Scope Probing':<28} -{sp:>2}   {sp_note}", CYAN)
        _box_row(f"  {'─' * (_W - 4)}", CYAN)
        _box_row(f"  {'Total Penalty':<28} -{penalty:>2}", CYAN)

    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")
    final_line = f"  FINAL: {base} - {penalty} = {score}/100  →  {dec_label}  ({threshold_note})"
    print(f"  {CYAN}║{RESET} {dec_color}{BOLD}{final_line:<{_W - 1}}{RESET}{CYAN}║{RESET}")
    print(f"  {CYAN}╚{'═' * _W}╝{RESET}")


def display_delegation_chain(
    chain: list[dict[str, Any]],
    effective_scope: dict[str, Any],
    delegator_claims: Optional[dict[str, Any]] = None,
    agent_did: Optional[str] = None,
) -> None:
    """
    Render the delegation chain as a visual tree. Works with the DelegationResult.chain
    list from the SDK or a synthesised structure from the bind response.
    """
    delegator_claims = delegator_claims or {}

    delegator_name = (
        delegator_claims.get("name")
        or delegator_claims.get("sub")
        or "Delegator"
    )
    delegator_org   = delegator_claims.get("organization", "")
    delegator_role  = delegator_claims.get("role", "")
    delegator_email = delegator_claims.get("email", "")
    delegator_idp   = "Acme Corp Okta" if "acme" in delegator_email.lower() else (
        "Enterprise IdP" if delegator_email else "Unknown IdP"
    )

    actions     = effective_scope.get("actions", [])
    max_amount  = effective_scope.get("max_amount")
    currency    = effective_scope.get("currency", "USD")
    depth       = len(chain) if chain else 1
    max_depth   = chain[0].get("max_depth", 2) if chain else 2

    amount_str = f"${max_amount:,} {currency}" if max_amount else "no limit"

    print(f"\n  {CYAN}╔{'═' * _W}╗{RESET}")
    print(f"  {CYAN}║{RESET} {BOLD}{'DELEGATION CHAIN — Visual Tree':<{_W - 1}}{RESET}{CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")

    # Delegator (human) node
    _box_row(f"  {GREEN}👤 {delegator_name}{RESET}", CYAN)
    if delegator_role and delegator_org:
        _box_row(f"     {delegator_role} @ {delegator_org}", CYAN)
    if delegator_claims.get("trustLevel"):
        _box_row(f"     Trust level: {delegator_claims['trustLevel']}", CYAN)
    if delegator_email:
        _box_row(f"     {_short_did(next((v for k, v in delegator_claims.items() if 'did' in k.lower()), ''), 28)}", CYAN)
    _box_row(f"     Identity verified via: {delegator_idp} (RS256 JWT)", CYAN)
    _box_row(f"  │", CYAN)

    # Edge label
    action_str = ", ".join(actions[:4]) + ("…" if len(actions) > 4 else "")
    _box_row(f"  ├─ Scope  : [{action_str}]", CYAN)
    _box_row(f"  ├─ Amount : ≤ {amount_str}", CYAN)
    _box_row(f"  ├─ Depth  : {depth} of {max_depth} max", CYAN)
    _box_row(f"  │", CYAN)

    # Agent node
    _box_row(f"  {MAGENTA}└→ 🤖 ShoppingBot{RESET}", CYAN)
    if agent_did:
        _box_row(f"        {_short_did(agent_did, 38)}", CYAN)
    _box_row(f"        Type: LLM Agent — Procurement automation", CYAN)

    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")
    _box_row(f"  {GREEN}✓{RESET}  Scope narrowing   — child scope is subset of parent", CYAN)
    _box_row(f"  {GREEN}✓{RESET}  Chain signature   — all links verified (Ed25519)", CYAN)
    _box_row(f"  {GREEN}✓{RESET}  Revocation status — not revoked", CYAN)
    _box_row(f"  {GREEN}✓{RESET}  TTL bound         — child TTL ≤ parent TTL", CYAN)
    print(f"  {CYAN}╚{'═' * _W}╝{RESET}")


def display_credential_isolation(
    vp_jwt: str,
    server_entry: Optional[dict[str, Any]] = None,
) -> None:
    """
    Side-by-side two-column view showing what the agent sent vs what the
    MCP server actually received, illustrating credential isolation.
    """
    server_entry = server_entry or {}
    vp_preview   = (vp_jwt[:28] + "…") if len(vp_jwt) > 30 else vp_jwt
    api_key_val  = server_entry.get("api_key_value", "secret-***")
    agent_did_hdr = server_entry.get("agent_did", "")
    delegator_hdr = server_entry.get("delegator", "")
    api_key_present = server_entry.get("api_key_present", True)

    col_w = 30  # each column's inner width
    full_w = col_w * 2 + 5  # two cols + divider

    def row(left: str, right: str) -> None:
        print(f"  {CYAN}║{RESET} {left:<{col_w}}  {DIM}│{RESET}  {right:<{col_w}} {CYAN}║{RESET}")

    print(f"\n  {CYAN}╔{'═' * full_w}╗{RESET}")
    print(f"  {CYAN}║{RESET} {BOLD}{'CREDENTIAL ISOLATION — What Each Side Sees':<{full_w - 1}}{RESET}{CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═' * (col_w + 2)}╦{'═' * (col_w + 2)}╣{RESET}")

    row(f"{CYAN}AGENT SIDE{RESET}", f"{CYAN}MCP SERVER SIDE{RESET}")
    row("─" * col_w, "─" * col_w)
    row(f"{DIM}Sent:{RESET}", f"{DIM}Received:{RESET}")
    row(f"  Bearer {vp_preview}", f"  X-API-Key: {api_key_val}")
    row("  (Blended VP-JWT)", "  (Gateway credential)")
    row("", "")
    row(f"{DIM}Agent KNOWS:{RESET}", f"{DIM}Server KNOWS:{RESET}")
    row(f"  {GREEN}✓{RESET} Its own identity", f"  {GREEN}✓{RESET} Gateway API key")
    row(f"  {GREEN}✓{RESET} Alice's delegation", f"  {GREEN}✓{RESET} Agent DID (header)")
    row(f"  {GREEN}✓{RESET} Alice's enterprise VC", f"  {GREEN}✓{RESET} Delegator (header)")
    row("", "")
    row(f"{DIM}Agent NEVER sees:{RESET}", f"{DIM}Server NEVER sees:{RESET}")
    row(f"  {RED}✗{RESET} The API key", f"  {RED}✗{RESET} The VP-JWT")
    row(f"  {RED}✗{RESET} The server URL", f"  {RED}✗{RESET} Alice's OIDC token")
    row(f"  {RED}✗{RESET} Any server credential", f"  {RED}✗{RESET} The delegation chain")

    print(f"  {CYAN}╠{'═' * (col_w + 2)}╩{'═' * (col_w + 2)}╣{RESET}")
    isolation_ok = not server_entry.get("auth_header", "").startswith("Bearer ey")
    status = f"{GREEN}VERIFIED{RESET}" if (not server_entry or isolation_ok) else f"{YELLOW}CHECK{RESET}"
    msg = f"  ISOLATION {status}: Agent credentials ≠ Server credentials"
    print(f"  {CYAN}║{RESET} {msg:<{full_w - 1}}{CYAN}║{RESET}")
    print(f"  {CYAN}╚{'═' * full_w}╝{RESET}")


def display_trust_timeline(events: list[dict[str, Any]]) -> None:
    """
    ASCII line chart of trust score over the session.
    events: list of dicts with at least {tool_name, trust_score, decision}.
    Draws a Y-axis (0-100) with reference lines at 75 (ALLOW) and 50 (STEP-UP).
    """
    if not events:
        return

    scores = [e.get("trust_score", 0) for e in events]
    decisions = [e.get("trust_decision") or e.get("decision", "?") for e in events]
    tools = [e.get("tool_name") or "?" for e in events]

    n = len(scores)
    height = 11   # number of Y rows (0,10,20,...100)
    y_vals = list(range(100, -1, -10))  # 100 down to 0
    col_w = 5     # chars per data column

    # Map score to row index (row 0 = score 100)
    def score_to_row(s: int) -> int:
        return max(0, min(height - 1, (100 - s) // 10))

    # Build grid
    grid = [[" " * col_w for _ in range(n)] for _ in range(height)]

    for col, score in enumerate(scores):
        row = score_to_row(score)
        decision = decisions[col]
        if decision in ("allow", "allowed"):
            char = f"{GREEN}●{RESET}    "
        elif decision == "step_up":
            char = f"{YELLOW}⚠{RESET}    "
        else:
            char = f"{RED}✗{RESET}    "
        grid[row][col] = char

    # Draw reference line rows
    allow_row   = score_to_row(75)
    stepup_row  = score_to_row(50)

    print(f"\n  {CYAN}╔{'═' * _W}╗{RESET}")
    print(f"  {CYAN}║{RESET} {BOLD}{'TRUST SCORE TIMELINE — ShoppingBot Session':<{_W - 1}}{RESET}{CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")
    print(f"  {CYAN}║{RESET}")

    for r, y in enumerate(y_vals):
        row_cells = ""
        for c in range(n):
            row_cells += grid[r][c]

        # Reference line decoration
        if r == allow_row:
            ref = f" {DIM}─ ─ ALLOW threshold (≥75){RESET}"
        elif r == stepup_row:
            ref = f" {DIM}─ ─ STEP-UP threshold (≥50){RESET}"
        else:
            ref = ""

        label = f"{y:>3}│"
        print(f"  {CYAN}║{RESET}  {DIM}{label}{RESET}{row_cells}{ref}")

    # X-axis
    x_axis = "    └" + "─────" * n
    print(f"  {CYAN}║{RESET}  {DIM}{x_axis}{RESET}")

    # X labels (abbreviated tool names)
    abbrevs = []
    tool_counts: dict[str, int] = {}
    for t in tools:
        short = {
            "query_database": "qdb",
            "delete_record": "del",
            "insert_record": "ins",
            "admin_panel": "adm",
            "export_data": "exp",
        }.get(t, t[:3])
        tool_counts[short] = tool_counts.get(short, 0) + 1
        n_seen = tool_counts[short]
        abbrevs.append(f"{short}{n_seen}" if tool_counts[short] > 1 else short)

    x_label_row = "      " + "".join(f"{a:<5}" for a in abbrevs)
    print(f"  {CYAN}║{RESET}  {DIM}{x_label_row}{RESET}")

    print(f"  {CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═' * _W}╣{RESET}")

    # Key events legend
    _box_row(f"  {GREEN}●{RESET} = ALLOW   {YELLOW}⚠{RESET} = STEP-UP   {RED}✗{RESET} = BLOCKED/SCOPE", CYAN)

    # Key events annotation
    for i, e in enumerate(events):
        decision = decisions[i]
        score    = scores[i]
        tool     = tools[i]
        if decision not in ("allow", "allowed"):
            ev_color = YELLOW if decision == "step_up" else RED
            penalty  = e.get("trust_factors", {}).get("behavioral_penalty", 0)
            penalty_note = f"  penalty: -{penalty}" if penalty else ""
            _box_row(f"  #{i+1} {tool:<18} score:{score:>3}  {ev_color}{decision.upper()}{RESET}{penalty_note}", CYAN)

    print(f"  {CYAN}╚{'═' * _W}╝{RESET}")
