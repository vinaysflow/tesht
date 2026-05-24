"""
idp_bridge.config
~~~~~~~~~~~~~~~~~
Trusted IdP registry configuration.

Declarative settings are loaded from YAML (issuer URLs, JWKS endpoints,
claim mappings).  Runtime-only objects (PyJWKClient instances) are created
in the validator layer.

YAML values support ``${ENV_VAR:-default}`` environment variable expansion
so that real Okta credentials can be injected at runtime without committing
secrets to the YAML file.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env_vars(value: Any) -> Any:
    """
    Recursively expand ``${VAR:-default}`` placeholders in YAML string values.

    Supports:
      - ``${VAR}``           — required env var (kept as-is if not set)
      - ``${VAR:-default}``  — uses ``default`` if VAR is unset or empty
    """
    if isinstance(value, str):
        def _replace(m: re.Match) -> str:
            var_name = m.group(1)
            default = m.group(2)  # None if no :- present
            env_val = os.environ.get(var_name)
            if env_val:
                return env_val
            if default is not None:
                return default
            return m.group(0)  # leave placeholder intact if no default and not set
        return _ENV_VAR_PATTERN.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


@dataclass
class TrustedIdP:
    """One trusted enterprise identity provider."""

    name: str
    issuer: str
    jwks_uri: str
    audience: Optional[str] = None
    claim_mapping: dict[str, str] = field(default_factory=dict)
    """Maps VC claim name -> OIDC token claim name.

    Example: {"name": "name", "email": "email", "organization": "org"}
    """
    default_credential_type: str = "OrganizationalRoleCredential"
    allowed_algorithms: list[str] = field(default_factory=lambda: ["RS256"])


@dataclass
class IdPRegistryConfig:
    """Registry of all trusted identity providers."""

    providers: dict[str, TrustedIdP] = field(default_factory=dict)

    def find_by_issuer(self, issuer: str) -> Optional[tuple[str, TrustedIdP]]:
        """Return (provider_id, TrustedIdP) for the given issuer URL, or None.

        Normalizes trailing slashes so that
        ``https://example.auth0.com`` matches ``https://example.auth0.com/``.
        """
        issuer_norm = issuer.rstrip("/")
        for pid, idp in self.providers.items():
            if idp.issuer.rstrip("/") == issuer_norm:
                return pid, idp
        return None


def load_idp_config(path: str | Path) -> IdPRegistryConfig:
    """Load the IdP registry from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"IdP config not found: {path}")

    with open(path) as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    # Expand ${ENV_VAR:-default} placeholders before parsing
    raw = _expand_env_vars(raw)

    providers: dict[str, TrustedIdP] = {}
    for pid, pdata in (raw.get("providers") or {}).items():
        providers[pid] = TrustedIdP(
            name=pdata.get("name", pid),
            issuer=pdata["issuer"],
            jwks_uri=pdata["jwks_uri"],
            audience=pdata.get("audience"),
            claim_mapping=pdata.get("claim_mapping", {}),
            default_credential_type=pdata.get(
                "default_credential_type", "OrganizationalRoleCredential"
            ),
            allowed_algorithms=pdata.get("allowed_algorithms", ["RS256"]),
        )

    return IdPRegistryConfig(providers=providers)
