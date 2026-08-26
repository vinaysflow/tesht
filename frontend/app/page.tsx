"use client";

import { useEffect, useState } from "react";
import { getAccessToken } from "../lib/api";

export default function Page() {
  const [hasToken, setHasToken] = useState(false);

  useEffect(() => {
    setHasToken(!!getAccessToken());
  }, []);

  return (
    <main style={{ maxWidth: 820 }}>
      <h1>Tesht (Pramana)</h1>
      <p>
        Portable identity and scoped authorization for AI agents — did:web + VC
        issuance, verification, and revocation with signed status lists.
      </p>

      <p>
        <b>Fastest path:</b> <a href="/demo">Guided Demo</a> (one-click flow + isolated demo tenant)
      </p>

      <p>
        <b>Auth</b>: {hasToken ? "Token present" : "No token yet"}
      </p>

      <ul>
        <li><a href="/agentic-commerce"><b>Agentic Commerce</b> (authorize an agent, shop with a trust-gated budget, revoke)</a></li>
        <li><a href="/demo-dashboard"><b>Interactive Demo Dashboard</b> (happy / unhappy / edge path scenarios)</a></li>
        <li><a href="/demo">Guided Demo (drift workflow)</a></li>
        <li><a href="/login">Login (Keycloak, local dev)</a></li>
        <li><a href="/issue">Issue</a></li>
        <li><a href="/verify">Verify (public)</a></li>
        <li><a href="/revoke">Revoke</a></li>
        <li><a href="/audit">Audit</a></li>
      </ul>
    </main>
  );
}
