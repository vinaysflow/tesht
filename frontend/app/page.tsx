"use client";

import { useEffect, useState } from "react";
import { getAccessToken } from "../lib/api";

export default function Page() {
  const [hasToken, setHasToken] = useState(false);
  const [isHfSpace, setIsHfSpace] = useState(false);

  useEffect(() => {
    setHasToken(!!getAccessToken());
    if (typeof window !== "undefined") {
      setIsHfSpace(window.location.host.endsWith(".hf.space"));
    }
  }, []);

  return (
    <main style={{ maxWidth: 820 }}>
      <h1>Pramana Protocol</h1>
      <p>did:web + VC issuance/verification/revocation with signed status lists.</p>

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
        {!isHfSpace && <li><a href="/login">Login (Keycloak, local dev)</a></li>}
        <li><a href="/issue">Issue</a></li>
        <li><a href="/verify">Verify (public)</a></li>
        <li><a href="/revoke">Revoke</a></li>
        <li><a href="/audit">Audit</a></li>
      </ul>
    </main>
  );
}
