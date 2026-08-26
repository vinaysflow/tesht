"use client";

import { useMemo } from "react";

function b64url(bytes: Uint8Array): string {
  const s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

function randomVerifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64url(bytes);
}

export default function LoginPage() {
  const kcBase = process.env.NEXT_PUBLIC_KEYCLOAK_URL || "http://127.0.0.1:8080";
  const realm = process.env.NEXT_PUBLIC_KEYCLOAK_REALM || "tesht";
  const clientId = process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID || "tesht-api";

  const redirectUri = useMemo(() => {
    if (typeof window === "undefined") return "";
    return `${window.location.origin}/auth/callback`;
  }, []);

  const isHfSpace = useMemo(() => {
    if (typeof window === "undefined") return false;
    return window.location.host.endsWith(".hf.space");
  }, []);

  async function login() {
    const verifier = randomVerifier();
    sessionStorage.setItem("pkce_verifier", verifier);

    const challenge = b64url(await sha256(verifier));

    const authUrl = new URL(`${kcBase}/realms/${realm}/protocol/openid-connect/auth`);
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid profile email");
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    window.location.href = authUrl.toString();
  }

  return (
    <main style={{ maxWidth: 820 }}>
      <h1>Login</h1>
      {isHfSpace ? (
        <>
          <p>This Hugging Face Space runs in demo mode. Keycloak login is disabled here.</p>
          <p>
            Use the <a href="/demo">Guided Demo</a> (auto session) or the demo token API:
          </p>
          <pre style={{ padding: 12, background: "#f6f6f6", overflowX: "auto", whiteSpace: "pre-wrap" }}>
{`curl -sSf -X POST ${typeof window !== "undefined" ? window.location.origin : ""}/v1/demo/session \\
  -H "content-type: application/json" -d '{}'`}
          </pre>
        </>
      ) : (
        <>
          <p>OIDC login via Keycloak (PKCE).</p>
          <button onClick={login}>Login with Keycloak</button>
        </>
      )}
      <p style={{ marginTop: 16 }}>
        <a href="/">Back</a>
      </p>
    </main>
  );
}
