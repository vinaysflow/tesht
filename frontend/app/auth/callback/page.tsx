"use client";

import { useEffect, useState } from "react";
import { setAccessToken } from "../../../lib/api";

export default function AuthCallback() {
  const [msg, setMsg] = useState("Exchanging code…");

  useEffect(() => {
    async function run() {
      const kcBase = process.env.NEXT_PUBLIC_KEYCLOAK_URL || "http://127.0.0.1:8080";
      const realm = process.env.NEXT_PUBLIC_KEYCLOAK_REALM || "tesht";
      const clientId = process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID || "tesht-api";

      const url = new URL(window.location.href);
      const code = url.searchParams.get("code");
      if (!code) {
        setMsg("Missing code");
        return;
      }

      const verifier = sessionStorage.getItem("pkce_verifier");
      if (!verifier) {
        setMsg("Missing PKCE verifier");
        return;
      }

      const redirectUri = `${window.location.origin}/auth/callback`;

      const tokenUrl = `${kcBase}/realms/${realm}/protocol/openid-connect/token`;
      const form = new URLSearchParams();
      form.set("grant_type", "authorization_code");
      form.set("client_id", clientId);
      form.set("code", code);
      form.set("redirect_uri", redirectUri);
      form.set("code_verifier", verifier);

      const resp = await fetch(tokenUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });

      if (!resp.ok) {
        setMsg(`Token exchange failed: ${resp.status}`);
        return;
      }

      const data = (await resp.json()) as any;
      const access = data.access_token;
      if (!access) {
        setMsg("No access_token in response");
        return;
      }

      setAccessToken(access);
      setMsg("Login complete. Redirecting…");
      window.location.href = "/";
    }

    run().catch((e) => setMsg(String(e)));
  }, []);

  return (
    <main style={{ maxWidth: 820 }}>
      <h1>Auth callback</h1>
      <p>{msg}</p>
    </main>
  );
}
