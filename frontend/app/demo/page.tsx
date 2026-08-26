"use client";

import { useEffect, useMemo, useState } from "react";
import { apiBase, apiPost, clearAccessToken, getAccessToken, setAccessToken } from "../../lib/api";

type DemoSessionResp = {
  token: string;
  tenant_id: string;
  expires_in: number;
};

type DriftResp = {
  tenant_id: string;
  issuer_agent_id: string;
  issuer_did: string;
  subject_agent_id: string;
  subject_did: string;
  credential_id: string;
  vc_jwt: string;
  status_list_id: string;
  status_list_index: number;
  status_list_url: string;
  verify_before: any;
  revoke: any;
  verify_after: any;
};

function CopyButton({ text }: { text: string }) {
  async function copy() {
    await navigator.clipboard.writeText(text);
  }
  return (
    <button
      onClick={copy}
      style={{ marginLeft: 8, fontSize: 12, padding: "4px 8px" }}
      title="Copy to clipboard"
    >
      Copy
    </button>
  );
}

function codeBlock(text: string) {
  return (
    <pre style={{ padding: 12, background: "#f6f6f6", overflowX: "auto", whiteSpace: "pre-wrap" }}>{text}</pre>
  );
}

export default function DemoPage() {
  const base = apiBase();
  const [tenantId, setTenantId] = useState<string>("");
  const [status, setStatus] = useState<string>("Initializing…");
  const [result, setResult] = useState<DriftResp | null>(null);
  const [error, setError] = useState<string>("");

  const token = useMemo(() => getAccessToken() || "", []);

  async function ensureSession() {
    const existing = getAccessToken();
    if (existing) {
      setStatus("Session ready");
      return;
    }

    setStatus("Creating demo session…");
    const res = await fetch(`${base}/v1/demo/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
    }
    const data = (await res.json()) as DemoSessionResp;
    setAccessToken(data.token);
    setTenantId(data.tenant_id);
    setStatus("Session ready");
  }

  async function runDemo() {
    setError("");
    setResult(null);
    setStatus("Running drift demo…");
    try {
      const resp = await apiPost<DriftResp>("/v1/workflows/drift-demo", {});
      setResult(resp);
      setTenantId(resp.tenant_id || tenantId);
      setStatus("Done");
    } catch (e: any) {
      const msg = String(e?.message || e);
      // If token expired/invalid, clear + re-create a session and retry once.
      if (msg.includes("401") || msg.toLowerCase().includes("invalid token")) {
        try {
          clearAccessToken();
          await ensureSession();
          const resp = await apiPost<DriftResp>("/v1/workflows/drift-demo", {});
          setResult(resp);
          setTenantId(resp.tenant_id || tenantId);
          setStatus("Done");
          return;
        } catch (e2: any) {
          setError(String(e2?.message || e2));
          setStatus("Failed");
          return;
        }
      }
      setError(msg);
      setStatus("Failed");
    }
  }

  async function resetDemo() {
    setError("");
    setStatus("Resetting…");
    try {
      const resp = await apiPost<any>("/v1/demo/reset", {});
      setResult(null);
      setStatus(`Reset complete (${resp.tenant_id})`);
    } catch (e: any) {
      setError(String(e?.message || e));
      setStatus("Reset failed");
    }
  }

  useEffect(() => {
    ensureSession().catch((e) => {
      setError(String(e?.message || e));
      setStatus("Failed");
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const curlWorkflow = result
    ? `curl -sSf -X POST ${window.location.origin}/v1/workflows/drift-demo \\\n  -H "Authorization: Bearer <YOUR_TOKEN>" \\\n  -H "content-type: application/json" \\\n  -d '{}' | python -m json.tool`
    : "";

  const curlVerify = result
    ? `curl -sSf -X POST ${window.location.origin}/v1/credentials/verify \\\n  -H "content-type: application/json" \\\n  -d '{"jwt":"${result.vc_jwt}"}' | python -m json.tool`
    : "";

  return (
    <main style={{ maxWidth: 1100 }}>
      <h1>Guided Demo</h1>
      <p>
        This demo creates an isolated tenant for your session, issues a VC, verifies it, revokes it, then verifies again.
      </p>
      <p style={{ marginTop: 8 }}>
        <b>Give feedback:</b>{" "}
        <a
          href="https://huggingface.co/spaces/aurviaglobal/tesht-demo/discussions"
          target="_blank"
          rel="noreferrer"
        >
          Space Community
        </a>{" "}
        (please include any <code>request_id</code> shown in errors)
      </p>

      <div style={{ display: "grid", gap: 6, marginTop: 12 }}>
        <div>
          <b>Status:</b> {status}
        </div>
        <div>
          <b>Tenant:</b> {tenantId || "(assigned on first call)"}
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button onClick={runDemo}>Run Drift Demo</button>
        <button onClick={resetDemo}>Reset my demo</button>
      </div>

      {error && (
        <div style={{ marginTop: 16, padding: 12, border: "1px solid #f2b8b5", borderRadius: 8, background: "#fff5f5" }}>
          <p style={{ color: "crimson", margin: 0 }}>{error}</p>
        </div>
      )}

      {result && (
        <div style={{ marginTop: 20 }}>
          <h2>Artifacts</h2>

          <div style={{ display: "grid", gap: 10 }}>
            <div>
              <b>VC JWT</b>
              <CopyButton text={result.vc_jwt} />
              {codeBlock(result.vc_jwt)}
            </div>

            <div>
              <b>credential_id</b>: <code>{result.credential_id}</code>
              <CopyButton text={result.credential_id} />
            </div>

            <div>
              <b>issuer DID</b>: <code>{result.issuer_did}</code>
              <CopyButton text={result.issuer_did} />
            </div>

            <div>
              <b>subject DID</b>: <code>{result.subject_did}</code>
              <CopyButton text={result.subject_did} />
            </div>

            <div>
              <b>Status list</b>: <a href={result.status_list_url} target="_blank" rel="noreferrer">{result.status_list_url}</a>
              <CopyButton text={result.status_list_url} />
            </div>
          </div>

          <h2 style={{ marginTop: 20 }}>Results</h2>
          <div style={{ display: "grid", gap: 12 }}>
            <div>
              <b>verify_before</b>
              {codeBlock(JSON.stringify(result.verify_before, null, 2))}
            </div>
            <div>
              <b>verify_after</b>
              {codeBlock(JSON.stringify(result.verify_after, null, 2))}
            </div>
          </div>

          <h2 style={{ marginTop: 20 }}>Copy/paste snippets</h2>
          <p>
            Replace <code>&lt;YOUR_TOKEN&gt;</code> with your session token.
          </p>
          {curlWorkflow && (
            <div>
              <b>Run workflow</b>
              <CopyButton text={curlWorkflow} />
              {codeBlock(curlWorkflow)}
            </div>
          )}
          {curlVerify && (
            <div style={{ marginTop: 12 }}>
              <b>Verify VC (public)</b>
              <CopyButton text={curlVerify} />
              {codeBlock(curlVerify)}
            </div>
          )}

          <p style={{ marginTop: 16 }}>
            Portable verifier: <code>python backend/tools/verifier_cli.py --jwt "&lt;VC_JWT&gt;"</code>
          </p>
        </div>
      )}

      <p style={{ marginTop: 16 }}>
        <a href="/">Back</a>
      </p>
    </main>
  );
}
