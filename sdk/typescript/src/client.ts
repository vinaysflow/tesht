/** HTTP client for the Tesht (Pramana) server API. */
export class TeshtClient {
  baseUrl: string;
  token?: string;

  constructor(baseUrl = "http://localhost:8000", token?: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async createAgent(name: string) {
    return this.post("/v1/agents", { name });
  }

  async issueCredential(params: {
    issuer_agent_id: string;
    subject_did: string;
    credential_type?: string;
    ttl_seconds?: number;
    subject_claims?: Record<string, unknown>;
  }) {
    return this.post("/v1/credentials/issue", {
      credential_type: "AgentCredential",
      ...params,
    });
  }

  async verifyCredential(jwt: string) {
    return this.post("/v1/credentials/verify", { jwt });
  }

  async revokeCredential(credentialId: string) {
    return this.post(`/v1/credentials/${credentialId}/revoke`, {});
  }

  // ── Session / Decision / Mandate ────────────────────────────────────

  async createSession(params: {
    agent_did: string;
    human_did?: string;
    human_proof_jwt?: string;
    agent_vc_jwt?: string;
    delegation_jwt?: string;
    scope?: Record<string, unknown>;
    packs?: string[];
    ttl_seconds?: number;
    metadata?: Record<string, unknown>;
  }, idempotencyKey?: string) {
    return this.post(
      "/v1/sessions",
      {
        packs: ["core"],
        ttl_seconds: 3600,
        scope: {},
        metadata: {},
        ...params,
      },
      idempotencyKey,
    );
  }

  async getSession(sessionId: string) {
    return this.get(`/v1/sessions/${sessionId}`);
  }

  /** Evaluate an action → allow | step_up | block */
  async decide(
    sessionId: string,
    params: {
      action: string;
      resource?: string;
      amount?: number;
      currency?: string;
      tool_name?: string;
      metadata?: Record<string, unknown>;
    },
  ) {
    return this.post(`/v1/sessions/${sessionId}/actions`, {
      metadata: {},
      ...params,
    });
  }

  async stepUp(
    sessionId: string,
    params: {
      human_proof_jwt?: string;
      fresh_vp_jwt?: string;
      metadata?: Record<string, unknown>;
    } = {},
  ) {
    return this.post(`/v1/sessions/${sessionId}/step_up`, {
      metadata: {},
      ...params,
    });
  }

  async revokeSession(
    sessionId: string,
    params: { cascade?: boolean; reason?: string } = {},
  ) {
    return this.post(`/v1/sessions/${sessionId}/revoke`, {
      cascade: true,
      ...params,
    });
  }

  async createIntentMandate(params: {
    agent_did: string;
    max_amount: number;
    currency?: string;
    intent?: Record<string, unknown>;
  }) {
    return this.post("/v1/commerce/mandates/intent", {
      agent_did: params.agent_did,
      intent: {
        max_amount: params.max_amount,
        currency: params.currency ?? "USD",
        ...(params.intent ?? {}),
      },
    });
  }

  async createCartMandate(params: {
    agent_did: string;
    intent_mandate_jwt: string;
    cart: Record<string, unknown>;
  }) {
    return this.post("/v1/commerce/mandates/cart", params);
  }

  async verifyMandate(jwt: string, mandateType?: string) {
    return this.post("/v1/commerce/mandates/verify", {
      jwt,
      ...(mandateType ? { mandate_type: mandateType } : {}),
    });
  }

  private headers(idempotencyKey?: string): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.token) h.Authorization = `Bearer ${this.token}`;
    if (idempotencyKey) h["Idempotency-Key"] = idempotencyKey;
    return h;
  }

  private async post(path: string, body: unknown, idempotencyKey?: string) {
    const res = await fetch(this.baseUrl.replace(/\/$/, "") + path, {
      method: "POST",
      headers: this.headers(idempotencyKey),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return res.json();
  }

  private async get(path: string) {
    const res = await fetch(this.baseUrl.replace(/\/$/, "") + path, {
      method: "GET",
      headers: this.headers(),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return res.json();
  }
}
