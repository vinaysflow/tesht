export function apiBase(): string {
  // In single-origin deployments (Spaces), browser should call the same origin.
  // If NEXT_PUBLIC_API_URL is set (local multi-container), use it.
  return process.env.NEXT_PUBLIC_API_URL || "";
}

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("tesht_access_token");
}

export function setAccessToken(token: string) {
  window.localStorage.setItem("tesht_access_token", token);
}

export function clearAccessToken() {
  window.localStorage.removeItem("tesht_access_token");
}

function authHeaders(): Record<string, string> {
  const t = getAccessToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function formatError(res: Response): Promise<string> {
  const rid = res.headers.get("x-request-id") || res.headers.get("X-Request-ID") || "";
  const ct = res.headers.get("content-type") || "";
  const text = await res.text();

  if (ct.includes("application/json")) {
    try {
      const data = JSON.parse(text);
      const msg = typeof data?.error === "string" ? data.error : text;
      const reqId = typeof data?.request_id === "string" ? data.request_id : rid;
      return reqId ? `${msg} (request_id=${reqId})` : msg;
    } catch {
      // fall through
    }
  }

  return rid ? `${text} (request_id=${rid})` : text;
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const base = apiBase();
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const msg = await formatError(res);
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  return (await res.json()) as T;
}

export async function apiGet<T>(path: string): Promise<T> {
  const base = apiBase();
  const res = await fetch(`${base}${path}`, {
    method: "GET",
    headers: { ...authHeaders() },
  });
  if (!res.ok) {
    const msg = await formatError(res);
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  return (await res.json()) as T;
}
