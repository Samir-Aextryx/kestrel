export type User = { id: string; email: string; name: string; role: "admin" | "analyst" | "viewer" };

function csrf() {
  const match = document.cookie.match(/(?:^|;\s*)kestrel_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set("content-type", "application/json");
  const method = (options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) headers.set("x-csrf-token", csrf());
  const res = await fetch(`/api${path}`, { ...options, headers, credentials: "same-origin" });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const data = await res.json();
      message = data.error || message;
    } catch {
      /* ignore */
    }
    throw new ApiError(message, res.status);
  }
  if (res.status === 204) return undefined as T;
  const type = res.headers.get("content-type") || "";
  if (type.includes("application/json")) return (await res.json()) as T;
  return (await res.text()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body: JSON.stringify(body ?? {}) }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: "PUT", body: JSON.stringify(body ?? {}) }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

export async function login(email: string, password: string) {
  return api.post<{ csrf: string; user: User }>("/auth/login", { email, password });
}

export async function logout() {
  return api.post("/auth/logout");
}

export async function me() {
  return api.get<{ user: User; csrf: string | null }>("/auth/me");
}

export function streamScan(scanId: string, after: number, onEvent: (event: unknown) => void) {
  const source = new EventSource(`/api/scans/${scanId}/stream?after=${after}`);
  source.onmessage = (event) => {
    try {
      onEvent(JSON.parse(event.data));
    } catch {
      /* ignore */
    }
  };
  return () => source.close();
}
