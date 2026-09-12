const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function getToken() {
  return localStorage.getItem("token");
}

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = data.detail || detail;
    } catch {
      /* ignore parse errors */
    }
    throw new Error(detail);
  }

  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  signup: (payload) => request("/auth/signup", { method: "POST", body: payload, auth: false }),
  login: (payload) => request("/auth/login", { method: "POST", body: payload, auth: false }),

  listAccounts: () => request("/accounts"),
  createAccount: (payload) => request("/accounts", { method: "POST", body: payload }),
  deleteAccount: (id) => request(`/accounts/${id}`, { method: "DELETE" }),

  triggerScan: (accountId) => request(`/scans/trigger/${accountId}`, { method: "POST" }),
  getScan: (scanId) => request(`/scans/${scanId}`),
  listScansForAccount: (accountId) => request(`/scans/account/${accountId}`),

  chat: (payload) => request("/chat", { method: "POST", body: payload }),
};

export function saveToken(token) {
  localStorage.setItem("token", token);
}

export function clearToken() {
  localStorage.removeItem("token");
}

export function isLoggedIn() {
  return Boolean(getToken());
}
