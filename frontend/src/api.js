// All calls to the FastAPI backend live here.
export const SHARED_VIEW = import.meta.env.VITE_SHARED_VIEW === "true";
const BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

let operatorKey = ""; // Memory only. Never bundle a secret in VITE_* settings.

async function request(path, options = {}, retry = true) {
  let res;
  try {
    res = await fetch(BASE + path, {
      ...options,
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(operatorKey ? { "X-API-Key": operatorKey } : {}),
      },
    });
  } catch {
    throw new Error(`Cannot reach the API at ${BASE}. Is the backend running?`);
  }
  if (res.status === 401 && retry) {
    operatorKey = "";
    const entered = window.prompt("Enter the project operator API key for this action. Do not enter AWS credentials.");
    if (entered?.trim()) {
      operatorKey = entered.trim();
      return request(path, options, false);
    }
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
    } catch { /* keep default message */ }
    throw new Error(msg);
  }
  return res.json();
}

async function sharedRecords() {
  try {
    const res = await fetch(BASE + "/public/incidents", { signal: AbortSignal.timeout(12000) });
    if (!res.ok) throw new Error("Shared API unavailable");
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error("Invalid shared API response");
    return data;
  } catch {
    const res = await fetch("/review-archive.json");
    if (!res.ok) throw new Error("The shared review archive is unavailable. Please try again later.");
    const data = await res.json();
    if (!Array.isArray(data.incidents)) throw new Error("The review archive is invalid.");
    return data.incidents.map(i => ({ ...i, archive_fallback: true }));
  }
}

function writable() {
  if (SHARED_VIEW) throw new Error("This shared dashboard is read-only.");
}

export const getIncidents = () => SHARED_VIEW ? sharedRecords() : request("/incidents");
export const getIncident = async (id) => {
  if (!SHARED_VIEW) return request(`/incidents/${id}`);
  const items = await sharedRecords();
  const incident = items.find(i => i.incident_id === id);
  if (!incident) throw new Error("Incident not found in the shared review");
  return incident;
};
export const postEvent = (rawEvent) => { writable(); return request("/events", { method: "POST", body: JSON.stringify(rawEvent) }); };
export const loadDemo = (reset = false) => { writable(); return request(`/demo/load?reset=${reset}`, { method: "POST" }); };
export const updateStatus = (id, status, note = "") => {
  writable();
  return request(`/incidents/${id}/status`, { method: "PATCH", body: JSON.stringify({ status, note }) });
};
