import { STATUSES, fmt, sevColor, originLabel } from "../constants.js";
import Playbook from "./Playbook.jsx";
import History from "./History.jsx";

export default function IncidentDetail({ incident: i, loading = true, error, busy, disabled = false, readOnly = false, onAdvance }) {
  if (!i) {
    return (
      <div className="incident-detail panel p-5">
        {error ? <p role="alert" className="text-sm">{error}</p> : <p className="mute">{loading ? "Loading incident…" : "Select an incident to view its details."}</p>}
      </div>
    );
  }
  const k = STATUSES.indexOf(i.status);
  const next = STATUSES[k + 1];
  const e = i.event;
  const facts = [
    ["Cloud", i.provider.toUpperCase()], ["Actor", i.actor], ["Resource", `${i.resource_type} · ${i.resource_id}`],
    ["Time", fmt(e.event_time)], ["Event", e.event_name], ["Source IP", e.source_ip || "unknown"],
    ["Account", e.account_id], ["Region", e.region],
    ["Event origin", originLabel(e.origin)], ["Event ID", e.event_id],
  ];
  return (
    <div className="incident-detail panel p-5">
      {error && <p role="alert" className="text-sm mb-3 p-2 rounded" style={{ borderLeft: "4px solid var(--Critical)" }}>{error}</p>}
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <span className="severity-badge" style={{ "--severity": sevColor(i.severity) }}>{i.severity}</span>
        <span className="text-xs mute">{i.incident_id} · {i.type.replaceAll("_", " ")}</span>
      </div>
      <h2 className="text-xl font-bold">{i.title}</h2>
      <p className="text-sm mt-1">{i.description}</p>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm mt-4">
        {facts.filter(([label]) => !readOnly || !["Account", "Actor", "Source IP"].includes(label)).map(([label, value]) => (
          <div key={label} className="min-w-0"><dt className="text-xs mute">{label}</dt><dd className="break-words">{value}</dd></div>
        ))}
      </dl>
      <p className="mute text-sm mt-3">
        {e.origin === "demo" || e.origin === "fixture"
          ? "Simulated event for demonstration and testing."
          : e.origin === "aws-cloudtrail"
            ? "Imported from CloudTrail by the local collector. This records a past action; the resource may already be cleaned up."
            : "Submitted event; AWS origin has not been verified."}
      </p>
      <pre className="p-2 mt-3 overflow-x-auto" aria-label="Event details">{JSON.stringify(e.details, null, 2)}</pre>

      <h3 className="font-semibold mt-5 mb-2">Status</h3>
      <div className="flex items-center gap-2 flex-wrap">
        {STATUSES.map((s, n) => (
          <span key={s} className={`text-sm px-2 py-1 rounded border line ${n <= k ? "font-semibold" : "mute"}`}
                style={n === k ? { background: "var(--sel)" } : {}}>{n < k ? "✓ " : ""}{s}</span>
        ))}
        {next && !readOnly && (
          <button disabled={busy || disabled} onClick={() => onAdvance(next)} className="button primary ml-auto">{busy ? "Saving…" : `Mark as ${next}`}</button>
        )}
      </div>

      <h3 className="font-semibold mt-5 mb-1">Why {i.severity.toLowerCase()} (score {i.severity_score})</h3>
      <ul className="text-sm list-disc pl-5">{i.severity_reasons.map((r) => <li key={r}>{r}</li>)}</ul>

      <p className="mute text-sm mt-5">Playbook steps are manual guidance. Changing status does not execute AWS commands.</p>
      {!readOnly && <Playbook key={i.incident_id} steps={i.playbook} resource={i.resource_id} />}
      {!readOnly && <History history={i.history} />}
    </div>
  );
}
