import { useState } from "react";

// Checkbox progress is kept in the browser only; the backend does not store it yet.
export default function Playbook({ steps, resource }) {
  const [done, setDone] = useState({});
  const count = steps.filter((_, n) => done[n]).length;
  return (
    <>
      <h3 id="response-playbook" className="font-semibold mt-5 mb-2">Response playbook <span className="mute font-normal text-sm">{count}/{steps.length} done</span></h3>
      <div className="space-y-3">
        {steps.map((s, n) => (
          <label key={n} className="flex gap-3 items-start">
            <input type="checkbox" className="mt-1" checked={!!done[n]} onChange={(e) => setDone({ ...done, [n]: e.target.checked })} />
            <span className="min-w-0">
              <span className={`font-medium ${done[n] ? "line-through mute" : ""}`}>{s.title}</span><br />
              <span className="text-sm mute">{s.action}</span>
              {s.command && <pre className="p-2 mt-1 overflow-x-auto">{resource.startsWith("resource-") ? s.command : s.command.replace(/<(BUCKET|USER|SG_ID)>/g, resource)}</pre>}
            </span>
          </label>
        ))}
      </div>
    </>
  );
}
