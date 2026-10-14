import { useCallback, useEffect, useRef, useState } from "react";
import { getIncidents, getIncident, loadDemo, updateStatus, SHARED_VIEW } from "./api.js";
import Stats from "./components/Stats.jsx";
import IncidentFilters from "./components/IncidentFilters.jsx";
import IncidentList from "./components/IncidentList.jsx";
import IncidentDetail from "./components/IncidentDetail.jsx";
import Icon from "./components/Icon.jsx";

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [sevF, setSevF] = useState(null);
  const [stF, setStF] = useState("All");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [action, setAction] = useState(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState(null);
  const [detailError, setDetailError] = useState(null);
  const detailRequest = useRef(0);
  const [query, setQuery] = useState("");
  const [originF, setOriginF] = useState("all");
  const [refreshedAt, setRefreshedAt] = useState(null);
  const [navSection, setNavSection] = useState("overview");

  const refreshList = useCallback(async () => {
    try {
      const latest = await getIncidents();
      setIncidents(latest);
      setRefreshedAt(new Date());
      setError(null);
      return latest;
    } catch (e) {
      setError(e.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshDetail = useCallback(async (id) => {
    const requestId = ++detailRequest.current;
    try {
      const incident = await getIncident(id);
      if (requestId === detailRequest.current) {
        setDetail(incident);
        setDetailError(null);
        return true;
      }
    } catch (e) {
      if (requestId === detailRequest.current) setDetailError(e.message);
    }
    return false;
  }, []);

  useEffect(() => {
    refreshList();
  }, [refreshList]);

  useEffect(() => {
    if (selectedId) {
      refreshDetail(selectedId);
    }
  }, [selectedId, refreshDetail]);

  async function handleRefresh() {
    if (action || busy) return;
    setAction('refresh');
    setNotice('');
    try {
      const [latest, detailOK] = await Promise.all([
        refreshList(),
        selectedId ? refreshDetail(selectedId) : Promise.resolve(true),
      ]);
      if (latest && detailOK) {
        const changed = JSON.stringify(latest) !== JSON.stringify(incidents);
        setNotice(changed
          ? `Dashboard updated. ${latest.length} saved incidents loaded.`
          : `Up to date. ${latest.length} saved incidents; no changes since the last refresh.`);
      }
    } finally {
      setAction(null);
    }
  }

  async function handleAdvance(status) {
    if (action || busy) return;
    setNotice("");
    setBusy(true);

    try {
      await updateStatus(selectedId, status);

      await Promise.all([
        refreshList(),
        refreshDetail(selectedId)
      ]);
    } catch (e) {
      setDetailError(e.message);
    } finally {
      setBusy(false);
    }
  }

  // Sample loading is additive; the API skips events already in the store.
  async function handleLoadDemo() {
    if (action || busy) return;
    setAction('demo');
    setNotice('');
    try {
      const result = await loadDemo();
      const latest = await refreshList();
      if (!latest) return;
      setDetailError(null);
      clearFilters();
      if (selectedId) await refreshDetail(selectedId);
      setNotice(result.incidents_created
        ? `Added ${result.incidents_created} simulated demo incidents. Existing incidents were kept.`
        : `Demo already loaded. ${result.duplicates_skipped} existing demo incidents kept; no duplicates added.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setAction(null);
    }
  }

  const visible = incidents.filter(i => {
    const origin = i.event.origin;
    const matchesSource = originF === "all" || (originF === "other"
      ? !["demo", "aws-cloudtrail"].includes(origin) : origin === originF);
    const text = [i.title, i.actor, i.resource_id, i.incident_id, i.event.event_name, i.event.event_id].join(" ").toLowerCase();
    return (!sevF || i.severity === sevF) && (stF === "All" || i.status === stF)
      && matchesSource && text.includes(query.trim().toLowerCase());
  });
  useEffect(() => {
    if (!visible.some(i => i.incident_id === selectedId)) {
      setSelectedId(visible[0]?.incident_id ?? null);
      setDetailError(null);
    }
  }, [visible, selectedId]);
  const current = detail && detail.incident_id === selectedId ? detail : null;
  function clearFilters() {
    setOriginF('all'); setSevF(null); setStF('All'); setQuery('');
  }

  return <div className="app-shell">
    <aside className="sidebar" aria-label="Workspace navigation">
      <a className="brand" href="#overview" onClick={() => setNavSection('overview')}><span className="brand-symbol"><Icon name="shield" size={29}/></span><span>Cloud Security<small>Incident response console</small></span></a>
      <div className="sidebar-welcome"><h2>Welcome<br/>back<span>.</span></h2><p>Your cloud security workspace.</p></div>
      <div className="sidebar-section-label">Overview</div>
      <nav className="workspace-nav">
        <a href="#overview" onClick={() => setNavSection('overview')} className={navSection === 'overview' ? 'nav-active' : ''} aria-current={navSection === 'overview' ? 'location' : undefined}><Icon name="grid"/><span>Dashboard</span><span className="nav-marker"/></a>
      </nav>
      <div className="sidebar-section-label">Investigation</div>
      <nav className="workspace-nav">
        <a href="#incident-workspace" onClick={() => setNavSection('incidents')} className={navSection === 'incidents' ? 'nav-active' : ''} aria-current={navSection === 'incidents' ? 'location' : undefined}><Icon name="activity"/><span>Incidents</span><span className="nav-count">{incidents.length}</span></a>
        {!SHARED_VIEW && <a href="#response-playbook" onClick={() => setNavSection('playbook')} className={navSection === 'playbook' ? 'nav-active' : ''} aria-current={navSection === 'playbook' ? 'location' : undefined}><Icon name="book"/><span>Response playbook</span></a>}
      </nav>
      <div className="sidebar-bottom"><div className="workspace-region"><Icon name="cloud" size={24}/><div><strong>Amazon Web Services</strong><span>Mumbai · ap-south-1</span></div></div><p className="sidebar-note">Review incidents.<br/>Respond with confidence.</p></div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div className="breadcrumb"><Icon name="home" size={22}/><span>Overview</span><span>/</span><strong>Dashboard</strong></div><label className="search-field"><Icon name="search" size={18}/><input type="search" aria-label="Search incidents" placeholder="Search incidents…" value={query} onChange={e => setQuery(e.target.value)}/></label></header>
      <div className="page-content">
        <section id="overview" className="page-heading"><div><div className={`snapshot-line ${error ? 'connection-error' : ''}`}><i/>{loading ? 'Connecting…' : error ? 'API unavailable' : refreshedAt ? `Last refreshed ${refreshedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}` : 'Waiting for data'}<span>· Manual refresh</span></div><h1>Cloud security,<br/><span>at a glance.</span></h1><p className="mute">Your incidents. A clearer perspective.</p></div><div className="page-action-area"><div className="page-actions"><button className="button primary" onClick={handleRefresh} disabled={busy || !!action || loading} aria-describedby="refresh-help"><Icon name="refresh" size={16} className={action === 'refresh' ? 'refresh-spinning' : ''}/>{action === 'refresh' ? 'Refreshing…' : 'Refresh'}</button>{!SHARED_VIEW && <button className="button secondary" onClick={handleLoadDemo} disabled={busy || !!action || loading} aria-describedby="demo-help"><Icon name="flask" size={16}/>{action === 'demo' ? 'Loading demo…' : 'Load demo incidents'}</button>}</div><p className="action-help"><span id="refresh-help">Refresh reloads saved incidents, not new AWS events.</span>{!SHARED_VIEW && <span id="demo-help">Load demo adds simulated examples for testing.</span>}</p></div></section>
        <div role="status" aria-live="polite" aria-atomic="true" className={`action-notice ${action || notice ? 'is-visible' : ''}`}>
          {(action || notice) && <><Icon name={action ? 'refresh' : 'check'} size={16}/><span>{action === 'refresh' ? 'Refreshing saved incidents and selected details…' : action === 'demo' ? 'Loading simulated sample events…' : notice}</span></>}
        </div>

        {SHARED_VIEW && <div className="panel p-4 mb-4" role="note"><strong>Shared review · Read-only</strong><p className="mute mt-1">Historical controlled AWS tests and labelled demo samples. Account details, actors, source IPs and resource identifiers are hidden. This is not live monitoring.</p>{incidents.some(i => i.archive_fallback) && <p className="mute mt-1">The backend is unavailable. Showing the published review archive.</p>}</div>}
        {error && <div role="alert" className="panel error-banner"><b>Something went wrong.</b> {error}<div className="mute mt-1">{SHARED_VIEW ? "The shared review is temporarily unavailable. Please try again later." : <>Start the backend with <code>uvicorn app.main:app --reload</code> from the backend folder, then press Refresh.</>}</div></div>}
        {loading ? <div className="panel loading-state mute">Loading incidents…</div> : <>
          <Stats incidents={incidents} sevF={sevF} onSelect={s => setSevF(sevF === s ? null : s)}/>
          {!incidents.length && !error && <div className="panel empty-state"><Icon name="shield" size={28}/><div><strong>No incidents yet.</strong><p className="mute">Load the sample AWS events to run them through the detection engine.</p></div></div>}
          <section id="incident-workspace" className="incident-workspace">
            <div className="section-heading incident-section-heading"><div><div className="section-kicker"><Icon name="activity" size={17}/>Investigation</div><h2>Incident overview</h2></div><span className="subtle-pill">{visible.length} of {incidents.length} incidents</span></div>
            <div className="filter-toolbar"><p className="mute">Select an incident to review its details.</p><div className="filter-actions"><label className="source-select"><span className="sr-only">Filter by source</span><select aria-label="Filter by source" value={originF} onChange={e => setOriginF(e.target.value)}><option value="all">All sources</option><option value="aws-cloudtrail">AWS CloudTrail</option><option value="demo">Demo samples</option><option value="other">Other submissions</option></select></label>{(query || originF !== 'all' || sevF || stF !== 'All') && <button className="clear-filters" onClick={clearFilters}>Clear filters</button>}</div></div>
            <IncidentFilters incidents={incidents} stF={stF} onChange={setStF}/>
            <div className="incident-grid"><section className="panel incident-queue"><div className="queue-heading"><span>Incident queue</span><span>{visible.length}</span></div><IncidentList items={visible} selectedId={selectedId} onSelect={setSelectedId}/></section><IncidentDetail incident={current} loading={selectedId !== null} error={detailError} busy={busy} disabled={!!action} readOnly={SHARED_VIEW} onAdvance={handleAdvance}/></div>
          </section>
          <footer className="page-footer"><span><Icon name="shield" size={14}/>Cloud Security</span><span>Demo events are simulated · Response actions are manual</span></footer>
        </>}
      </div>
    </main>
  </div>;
}
