"""FastAPI app. Run from backend/:  uvicorn app.main:app --reload"""
import json
import os
import secrets
from pathlib import Path
from typing import Any, Literal, Optional
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .engine import process_event
from .sample_data import SAMPLE_EVENTS
from .schemas import Incident, Severity, Status, EventOrigin
from .store import InMemoryStore, InvalidTransition
from .sqlite_store import SQLiteStore
from .public_view import public_incident

app = FastAPI(title="Multi-Cloud Incident Response API", version="0.2.0")

# Lets the React dev server and deployed Netlify frontend call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "https://multicloudsecurity.netlify.app",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

store_mode = os.environ.get("CLOUD_SECURITY_STORE", "sqlite")
if store_mode == "memory":
    store = InMemoryStore()
elif store_mode == "sqlite":
    database_path = os.environ.get("CLOUD_SECURITY_DB_PATH") or str(
        Path(__file__).resolve().parent.parent / "data" / "incidents.sqlite3")
    store = SQLiteStore(database_path)
else:
    raise ValueError("CLOUD_SECURITY_STORE must be sqlite or memory")


def require_operator_key(x_api_key: Optional[str] = Header(default=None)):
    expected = os.environ.get("CLOUD_SECURITY_API_KEY")
    if not expected:
        if os.environ.get("RENDER", "").lower() == "true":
            raise HTTPException(503, "Operator access is not configured on this server")
        return  # Preserve the existing local-only demo setup.
    if not x_api_key or not secrets.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(401, "An operator API key is required for this action")


class StatusUpdate(BaseModel):
    status: Status
    note: str = ""


class EventResult(BaseModel):
    detected: bool
    duplicate: bool = False
    message: str
    incident: Optional[Incident] = None


def ingest(raw: dict, origin: EventOrigin = EventOrigin.SUBMITTED) -> EventResult:
    """Shared by POST /events and POST /demo/load: engine -> store."""
    try:
        incident = process_event(raw, origin)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(422, f"Could not parse event, missing or invalid field: {exc!r}")
    if incident is None:
        return EventResult(detected=False, message="No incident: event is not monitored or is harmless.")
    saved, created = store.add(incident)
    if not created:
        return EventResult(detected=True, duplicate=True, incident=saved,
                           message="Event already processed; returning the existing incident.")
    return EventResult(detected=True, incident=saved, message="Incident created.")


@app.get("/incidents", response_model=list[Incident], dependencies=[Depends(require_operator_key)])
def list_incidents(severity: Optional[Severity] = None, status: Optional[Status] = None):
    """All incidents, highest severity score first. Optional filters: ?severity=High&status=Detected"""
    return store.list(severity, status)


@app.get("/incidents/{incident_id}", response_model=Incident, dependencies=[Depends(require_operator_key)])
def get_incident(incident_id: str):
    incident = store.get(incident_id)
    if incident is None:
        raise HTTPException(404, f"Incident {incident_id} not found.")
    return incident


@app.post("/events", response_model=EventResult, dependencies=[Depends(require_operator_key)])
def post_event(response: Response, raw: dict[str, Any] = Body(...),
               origin: Literal["submitted", "aws-cloudtrail", "fixture"] = "submitted"):
    """Send one CloudTrail record (or EventBridge envelope). 201 = new incident, 200 = otherwise."""
    result = ingest(raw, EventOrigin(origin))
    if result.detected and not result.duplicate:
        response.status_code = 201
    return result


@app.post("/demo/load", dependencies=[Depends(require_operator_key)])
def load_demo(reset: bool = False):
    """Feed the 7 sample CloudTrail events through the engine. ?reset=true clears existing incidents first."""
    if reset:
        store.clear()
    summary = {"events_processed": 0, "incidents_created": 0, "duplicates_skipped": 0, "no_incident": 0}
    for raw in SAMPLE_EVENTS:
        result = ingest(raw, EventOrigin.DEMO)
        summary["events_processed"] += 1
        if not result.detected:
            summary["no_incident"] += 1
        elif result.duplicate:
            summary["duplicates_skipped"] += 1
        else:
            summary["incidents_created"] += 1
    return summary


@app.patch("/incidents/{incident_id}/status", response_model=Incident, dependencies=[Depends(require_operator_key)])
def update_status(incident_id: str, body: StatusUpdate):
    """Advance an incident one step: Detected -> Investigating -> Contained -> Resolved."""
    try:
        incident = store.update_status(incident_id, body.status, body.note)
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc))
    if incident is None:
        raise HTTPException(404, f"Incident {incident_id} not found.")
    return incident


@app.get("/public/incidents")
def shared_incidents():
    """Redacted records only. Published review archive survives free-host restarts."""
    archive_path = Path(__file__).with_name("shared_incidents.json")
    published = json.loads(archive_path.read_text()) if archive_path.exists() else {"incidents": []}
    records = {i["event"]["event_id"]: i for i in published["incidents"]}
    for incident in store.list():
        if incident.event.origin in {EventOrigin.AWS_CLOUDTRAIL, EventOrigin.DEMO}:
            records[incident.event.event_id] = public_incident(incident)
    return sorted(records.values(), key=lambda i: (i["severity_score"], i["event"]["event_time"]), reverse=True)


@app.get("/public/incidents/{incident_id}")
def shared_incident_detail(incident_id: str):
    for incident in shared_incidents():
        if incident["incident_id"] == incident_id:
            return incident
    raise HTTPException(404, "Incident not found")
