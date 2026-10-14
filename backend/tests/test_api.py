"""Run from backend/:  python -m pytest -v"""
import copy
import pytest
from fastapi.testclient import TestClient
from app.main import app, store
from app import main as api
from app.sqlite_store import SQLiteStore
from app.store import InMemoryStore
from app.sample_data import SAMPLE_EVENTS

client = TestClient(app)
EXPECTED = {"evt-0001": "Medium", "evt-0002": "Critical", "evt-0003": "Critical",
            "evt-0004": "High", "evt-0005": "Critical", "evt-0006": "Low", "evt-0007": None}


@pytest.fixture(autouse=True, params=["memory", "sqlite"])
def fresh_store(request, tmp_path, monkeypatch):
    isolated = (InMemoryStore() if request.param == "memory"
                else SQLiteStore(tmp_path / "test-incidents.sqlite3"))
    monkeypatch.setattr(api, "store", isolated)


def first_id(severity=None):
    client.post("/demo/load")
    url = "/incidents" + (f"?severity={severity}" if severity else "")
    return client.get(url).json()[0]["incident_id"]


def test_list_empty_at_start():
    r = client.get("/incidents")
    assert r.status_code == 200 and r.json() == []


def test_demo_load_and_idempotent():
    r = client.post("/demo/load")
    assert r.status_code == 200
    assert r.json() == {"events_processed": 7, "incidents_created": 6, "duplicates_skipped": 0, "no_incident": 1}
    again = client.post("/demo/load").json()
    assert again["incidents_created"] == 0 and again["duplicates_skipped"] == 6
    assert len(client.get("/incidents").json()) == 6
    assert client.post("/demo/load?reset=true").json()["incidents_created"] == 6


def test_list_sorted_and_filters():
    client.post("/demo/load")
    scores = [i["severity_score"] for i in client.get("/incidents").json()]
    assert scores == sorted(scores, reverse=True)
    crit = client.get("/incidents?severity=Critical").json()
    assert len(crit) == 3 and all(i["severity"] == "Critical" for i in crit)
    assert client.get("/incidents?status=Resolved").json() == []
    assert len(client.get("/incidents?status=Detected").json()) == 6
    assert client.get("/incidents?severity=Bogus").status_code == 422


def test_get_incident_has_all_fields():
    iid = first_id()
    r = client.get(f"/incidents/{iid}")
    assert r.status_code == 200
    inc = r.json()
    assert inc["severity"] in ("Critical", "High", "Medium", "Low")
    assert inc["severity_reasons"] and inc["resource_id"] and inc["resource_type"] and inc["actor"]
    assert inc["title"] and inc["description"] and inc["event"]["event_name"]
    assert len(inc["playbook"]) == 4 and inc["playbook"][0]["title"]
    assert inc["status"] == "Detected"
    assert len(inc["history"]) == 1 and inc["history"][0]["status"] == "Detected"


def test_get_incident_404():
    assert client.get("/incidents/INC-NOPE").status_code == 404


@pytest.mark.parametrize("raw", SAMPLE_EVENTS, ids=[e["eventID"] for e in SAMPLE_EVENTS])
def test_post_each_sample_event(raw):
    r = client.post("/events", json=raw)
    expected = EXPECTED[raw["eventID"]]
    body = r.json()
    if expected is None:
        assert r.status_code == 200 and body["detected"] is False and body["incident"] is None
    else:
        assert r.status_code == 201 and body["detected"] is True
        assert body["incident"]["severity"] == expected


def test_post_event_duplicate_returns_existing():
    raw = SAMPLE_EVENTS[0]
    first = client.post("/events", json=raw)
    second = client.post("/events", json=raw)
    assert first.status_code == 201 and second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["incident"]["incident_id"] == first.json()["incident"]["incident_id"]
    assert len(client.get("/incidents").json()) == 1


def test_post_event_eventbridge_envelope():
    envelope = {"version": "0", "source": "aws.s3", "detail-type": "AWS API Call via CloudTrail",
                "detail": copy.deepcopy(SAMPLE_EVENTS[1])}
    r = client.post("/events", json=envelope)
    assert r.status_code == 201 and r.json()["incident"]["severity"] == "Critical"


def test_post_event_unwatched_and_malformed():
    r = client.post("/events", json={"eventName": "CreateBucket", "requestParameters": {"bucketName": "x"}})
    assert r.status_code == 200 and r.json()["detected"] is False
    bad = copy.deepcopy(SAMPLE_EVENTS[0])
    del bad["requestParameters"]["bucketName"]
    assert client.post("/events", json=bad).status_code == 422
    assert client.post("/events", json=[1, 2]).status_code == 422


def test_status_full_lifecycle_with_history():
    iid = first_id()
    before = client.get(f"/incidents/{iid}").json()["updated_at"]
    for status in ("Investigating", "Contained", "Resolved"):
        r = client.patch(f"/incidents/{iid}/status", json={"status": status, "note": f"moved to {status}"})
        assert r.status_code == 200 and r.json()["status"] == status
    inc = client.get(f"/incidents/{iid}").json()
    assert [h["status"] for h in inc["history"]] == ["Detected", "Investigating", "Contained", "Resolved"]
    assert inc["history"][1]["note"] == "moved to Investigating"
    assert all(h["timestamp"] for h in inc["history"])
    assert inc["updated_at"] >= before


def test_status_default_note():
    iid = first_id()
    r = client.patch(f"/incidents/{iid}/status", json={"status": "Investigating"})
    assert r.json()["history"][-1]["note"] == "Status changed by analyst"


def test_status_invalid_transitions():
    iid = first_id()
    assert client.patch(f"/incidents/{iid}/status", json={"status": "Contained"}).status_code == 409   # skip
    assert client.patch(f"/incidents/{iid}/status", json={"status": "Detected"}).status_code == 409    # same
    client.patch(f"/incidents/{iid}/status", json={"status": "Investigating"})
    assert client.patch(f"/incidents/{iid}/status", json={"status": "Detected"}).status_code == 409    # backward
    for s in ("Contained", "Resolved"):
        client.patch(f"/incidents/{iid}/status", json={"status": s})
    r = client.patch(f"/incidents/{iid}/status", json={"status": "Investigating"})
    assert r.status_code == 409 and "Resolved" in r.json()["detail"]
    assert len(client.get(f"/incidents/{iid}").json()["history"]) == 4    # failed attempts not recorded


def test_status_404_and_bad_value():
    assert client.patch("/incidents/INC-NOPE/status", json={"status": "Investigating"}).status_code == 404
    iid = first_id()
    assert client.patch(f"/incidents/{iid}/status", json={"status": "Fixed"}).status_code == 422
    assert client.patch(f"/incidents/{iid}/status", json={}).status_code == 422


def test_demo_and_submitted_origins_are_distinct():
    client.post('/demo/load')
    assert all(i['event']['origin'] == 'demo' for i in client.get('/incidents').json())
    raw = copy.deepcopy(SAMPLE_EVENTS[0])
    raw['eventID'] = 'origin-submitted'
    raw['origin'] = 'aws-cloudtrail'  # Body metadata cannot silently claim AWS ingestion.
    response = client.post('/events', json=raw)
    assert response.json()['incident']['event']['origin'] == 'submitted'


@pytest.mark.parametrize('origin', ['aws-cloudtrail', 'fixture'])
def test_explicit_collector_origin_is_retained_on_replay(origin):
    raw = copy.deepcopy(SAMPLE_EVENTS[0])
    response = client.post('/events?origin=' + origin, json=raw)
    assert response.json()['incident']['event']['origin'] == origin
    replay = client.post('/events', json=raw)
    assert replay.json()['duplicate'] is True
    assert replay.json()['incident']['event']['origin'] == origin


def test_post_event_rejects_invalid_origin():
    assert client.post('/events?origin=demo', json=SAMPLE_EVENTS[0]).status_code == 422


@pytest.mark.parametrize("origin", [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://multicloudsecurity.netlify.app",
])
def test_cors_allowed_origins(origin):
    response = client.options(
        "/incidents",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin


def test_cors_disallows_unknown_origin():
    response = client.options(
        "/incidents",
        headers={
            "Origin": "https://unauthorized.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") is None


def test_operator_key_protects_data_and_all_mutations(monkeypatch):
    monkeypatch.setenv('CLOUD_SECURITY_API_KEY', 'test-only-key')
    headers = {'X-API-Key': 'test-only-key'}
    for bad_headers in ({}, {'X-API-Key': 'wrong'}):
        assert client.get('/incidents', headers=bad_headers).status_code == 401
        assert client.post('/events', json=SAMPLE_EVENTS[0], headers=bad_headers).status_code == 401
        assert client.post('/demo/load?reset=true', headers=bad_headers).status_code == 401
        assert client.patch('/incidents/INC-NOPE/status', json={'status':'Investigating'}, headers=bad_headers).status_code == 401
    assert client.post('/events', json=SAMPLE_EVENTS[0], headers=headers).status_code == 201
    data = client.get('/incidents', headers=headers).json()
    assert len(data) == 1
    assert client.get('/incidents/' + data[0]['incident_id']).status_code == 401
    assert client.post('/demo/load', headers=headers).status_code == 200
    assert client.patch('/incidents/' + data[0]['incident_id'] + '/status',
                        json={'status':'Investigating'}, headers=headers).status_code == 200


def test_render_fails_closed_without_operator_key(monkeypatch):
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.delenv('CLOUD_SECURITY_API_KEY', raising=False)
    assert client.get('/incidents').status_code == 503
    assert client.post('/demo/load').status_code == 503
    assert client.post('/events', json=SAMPLE_EVENTS[0]).status_code == 503
    result = client.options('/events', headers={'Origin':'https://multicloudsecurity.netlify.app',
        'Access-Control-Request-Method':'POST', 'Access-Control-Request-Headers':'X-API-Key'})
    assert result.status_code == 200
