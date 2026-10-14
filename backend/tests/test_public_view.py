import copy
import json
import pytest
from fastapi.testclient import TestClient
from app import main as api
from app.engine import process_event
from app.schemas import EventOrigin
from app.sample_data import SAMPLE_EVENTS
from app.public_view import public_incident
from app.store import InMemoryStore

client = TestClient(api.app)


def test_public_projection_does_not_copy_private_fields():
    inc = process_event(copy.deepcopy(SAMPLE_EVENTS[4]), EventOrigin.AWS_CLOUDTRAIL)
    inc.actor = inc.event.actor = 'private-actor-marker'
    inc.resource_id = inc.event.resource_id = 'private-resource-marker'
    inc.event.account_id = 'private-account-marker'
    inc.event.source_ip = 'private-ip-marker'
    inc.description = inc.title = 'private-description-marker'
    inc.event.details['private'] = 'private-details-marker'
    inc.history[0].note = 'private-note-marker'
    inc.severity_reasons.append('private-reason-marker')
    inc.playbook[0].command = 'private-command-marker'
    shared = public_incident(inc)
    assert 'private-' not in json.dumps(shared)
    assert shared['event']['event_id'] == inc.event.event_id
    assert shared['severity_score'] == inc.severity_score
    assert len(shared['playbook']) == 4 and shared['history'][0]['note'] == 'Recorded review baseline'
    assert shared['shared_demo'] is True


def test_public_archive_survives_empty_store_and_requires_no_key(monkeypatch):
    monkeypatch.setattr(api, 'store', InMemoryStore())
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.delenv('CLOUD_SECURITY_API_KEY', raising=False)
    assert client.get('/incidents').status_code == 503
    assert client.post('/demo/load').status_code == 503
    response = client.get('/public/incidents')
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 10
    assert sum(i['event']['origin'] == 'aws-cloudtrail' for i in data) == 4
    for incident in data:
        assert incident['actor'] == incident['event']['account_id'] == 'Hidden'
        assert incident['event']['source_ip'] is None
        assert incident['resource_id'].startswith('resource-')
    assert client.get('/public/incidents/' + data[0]['incident_id']).json() == data[0]
    assert client.get('/public/incidents/missing').status_code == 404


def test_public_merge_deduplicates_and_excludes_unverified_records(monkeypatch):
    store = InMemoryStore()
    monkeypatch.setattr(api, 'store', store)
    inc = process_event(copy.deepcopy(SAMPLE_EVENTS[0]), EventOrigin.SUBMITTED)
    store.add(inc)
    assert len(client.get('/public/incidents').json()) == 10
    inc.event.origin = EventOrigin.AWS_CLOUDTRAIL
    inc.event.event_id = 'controlled-new-test-id'
    store = InMemoryStore()
    monkeypatch.setattr(api, 'store', store)
    store.add(inc)
    result = client.get('/public/incidents').json()
    assert len(result) == 11
    assert len({i['event']['event_id'] for i in result}) == 11


def test_classroom_workflow_is_interactive_but_private_records_are_unchanged(monkeypatch):
    monkeypatch.setattr(api, 'public_workflow', InMemoryStore())
    private = InMemoryStore()
    monkeypatch.setattr(api, 'store', private)
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.delenv('CLOUD_SECURITY_API_KEY', raising=False)
    rows = client.get('/public/incidents').json()
    incident = next(i for i in rows if i['event']['origin']=='aws-cloudtrail')
    assert len(incident['playbook']) == 4
    path = '/public/incidents/' + incident['incident_id'] + '/status'
    result = client.patch(path, json={'status':'Investigating', 'note':'must not publish this private note'})
    assert result.status_code == 200
    assert result.json()['status'] == 'Investigating'
    assert 'private note' not in result.text
    assert client.patch(path, json={'status':'Resolved'}).status_code == 409
    assert client.get('/public/incidents/' + incident['incident_id']).json()['status'] == 'Investigating'
    assert client.post('/public/demo/load').json()['duplicates_skipped'] == 6
    assert len(client.get('/public/incidents').json()) == 10
    assert private.list() == []
