"""Offline tests: AWS subprocess and HTTP transport are replaced with fixtures."""
import copy
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from app import aws_collector as collector
from app.main import app, store
from app.sample_data import SAMPLE_EVENTS

FIXTURE = Path(__file__).parent / "fixtures" / "cloudtrail_lookup.json"


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()


@pytest.fixture
def transport(monkeypatch):
    client = TestClient(app)
    def post(endpoint, record):
        response = client.post("/events" + ("?" + urlsplit(endpoint).query if urlsplit(endpoint).query else ""), json=record)
        if response.status_code >= 400:
            raise collector.CollectorError("Backend rejected event")
        return response.json()
    monkeypatch.setattr(collector, "post_event", post)
    return client


def run_fixture():
    summary = collector.Summary()
    collector.collect(collector.fixture_pages(FIXTURE), "http://127.0.0.1:8000/events", summary,
                      "AuthorizeSecurityGroupIngress", region="ap-south-1")
    return summary


def test_fixture_pipeline_and_replay(transport):
    summary = run_fixture()
    assert asdict(summary) == dict(pages=1, fetched=2, created=1, duplicates=0,
                                  ignored=1, failed=0, truncated=False)
    incidents = transport.get("/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "High"
    assert "assumed-role" in incidents[0]["actor"]
    assert run_fixture().duplicates == 1
    assert len(transport.get("/incidents").json()) == 1
    transport.post("/demo/load")
    assert len(transport.get("/incidents").json()) == 7


@pytest.mark.parametrize("envelope", [False, True])
def test_failed_operation_cannot_create_incident(transport, envelope):
    raw = copy.deepcopy(SAMPLE_EVENTS[2])
    raw["errorCode"] = "AccessDenied"
    response = transport.post("/events", json={"detail": raw} if envelope else raw)
    assert response.status_code == 200 and response.json()["detected"] is False
    assert store.list() == []


@pytest.mark.parametrize("field,value", [("eventID", ""), ("eventSource", "wrong.amazonaws.com"),
                                        ("eventTime", None), ("awsRegion", ""), ("recipientAccountId", "")])
def test_invalid_monitored_metadata(transport, field, value):
    raw = copy.deepcopy(SAMPLE_EVENTS[0])
    raw[field] = value
    assert transport.post("/events", json=raw).status_code == 422


def test_decode_failure_duplicate_and_account_filter(transport):
    raw = copy.deepcopy(SAMPLE_EVENTS[4])
    rows = [{"CloudTrailEvent": json.dumps(raw)}] * 2 + [{"CloudTrailEvent": "bad"}]
    summary = collector.Summary()
    collector.collect([{"Events": rows}], "unused", summary, raw["eventName"])
    assert (summary.created, summary.duplicates, summary.failed) == (1, 1, 1)
    summary = collector.Summary()
    collector.collect([{"Events": rows[:1]}], "unused", summary, raw["eventName"], account_id="999999999999")
    assert summary.ignored == 1


def test_pagination_keeps_window_and_respects_cap(monkeypatch):
    calls = []
    def lookup(params, region, profile):
        calls.append(copy.deepcopy(params))
        return {"Events": [], "NextToken": f"page-{len(calls)}"}
    monkeypatch.setattr(collector, "lookup_page", lookup)
    pages = list(collector.live_pages("ap-south-1", "student", "PutBucketAcl", 30, 2))
    assert len(calls) == 2 and calls[1]["NextToken"] == "page-1"
    assert calls[0]["StartTime"] == calls[1]["StartTime"]
    assert calls[0]["EndTime"] == calls[1]["EndTime"]
    summary = collector.Summary()
    collector.collect(pages, "unused", summary, "PutBucketAcl")
    assert summary.truncated


@pytest.mark.parametrize("error,expected", [("ExpiredTokenException secret", "authentication"),
    ("AccessDeniedException secret", "denied"), ("unknown secret", "lookup failed")])
def test_cli_errors_are_safe(monkeypatch, error, expected):
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(collector.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=1, stdout="", stderr=error))
    with pytest.raises(collector.CollectorError, match=expected) as exc:
        collector.lookup_page({}, "ap-south-1")
    assert "secret" not in str(exc.value)


def test_throttle_retries_and_disables_automatic_pagination(monkeypatch):
    calls, sleeps = [], []
    responses = iter([SimpleNamespace(returncode=1, stdout="", stderr="ThrottlingException"),
                      SimpleNamespace(returncode=0, stdout='{"Events": []}', stderr="")])
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return next(responses)
    monkeypatch.setattr(collector.subprocess, "run", run)
    monkeypatch.setattr(collector.time, "sleep", sleeps.append)
    assert collector.lookup_page({}, "ap-south-1", "student") == {"Events": []}
    assert len(calls) == 2 and sleeps == [0.6, 2]
    assert "--no-paginate" in calls[0][0]
    assert calls[0][1]["env"]["AWS_MAX_ATTEMPTS"] == "1"


@pytest.mark.parametrize("error", [FileNotFoundError(), subprocess.TimeoutExpired("aws", 30)])
def test_missing_cli_and_timeout(monkeypatch, error):
    def run(*args, **kwargs):
        raise error
    monkeypatch.setattr(collector.subprocess, "run", run)
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: None)
    with pytest.raises(collector.CollectorError):
        collector.lookup_page({}, "ap-south-1")


@pytest.mark.parametrize("url", ["https://example.com", "http://127.0.0.1@evil.com", "http://localhost/path"])
def test_nonlocal_backend_rejected(url):
    with pytest.raises(collector.CollectorError):
        collector.local_endpoint(url)


@pytest.mark.parametrize("error", [URLError("offline"), HTTPError("local", 503, "down", None, None),
                                 HTTPError("local", 422, "invalid", None, None)])
def test_backend_failures_and_retries(monkeypatch, error):
    calls = []
    class Opener:
        def open(self, *args, **kwargs):
            calls.append(1)
            raise error
    monkeypatch.setattr(collector, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: None)
    with pytest.raises(collector.CollectorError):
        collector.post_event("http://127.0.0.1:8000/events", SAMPLE_EVENTS[0])
    assert len(calls) == (1 if isinstance(error, HTTPError) and error.code == 422 else 3)


def test_fixture_mode_never_calls_aws(monkeypatch, transport, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("Fixture mode invoked AWS")
    monkeypatch.setattr(collector.subprocess, "run", forbidden)
    assert collector.main(["--fixture", str(FIXTURE)]) == 0
    assert json.loads(capsys.readouterr().out)["created"] == 1


def test_live_requires_explicit_selection():
    with pytest.raises(SystemExit):
        collector.main([])


@pytest.mark.parametrize("mode,expected", [("fixture", "fixture"), ("live", "aws-cloudtrail")])
def test_collector_marks_its_ingestion_mode(monkeypatch, transport, mode, expected):
    # Simulated live response: this test must never access AWS.
    monkeypatch.setattr(collector, "live_pages", lambda *args: collector.fixture_pages(FIXTURE))
    args = ["--fixture", str(FIXTURE)] if mode == "fixture" else ["--live"]
    assert collector.main(args) == 0
    assert transport.get("/incidents").json()[0]["event"]["origin"] == expected


def test_exact_render_origin_only():
    assert collector.local_endpoint(collector.RENDER_ORIGIN) == collector.RENDER_ORIGIN + '/events'
    for base in (collector.RENDER_ORIGIN.replace('https:', 'http:'),
                 collector.RENDER_ORIGIN + '.evil.com', collector.RENDER_ORIGIN + ':444',
                 collector.RENDER_ORIGIN + '?key=secret', collector.RENDER_ORIGIN + '/events',
                 collector.RENDER_ORIGIN.replace('https://', 'https://user:pass@')):
        with pytest.raises(collector.CollectorError):
            collector.local_endpoint(base)


def test_missing_render_key_stops_before_lookup(monkeypatch):
    monkeypatch.delenv('CLOUD_SECURITY_API_KEY', raising=False)
    monkeypatch.setattr(collector, 'live_pages', lambda *a, **k: pytest.fail('AWS called'))
    assert collector.main(['--live', '--backend-url', collector.RENDER_ORIGIN]) == 2


def test_historical_window_and_pagination(monkeypatch):
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc) - timedelta(days=7)
    start = end - timedelta(hours=4)
    parsed = collector.explicit_window(start.isoformat(), end.isoformat())
    calls = []
    def lookup(params, *args):
        calls.append(copy.deepcopy(params))
        return {'Events': [], **({'NextToken': 'second'} if len(calls) == 1 else {})}
    monkeypatch.setattr(collector, 'lookup_page', lookup)
    list(collector.live_pages('ap-south-1', None, 'AuthorizeSecurityGroupIngress', 30, 2,
                              start=parsed[0], end=parsed[1]))
    assert len(calls) == 2
    assert calls[0]['StartTime'] == calls[1]['StartTime'] == start.isoformat()
    assert calls[0]['EndTime'] == calls[1]['EndTime'] == end.isoformat()
    for bad_start, bad_end in [('2026-01-01', '2026-01-02'),
                               (end.isoformat(), start.isoformat()),
                               ((start-timedelta(days=3)).isoformat(), end.isoformat())]:
        with pytest.raises(collector.CollectorError):
            collector.explicit_window(bad_start, bad_end)


@pytest.mark.parametrize('flags', [['--start-time', '2026-10-07T00:00:00Z'],
                                  ['--start-time', 'bad', '--end-time', 'bad']])
def test_bad_window_stops_before_aws(monkeypatch, flags):
    monkeypatch.setattr(collector, 'live_pages', lambda *a, **k: pytest.fail('AWS called'))
    assert collector.main(['--live', *flags]) == 2


def test_render_key_header_and_no_redirects(monkeypatch):
    import io
    captured = []
    def build(*handlers):
        assert any(isinstance(h, collector.NoRedirects) for h in handlers)
        class Opener:
            def open(self, request, **kwargs):
                captured.append(request)
                return io.StringIO('{"detected":true,"duplicate":false}')
        return Opener()
    monkeypatch.setenv('CLOUD_SECURITY_API_KEY', 'test-only-key')
    monkeypatch.setattr(collector, 'build_opener', build)
    collector.post_event(collector.RENDER_ORIGIN + '/events', SAMPLE_EVENTS[0])
    assert captured[0].get_header('X-api-key') == 'test-only-key'


def test_auth_failure_stops_batch_without_retry(monkeypatch):
    calls = []
    class Opener:
        def open(self, *a, **k):
            calls.append(1)
            raise HTTPError('backend', 401, 'Unauthorized', None, None)
    monkeypatch.setattr(collector, 'build_opener', lambda *a: Opener())
    with pytest.raises(collector.BackendUnavailable, match='authentication'):
        collector.post_event(collector.RENDER_ORIGIN + '/events', SAMPLE_EVENTS[0])
    assert len(calls) == 1
