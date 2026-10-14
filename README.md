# Multi-Cloud Incident Response System (AWS MVP)

Pipeline: AWS event → normalize → detect → severity → playbook → dashboard.

## Run the backend locally (Step 2)

Requires Python 3.10+. Run everything from the `backend/` folder.

**1. Create a virtual environment and install dependencies**

macOS / Linux:
```
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```
Windows (PowerShell):
```
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

**2. Start the API**
```
uvicorn app.main:app --reload
```
- API: http://127.0.0.1:8000
- Interactive docs (try every endpoint in the browser): http://127.0.0.1:8000/docs

**3. Load the sample events**

Open `/docs`, run `POST /demo/load`, then `GET /incidents`. Or from a terminal:
```
curl -X POST http://127.0.0.1:8000/demo/load
curl http://127.0.0.1:8000/incidents
```

**4. Run the tests**
```
python -m pytest -v
```

Incidents are stored locally in SQLite at `backend/data/incidents.sqlite3` by default. Incidents, history, and event-ID deduplication survive backend restarts. The database is ignored by Git.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/incidents` | List incidents, highest severity first. Filters: `?severity=High&status=Detected` |
| GET | `/incidents/{id}` | One incident: severity, reasons, resource, event, playbook, history |
| POST | `/events` | Send one CloudTrail record (or EventBridge envelope). `201` new incident, `200` no incident or duplicate |
| POST | `/demo/load` | Run the 7 sample events. `?reset=true` clears existing incidents first |
| PATCH | `/incidents/{id}/status` | Body `{"status": "Investigating", "note": "optional"}`. Moves forward one step; anything else returns `409` |

## Run the dashboard (Step 3)

Requires Node.js 18+. Keep the backend from the section above running in one terminal, then in a second terminal:
```
cd frontend
npm install
npm run dev
```
Open **http://localhost:5173** (use `localhost`, not `127.0.0.1`, because the backend's CORS setting allows that origin).

1. Click **Load demo incidents** to run the 7 sample AWS events through the engine (6 incidents appear). Loading is non-destructive and preserves existing incidents.
2. Click a severity card or a status chip to filter. Click an incident to open its details and playbook.
3. Use the **Mark as …** button to move it Detected → Investigating → Contained → Resolved. Each change is saved by the backend, so a page refresh keeps it.

If the backend is not at `http://127.0.0.1:8000`, copy `.env.example` to `.env` and change `VITE_API_URL`.

**Automated check (React → FastAPI → store → engine).** Start a separate disposable backend with `CLOUD_SECURITY_STORE=memory uvicorn app.main:app --port 8001` from `backend/`, then:
```
cd frontend
VITE_API_URL=http://127.0.0.1:8001 npm run test:e2e
```
The tests reset only the disposable backend on port 8001 and run independently. They render the real dashboard against that API. It loads the demo data, exercises the filters, opens an incident, walks it to Resolved, and simulates a page refresh.


## Review 2: local AWS collector

Architecture: CloudTrail Event History → local AWS CLI collector → existing `POST /events` → engine → local SQLite store → dashboard.

The collector uses Python's standard library and the installed AWS CLI. It does not provision infrastructure, execute playbooks, save AWS log archives, or print credentials/raw AWS errors. Samples remain available through `/demo/load` and `python -m app.demo`.

### Offline verification (no AWS access)

From `backend/`, with the API running:

```bash
.venv/bin/python -m app.aws_collector --fixture tests/fixtures/cloudtrail_lookup.json
```

This fixture is synthetic, not evidence of live AWS integration. It contains one successful SSH change and one denied request. The first run creates one High incident and ignores the denied request; replay returns one duplicate. Use `--backend-url http://127.0.0.1:8001` to target a disposable test server.

### Live retrieval (only after the user's approval)

```bash
.venv/bin/python -m app.aws_collector --live --region ap-south-1 --minutes 30 --max-pages 2
```

Optional flags: `--profile NAME`, `--account-id EXPECTED_ACCOUNT`, and `--event-name NAME` (one of the six existing watched event names). Default event name: `AuthorizeSecurityGroupIngress`. Default AWS profile resolution is delegated to the CLI; authenticate through `aws login` if needed. Do not create access keys or commit credentials. The retrieval identity needs `cloudtrail:LookupEvents`; it does not need remediation permissions.

Each run freezes a recent time window, retrieves at most 50 records per page, decodes each `CloudTrailEvent`, and forwards individual records to the existing API. Pagination uses service `NextToken` with CLI automatic pagination disabled. Requests are spaced below two per second with bounded retry/backoff; no automatic ongoing polling. Limits: 1–1440 minutes and 1–20 pages. Exit code 2 means errors or truncation; a truncated run is incomplete. Increase the page cap within its limit or narrow the window. AWS Event History delivery is delayed, so rerun the overlapping window after the action appears in AWS; backend event-ID deduplication handles replay across restarts.

The JSON summary reports pages, fetched records, created incidents, duplicates, ignored records, failed records, and truncation. Invalid records are skipped and counted; persistent backend unavailability stops the batch. The backend URL must be a loopback HTTP origin or the explicitly approved Render HTTPS origin described below. HTTP redirects and proxies are disabled for event posting.

[CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html) is regional management-event history, available for 90 days without a new trail or S3 bucket. It excludes S3 object data events. [AWS lookup documentation](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html) describes its format and rate limit. For this milestone use EC2 management events in Mumbai; other services, including global IAM activity, may require a different lookup region.

### Local limitations

- Failed operations are excluded from successful-change detection; watched events must contain expected source and nonempty event ID, time, region, and account metadata.
- Existing request-based rules are heuristic: they do not verify current AWS resource state or execute remediation.
- The dashboard refreshes manually. Playbook checkboxes are browser-only progress.
- SQLite persists incidents and duplicate tracking across restarts; keep the database on local disk.
- `/demo/load?reset=true` remains an explicit destructive reset of the entire incident store. The dashboard uses non-destructive loading instead.
- Do not expose the API publicly without configuring operator authentication as described below. No AWS resources or remediation should be created/executed without separate approval.


## Local persistence

SQLite is included with Python; this adds no packages or AWS services. The store keeps the complete validated incident JSON, including event details, severity reasons, playbook, status, and history. Event IDs have a uniqueness constraint and writes use transactions, preventing duplicate incidents from concurrent requests. Normal ingestion and analyst status changes are saved immediately.

The default database path is anchored to `backend/data/incidents.sqlite3`, independent of the working directory. Override it with `CLOUD_SECURITY_DB_PATH=/absolute/path/incidents.sqlite3`. Choose `CLOUD_SECURITY_STORE=memory` for disposable sessions. Unsupported store modes fail explicitly.

Backend tests automatically use memory or temporary test databases; they never reset the default database. Frontend integration tests must use a separate backend on port 8001 with `CLOUD_SECURITY_STORE=memory`. Do not point destructive tests at your review database.

`POST /demo/load` preserves existing incidents. `POST /demo/load?reset=true` explicitly deletes **all** saved incidents, including real AWS incidents, and reloads the samples. The dashboard does not call this destructive reset.

The seven existing review incidents were migrated before switching the running backend to SQLite, retaining their original IDs and history. In future, switching from memory mode to SQLite does not automatically migrate in-memory incidents. For backups, stop the backend and copy the SQLite database to a private location; avoid committing incident data, which can contain account identifiers, actor names, and IP addresses. This is local persistence, not a hosted production database.


## Event origin and presentation

The normalized event includes `origin`: `demo`, `aws-cloudtrail`, `fixture`, or `submitted`. The dashboard shows readable labels and the original event ID. `/demo/load` labels samples as demo; the collector posts `?origin=aws-cloudtrail` in live mode and `?origin=fixture` in offline mode. Ordinary API submissions default to unverified; caller-provided body fields cannot silently change that default. Duplicate replay retains the first stored origin.

Origin is ingestion metadata, not cryptographic proof of authenticity: this local API is unauthenticated, and a caller can explicitly supply the supported query parameter. Verify real-event claims against AWS CloudTrail using the displayed event ID. The existing six sample incidents and the one AWS incident were labeled using their known event IDs; unknown records remain unverified. These labels persist in SQLite.

The dashboard warns that imported records describe past actions, not necessarily current exposure. Playbooks and status changes remain manual. Present the AWS component as a tested one-cloud MVP with manual bounded collection, not a continuously streaming, deployed multi-cloud service.

## Importing real events into the Render deployment

Approved collector destination: `https://cloud-security-backend-y7ty.onrender.com`.
The laptop runs the AWS CLI collector and sends records over HTTPS to Render.
AWS credentials remain on the laptop. There is no automatic AWS polling on Render.

### Deployment configuration, before importing

1. Deploy the updated backend and frontend using your existing deployment process.
   These local changes do not update either hosted site until deployed.
2. Set a long random private `CLOUD_SECURITY_API_KEY` value in Render's environment
   settings. Use an operator secret unrelated to your AWS credentials. Render
   supplies `RENDER=true`; without the key, the API rejects incident reads and
   all mutations with HTTP 503. With a key, requests need the matching `X-API-Key`
   header. OpenAPI and docs contain API metadata, not incident records.
3. Keep frontend `VITE_API_URL` set to the Render origin. Never put the key in
   `VITE_*`, source code or Git. The dashboard asks for the operator key when it
   receives HTTP 401 and retains it in memory until the page reloads. Operators
   with this shared key can read data, change status and reset the store.
4. Test the deployed authentication and a synthetic fixture first. This sends
   simulated records, not real AWS evidence. Do not upload real data until reads
   without the key are denied.

From `backend/`, enter the same key privately in zsh:

```zsh
read -s 'CLOUD_SECURITY_API_KEY?Project operator key: '
export CLOUD_SECURITY_API_KEY
```

Offline collector test against Render (no AWS access, but writes fixture incidents
on the hosted backend):

```bash
.venv/bin/python -m app.aws_collector \
  --fixture tests/fixtures/cloudtrail_lookup.json \
  --backend-url https://cloud-security-backend-y7ty.onrender.com
```

### Authorized live retrieval, only after separate approval

The historical test window includes the original test at 00:28 IST on October 7
and the additional tests that morning. Explicit windows require timezone-aware
ISO 8601 values, span at most 24 hours, and must be inside the past 90 days.
The window below is historical test data, not evidence of a new attack.

```bash
.venv/bin/python -m app.aws_collector --live \
  --region ap-south-1 --event-name AuthorizeSecurityGroupIngress \
  --start-time 2026-10-06T18:30:00Z --end-time 2026-10-07T04:00:00Z \
  --max-pages 2 \
  --backend-url https://cloud-security-backend-y7ty.onrender.com
```

Use `--minutes 30` instead of explicit dates for recent events. Optional `--profile`
and `--account-id` filters still work. Refresh in the dashboard reads stored
incidents and never performs AWS lookup. Importing the same event again returns
its existing incident while the database survives. An ignored event is not
necessarily an error: HTTPS-only ingress does not match the SSH rule.

Remote destinations are restricted to this exact HTTPS host on port 443. The
collector requires the key before remote lookup, disables proxies and redirects,
stops on HTTP 401/403, and allows time for a Render cold start. No packages or
paid infrastructure are required by these code changes.

Render free services use an ephemeral filesystem. A SQLite file there is not a
permanent archive and may disappear after a restart or redeploy. Keep a private
local export of the original CloudTrail LookupEvents response, which can later be
replayed with `--fixture` (and will be labelled fixture). Only records actually
retrieved by an authorized live lookup use the AWS origin label. Do not claim
replayed synthetic fixtures are new AWS events. See
[Render free-service limitations](https://render.com/docs/free).

For local-only development, leaving `CLOUD_SECURITY_API_KEY` unset preserves the
existing demo path. Set it whenever the app is exposed outside your machine.

## Shared read-only dashboard

Build the Netlify bundle with `VITE_SHARED_VIEW=true` and the Render origin in
`VITE_API_URL`. This version reads `/public/incidents`, never requests an operator
key, and hides all mutation controls. The API explicitly constructs a redacted
projection. Actor names, account IDs, source IPs, original resource identifiers,
free-text analyst notes, policy contents and response commands are excluded.
Real AWS event IDs, timestamps, priorities and origin labels remain visible.
The private incident endpoints and mutations still require the operator key.

The published archive contains **four historical controlled AWS test incidents
from October 7, 2026**, plus six labelled simulated incidents. These records came
from the existing verified local review database. No new AWS operations were
performed to publish them. The archive contains redacted fields only and is
intentionally included in the deployed bundle and repository.

`backend/app/shared_incidents.json` provides the review baseline when Render's
SQLite store is empty after restart. Current AWS/demo incidents in the store
merge into that public view with event-ID deduplication. Unverified submissions
and fixtures are excluded. This archive is not a durable database for later
imports: newly imported records must be deliberately added to a new reviewed,
redacted archive to survive free-host restarts.

`frontend/public/review-archive.json` holds the same redacted baseline. If Render
cannot respond within 12 seconds, the shared dashboard uses this published
archive and displays an explicit notice. Refresh updates saved results rather
than collecting AWS events. The shared site does not imply continuous monitoring,
confirmed compromise or current resource exposure. Historical test groups were
unattached and subsequently deleted.

Netlify's current Free plan includes credits, and a published production deploy
uses 15 credits. Do not publish without approval when the user's instruction is
to avoid credit consumption. Existing service URLs and Free instance plans should
remain unchanged. No paid storage, auto-recharge or new resources are necessary.


## Interactive classroom demo

The deployed shared build now includes response playbooks, browser checkboxes,
status progression and additive demo loading. Public status changes use a separate
in-memory classroom workflow shared by visitors. They never alter private
incidents or AWS resources. These workflow changes reset when the free backend
restarts. The 4 real historical records and 6 samples remain in the archive.
Generic CLI commands retain placeholders because original AWS identifiers remain
hidden. Commands are manual examples and are never executed by the website.
The prior read-only restriction is superseded by this classroom demo mode.
