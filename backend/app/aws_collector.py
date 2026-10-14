"""Bounded CloudTrail lookup -> local or approved Render POST /events. Standard library only."""
import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .normalizer import WATCHED


class CollectorError(Exception):
    """A safe message suitable for display; never includes raw AWS output."""


class BackendUnavailable(CollectorError):
    """Stop a batch when retries cannot reach a working backend."""


@dataclass
class Summary:
    pages: int = 0
    fetched: int = 0
    created: int = 0
    duplicates: int = 0
    ignored: int = 0
    failed: int = 0
    truncated: bool = False


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


RENDER_ORIGIN = "https://cloud-security-backend-y7ty.onrender.com"


def local_endpoint(base):
    """Accept loopback or the user's exact HTTPS deployment, never arbitrary hosts."""
    try:
        url = urlsplit(base)
        local = url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
        remote = (url.scheme == "https" and url.hostname == urlsplit(RENDER_ORIGIN).hostname
                  and url.port in {None, 443})
        valid_port = url.port is None or 1 <= url.port <= 65535
    except ValueError:
        raise CollectorError("Invalid backend URL or port") from None
    if (not (local or remote) or not valid_port or url.username or url.password
            or url.query or url.fragment or url.path not in {"", "/"}):
        raise CollectorError("Backend must be loopback HTTP or the approved Render HTTPS origin")
    return base.rstrip("/") + "/events"


def explicit_window(start, end):
    try:
        start = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if start.utcoffset() is None or end.utcoffset() is None:
            raise ValueError()
        start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if not now - timedelta(days=90) <= start < end <= now:
            raise ValueError()
        if end - start > timedelta(days=1):
            raise ValueError()
    except (ValueError, TypeError):
        raise CollectorError("Use timezone-aware start/end times in the past 90 days, at most 24 hours apart") from None
    return start, end


def lookup_page(params, region, profile=None):
    command = ["aws", "cloudtrail", "lookup-events", "--cli-input-json", json.dumps(params),
               "--region", region, "--output", "json", "--no-paginate", "--no-cli-pager",
               "--no-cli-auto-prompt", "--cli-connect-timeout", "5", "--cli-read-timeout", "20"]
    if profile:
        command += ["--profile", profile]
    env = dict(os.environ, AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="")
    for attempt in range(3):
        # Below the account/region lookup limit, including retries.
        time.sleep(0.6 if attempt == 0 else 2 ** attempt)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env)
        except FileNotFoundError:
            raise CollectorError("AWS CLI not found on PATH") from None
        except subprocess.TimeoutExpired:
            if attempt < 2:
                continue
            raise CollectorError("AWS lookup timed out; retry later") from None
        if result.returncode == 0:
            try:
                page = json.loads(result.stdout)
            except ValueError:
                raise CollectorError("AWS CLI returned malformed JSON") from None
            if not isinstance(page, dict) or not isinstance(page.get("Events"), list):
                raise CollectorError("AWS CLI returned an invalid lookup response")
            return page
        error = result.stderr.lower()
        if any(word in error for word in ("expired", "credentials", "login", "token", "sso")):
            raise CollectorError("AWS authentication unavailable or expired; run aws login for the selected profile")
        if "accessdenied" in error or "access denied" in error:
            raise CollectorError("AWS denied cloudtrail:LookupEvents for the selected identity")
        if any(word in error for word in ("throttl", "requestlimit", "too many requests")):
            if attempt < 2:
                continue
            raise CollectorError("AWS lookup remains throttled; retry later")
        raise CollectorError("AWS lookup failed; check the selected profile, region, and network")


def live_pages(region, profile, event_name, minutes, max_pages, start=None, end=None):
    end = end or datetime.now(timezone.utc)
    start = start or end - timedelta(minutes=minutes)
    params = {"StartTime": start.isoformat(),
              "EndTime": end.isoformat(), "MaxResults": 50,
              "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": event_name}]}
    tokens = set()
    for _ in range(max_pages):
        page = lookup_page(params, region, profile)
        yield page
        token = page.get("NextToken")
        if not token:
            return
        if not isinstance(token, str) or token in tokens:
            raise CollectorError("AWS returned an invalid or repeated pagination token")
        tokens.add(token)
        params["NextToken"] = token


def fixture_pages(path):
    try:
        page = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        raise CollectorError("Could not read the lookup-response JSON fixture") from None
    if not isinstance(page, dict) or not isinstance(page.get("Events"), list):
        raise CollectorError("Fixture must contain a CloudTrail LookupEvents response with an Events list")
    yield page


def post_event(endpoint, record):
    # Disable proxies and redirects so records and the key stay at the selected origin.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    request = Request(endpoint, data=json.dumps(record).encode(), method="POST",
                      headers={"Content-Type": "application/json",
                               **({"X-API-Key": os.environ["CLOUD_SECURITY_API_KEY"]}
                                  if os.environ.get("CLOUD_SECURITY_API_KEY") else {})})
    for attempt in range(3):
        try:
            with opener.open(request, timeout=60) as response:
                body = json.load(response)
            if (not isinstance(body, dict) or type(body.get("detected")) is not bool
                    or type(body.get("duplicate", False)) is not bool):
                raise CollectorError("Backend returned an invalid event result")
            return body
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise BackendUnavailable("Backend authentication rejected; check CLOUD_SECURITY_API_KEY") from None
            if exc.code == 429 or 500 <= exc.code < 600:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
            if exc.code == 429 or 500 <= exc.code < 600:
                raise BackendUnavailable(f"Backend unavailable (HTTP {exc.code}); retry later") from None
            raise CollectorError(f"Backend rejected event (HTTP {exc.code})") from None
        except (URLError, TimeoutError, OSError):
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise BackendUnavailable("Backend unreachable; check the URL or wait for Render to wake and retry") from None
        except ValueError:
            raise CollectorError("Backend returned malformed JSON") from None


def collect(pages, endpoint, summary, event_name, account_id=None, region=None):
    seen = set()
    for page in pages:
        summary.pages += 1
        summary.truncated = bool(page.get("NextToken"))
        for item in page["Events"]:
            summary.fetched += 1
            try:
                record = json.loads(item["CloudTrailEvent"])
                if not isinstance(record, dict):
                    raise ValueError("not an object")
                event_id = record.get("eventID")
                if not isinstance(event_id, str) or not event_id.strip():
                    raise ValueError("missing event ID")
                if record.get("eventName") != event_name or record.get("errorCode") or record.get("errorMessage"):
                    summary.ignored += 1
                    continue
                if account_id and record.get("recipientAccountId") != account_id:
                    summary.ignored += 1
                    continue
                if region and record.get("awsRegion") != region:
                    summary.ignored += 1
                    continue
                if event_id in seen:
                    summary.duplicates += 1
                    continue
                result = post_event(endpoint, record)
                seen.add(event_id)
                if result.get("duplicate"):
                    summary.duplicates += 1
                elif result["detected"]:
                    summary.created += 1
                else:
                    summary.ignored += 1
            except BackendUnavailable:
                summary.failed += 1
                raise
            except CollectorError as exc:
                summary.failed += 1
                print(str(exc), file=sys.stderr)
            except (KeyError, TypeError, ValueError):
                summary.failed += 1
                print("Skipped malformed CloudTrail record", file=sys.stderr)
    return summary


def bounded_int(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected an integer") from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Choose a value from {low} to {high}")
        return number
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fixture", help="Local LookupEvents response JSON; no AWS access")
    mode.add_argument("--live", action="store_true", help="Explicitly enable read-only AWS lookup")
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--profile")
    parser.add_argument("--account-id", help="Optional expected recipient account; other accounts are skipped")
    parser.add_argument("--event-name", choices=sorted(WATCHED), default="AuthorizeSecurityGroupIngress")
    parser.add_argument("--minutes", type=bounded_int(1, 1440), default=30)
    parser.add_argument("--start-time", help="ISO 8601 time with timezone, paired with --end-time")
    parser.add_argument("--end-time", help="End of a historical window, at most 24 hours wide")
    parser.add_argument("--max-pages", type=bounded_int(1, 20), default=2)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    args = parser.parse_args(argv)
    summary = Summary()
    try:
        endpoint = local_endpoint(args.backend_url)
        if urlsplit(endpoint).scheme == "https":
            if not os.environ.get("CLOUD_SECURITY_API_KEY"):
                raise CollectorError("Set CLOUD_SECURITY_API_KEY before sending events to Render")
        window = None
        if args.start_time or args.end_time:
            if not args.live or not (args.start_time and args.end_time):
                raise CollectorError("Historical lookup requires --live and both --start-time and --end-time")
            window = explicit_window(args.start_time, args.end_time)
        endpoint += "?origin=" + ("aws-cloudtrail" if args.live else "fixture")
        pages = (fixture_pages(args.fixture) if args.fixture else
                 live_pages(args.region, args.profile, args.event_name, args.minutes, args.max_pages,
                            **(dict(start=window[0], end=window[1]) if window else {})))
        collect(pages, endpoint, summary, args.event_name, args.account_id, args.region)
    except CollectorError as exc:
        print(str(exc), file=sys.stderr)
        print(json.dumps(asdict(summary)))
        return 2
    print(json.dumps(asdict(summary)))
    return 2 if summary.failed or summary.truncated else 0


if __name__ == "__main__":
    sys.exit(main())
