"""Explicit, allowlisted retrieval of CISA KEV and FIRST EPSS (DESIGN §5, §15).

- Only the official URLs below can be fetched. There is no arbitrary-URL fetch API.
- Every hop (including redirects) must be HTTPS to an allowlisted host whose DNS answers
  are all public addresses (no loopback/private/link-local/cloud-metadata).
- Responses are size-capped and then go through the same adapters as file imports, so a
  failed or malformed retrieval never removes existing evidence.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

import httpx
from sqlalchemy import select

from tiw.adapters.common import MAX_FILE_BYTES, RowError
from tiw.domain.vocab import CVE_RE
from tiw.services.ingest import ImportOutcome, _failed, run_import
from tiw.storage import db
from tiw.storage.models import Finding, Observation

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
ALLOWED_HOSTS = {"www.cisa.gov", "api.first.org"}
USER_AGENT = "threat-intel-workbench/0.1 (+local analyst tool)"
EPSS_BATCH = 100
MAX_REDIRECTS = 3
RETRIES = 2


class FetchError(Exception):
    pass


Resolver = Callable[[str], list[str]]


def _system_resolver(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})


def check_url(url: str, resolver: Resolver = _system_resolver) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchError(f"refusing non-HTTPS URL {url}")
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise FetchError(f"host {host or '?'} is not on the allowlist")
    if parts.port not in (None, 443):
        raise FetchError("non-standard port refused")
    try:
        addrs = resolver(host)
    except OSError as exc:
        raise FetchError(f"DNS lookup for {host} failed: {exc}") from None
    if not addrs:
        raise FetchError(f"DNS lookup for {host} returned nothing")
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not ip.is_global or ip.is_multicast or str(ip) in ("169.254.169.254", "fd00:ec2::254"):
            raise FetchError(f"{host} resolves to a non-public address ({ip}); refused")


@dataclass
class Fetcher:
    client: httpx.Client
    resolver: Resolver = _system_resolver
    sleep: Callable[[float], None] = time.sleep

    def get(self, url: str, params: dict[str, str] | None = None) -> bytes:
        last: Exception | None = None
        for attempt in range(RETRIES + 1):
            try:
                return self._get_once(url, params)
            except FetchError:
                raise
            except (httpx.TransportError, _Retryable) as exc:
                last = exc
                if attempt < RETRIES:
                    self.sleep(1.5 * (attempt + 1))
        raise FetchError(f"retrieval failed after {RETRIES + 1} attempts: {last}")

    def _get_once(self, url: str, params: dict[str, str] | None) -> bytes:
        current = str(httpx.URL(url, params=params)) if params else url
        for _hop in range(MAX_REDIRECTS + 1):
            check_url(current, self.resolver)
            with self.client.stream("GET", current, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location")
                    if not loc:
                        raise FetchError("redirect without a Location header")
                    current = urljoin(current, loc)
                    continue
                if r.status_code >= 500 or r.status_code == 429:
                    raise _Retryable(f"HTTP {r.status_code}")
                if r.status_code != 200:
                    raise FetchError(f"HTTP {r.status_code} from {urlsplit(current).hostname}")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > MAX_FILE_BYTES:
                        raise FetchError(f"response exceeds {MAX_FILE_BYTES} bytes")
                return bytes(buf)
        raise FetchError("too many redirects")


class _Retryable(Exception):
    pass


def default_fetcher() -> Fetcher:
    return Fetcher(httpx.Client(follow_redirects=False, timeout=httpx.Timeout(30.0, connect=10.0), trust_env=False))


def _guard_live(ws: db.Workspace) -> None:
    with db.session_scope(ws) as s:
        if db.is_synthetic_workspace(s):
            raise FetchError("this is a synthetic demo workspace; live feeds are only fetched into a live workspace")


def fetch_kev(ws: db.Workspace, fetcher: Fetcher | None = None, actor: str = "cli") -> ImportOutcome:
    _guard_live(ws)
    f = fetcher or default_fetcher()
    try:
        data = f.get(KEV_URL)
    except FetchError as exc:
        return _failed(ws, "kev", "kev-1", "fetch-failed", [RowError(None, "fetch", str(exc))], actor, False)
    return run_import(ws, "kev", data, actor=actor)


def relevant_cves(ws: db.Workspace) -> list[str]:
    """CVEs that matter locally: those with findings or locally observed activity."""
    with db.session_scope(ws) as s:
        ids = set(s.execute(select(Finding.vulnerability_id)).scalars())
        ids |= {v for v in s.execute(select(Observation.cve_id).where(Observation.cve_id.is_not(None))).scalars()}
    return sorted(v for v in ids if CVE_RE.match(v))


def fetch_epss(
    ws: db.Workspace, fetcher: Fetcher | None = None, actor: str = "cli", cves: list[str] | None = None
) -> ImportOutcome:
    _guard_live(ws)
    targets = cves if cves is not None else relevant_cves(ws)
    if not targets:
        raise FetchError("no CVEs to score: import findings first (EPSS is fetched only for CVEs you track)")
    f = fetcher or default_fetcher()
    rows: list[dict] = []
    try:
        for i in range(0, len(targets), EPSS_BATCH):
            batch = targets[i : i + EPSS_BATCH]
            raw = f.get(EPSS_URL, params={"cve": ",".join(batch)})
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError:
                raise FetchError("EPSS response was not valid JSON") from None
            if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
                raise FetchError("unexpected EPSS response layout")
            rows.extend(doc["data"])
    except FetchError as exc:
        return _failed(ws, "epss", "epss-1", "fetch-failed", [RowError(None, "fetch", str(exc))], actor, False)
    payload = json.dumps({"status": "OK", "data": rows}, sort_keys=True).encode()
    return run_import(ws, "epss", payload, actor=actor)
