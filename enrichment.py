"""Vulnerability enrichment for the briefing agent.

Pulls authoritative data instead of guessing from headlines:

* CISA KEV  - is the CVE known to be exploited in the wild?
* FIRST EPSS - probability of exploitation in the next 30 days
* NVD       - CVSS base score and affected vendors/products (CPE)

Every lookup is cached on disk. A failed lookup yields ``None`` for that field,
never a made-up value, so callers can tell "not exploited" from "we don't know".
"""

import json
import logging
import re
import time
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "CybersecNewsAgent/1.0"
HTTP_RETRY_ATTEMPTS = 3
HTTP_RETRY_BACKOFF = 1
logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

KEV_TTL = 12 * 3600
EPSS_TTL = 24 * 3600
NVD_TTL = 7 * 24 * 3600
HTTP_TIMEOUT = 15
EPSS_BATCH_SIZE = 50


def extract_cve_ids(*texts):
    """Return unique, upper-cased CVE IDs found in the given texts, in order."""
    seen = []
    for text in texts:
        for match in CVE_RE.findall(text or ""):
            cve_id = match.upper()
            if cve_id not in seen:
                seen.append(cve_id)
    return seen


def severity_from_score(score):
    """Map a CVSS base score to (severity, tag). Unknown stays unknown."""
    if score is None:
        return "unknown", "⚪ UNKNOWN"
    if score >= 9.0:
        return "critical", "🔴 CRITICAL"
    if score >= 7.0:
        return "high", "🟠 HIGH"
    if score >= 4.0:
        return "medium", "🟡 MEDIUM"
    return "low", "🟢 LOW"


class DiskCache:
    """Tiny JSON-file cache with per-entry expiry. Corrupt files are ignored."""

    def __init__(self, path, clock=time.time):
        self.path = Path(path) if path else None
        self.clock = clock
        self.data = {}
        self.dirty = False
        if self.path and self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except (OSError, ValueError):
                self.data = {}

    def get(self, key, ttl):
        entry = self.data.get(key)
        if not isinstance(entry, dict):
            return None
        if self.clock() - entry.get("ts", 0) > ttl:
            return None
        return entry.get("value")

    def set(self, key, value):
        self.data[key] = {"ts": self.clock(), "value": value}
        self.dirty = True

    def save(self):
        if not (self.path and self.dirty):
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data), encoding="utf-8")
            tmp.replace(self.path)
            self.dirty = False
        except OSError as exc:
            logger.warning("Could not write enrichment cache: %s", exc)


class VulnEnricher:
    def __init__(self, cache_path=None, nvd_api_key="", http=None,
                 max_nvd_lookups=15, sleep=time.sleep, clock=time.time):
        self.cache = DiskCache(cache_path, clock=clock)
        self.nvd_api_key = nvd_api_key or ""
        self.http = http or requests
        self.max_nvd_lookups = max_nvd_lookups
        self.sleep = sleep
        self.kev = None  # dict once loaded; None means the feed was unavailable
        self._nvd_lookups = 0

    # -- HTTP -------------------------------------------------------------
    def _get_json(self, url, params=None, headers=None):
        merged = {"User-Agent": USER_AGENT}
        merged.update(headers or {})
        for attempt in range(HTTP_RETRY_ATTEMPTS):
            try:
                response = self.http.get(
                    url, params=params, headers=merged, timeout=HTTP_TIMEOUT
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                if attempt + 1 == HTTP_RETRY_ATTEMPTS:
                    raise
                delay = HTTP_RETRY_BACKOFF * (2 ** attempt)
                logger.warning(
                    "GET %s failed (attempt %s/%s): %s; retrying in %s seconds",
                    url, attempt + 1, HTTP_RETRY_ATTEMPTS, exc, delay
                )
                self.sleep(delay)

    # -- CISA KEV ---------------------------------------------------------
    def load_kev(self):
        """Load the KEV catalogue (cached). Leaves ``self.kev`` as None on failure."""
        cached = self.cache.get("kev", KEV_TTL)
        if cached is not None:
            self.kev = cached
            return self.kev
        try:
            payload = self._get_json(KEV_URL)
            catalogue = {}
            for item in payload.get("vulnerabilities", []):
                cve_id = (item.get("cveID") or "").upper()
                if not cve_id:
                    continue
                catalogue[cve_id] = {
                    "vendor": item.get("vendorProject", ""),
                    "product": item.get("product", ""),
                    "name": item.get("vulnerabilityName", ""),
                    "date_added": item.get("dateAdded", ""),
                    "due_date": item.get("dueDate", ""),
                    "ransomware": (item.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
                }
            self.kev = catalogue
            self.cache.set("kev", catalogue)
        except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
            logger.error("Could not load CISA KEV catalogue: %s", exc)
            self.kev = None
        return self.kev

    # -- EPSS -------------------------------------------------------------
    def fetch_epss(self, cve_ids):
        """Return {CVE: (epss, percentile)} for the CVEs that FIRST knows about."""
        results = {}
        missing = []
        for cve_id in cve_ids:
            cached = self.cache.get(f"epss:{cve_id}", EPSS_TTL)
            if cached is not None:
                results[cve_id] = tuple(cached)
            else:
                missing.append(cve_id)

        for start in range(0, len(missing), EPSS_BATCH_SIZE):
            batch = missing[start:start + EPSS_BATCH_SIZE]
            try:
                payload = self._get_json(EPSS_URL, params={"cve": ",".join(batch)})
            except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
                logger.error("Could not fetch EPSS scores: %s", exc)
                continue
            for row in payload.get("data", []):
                try:
                    cve_id = row["cve"].upper()
                    value = (float(row["epss"]), float(row["percentile"]))
                except (KeyError, TypeError, ValueError):
                    continue
                results[cve_id] = value
                self.cache.set(f"epss:{cve_id}", list(value))
        return results

    # -- NVD --------------------------------------------------------------
    def fetch_nvd(self, cve_id):
        """Return {score, vendors, products, description} or None if unavailable."""
        cached = self.cache.get(f"nvd:{cve_id}", NVD_TTL)
        if cached is not None:
            return cached
        if self._nvd_lookups >= self.max_nvd_lookups:
            return None
        if self._nvd_lookups > 0:
            # NVD allows 5 requests / 30s without a key and 50 / 30s with one.
            self.sleep(0.7 if self.nvd_api_key else 6.5)
        self._nvd_lookups += 1

        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else None
        try:
            payload = self._get_json(NVD_URL, params={"cveId": cve_id}, headers=headers)
        except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
            logger.error("Could not fetch NVD data for %s: %s", cve_id, exc)
            return None

        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            return None
        record = self._parse_nvd(vulns[0].get("cve", {}))
        self.cache.set(f"nvd:{cve_id}", record)
        return record

    @staticmethod
    def _parse_nvd(cve):
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                try:
                    score = float(entries[0]["cvssData"]["baseScore"])
                    break
                except (KeyError, TypeError, ValueError):
                    continue

        vendors, products = [], []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue
                    parts = (match.get("criteria") or "").split(":")
                    if len(parts) > 4:
                        vendor = parts[3].replace("_", " ")
                        product = parts[4].replace("_", " ")
                        if vendor not in vendors:
                            vendors.append(vendor)
                        if product not in products:
                            products.append(product)

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        return {
            "score": score,
            "vendors": vendors[:30],
            "products": products[:30],
            "description": description,
        }

    # -- Public API -------------------------------------------------------
    def enrich(self, cve_ids):
        """Return {CVE: record}. Fields are None when the source had no answer."""
        cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids))
        if not cve_ids:
            return {}

        self.load_kev()
        epss = self.fetch_epss(cve_ids)

        records = {}
        for cve_id in cve_ids:
            nvd = self.fetch_nvd(cve_id) or {}
            kev_info = self.kev.get(cve_id) if self.kev is not None else None

            vendors = list(nvd.get("vendors", []))
            products = list(nvd.get("products", []))
            if kev_info:
                for value, bucket in ((kev_info["vendor"], vendors), (kev_info["product"], products)):
                    value = (value or "").lower()
                    if value and value not in bucket:
                        bucket.append(value)

            epss_value, epss_pct = epss.get(cve_id, (None, None))
            records[cve_id] = {
                "id": cve_id,
                "score": nvd.get("score"),
                "description": nvd.get("description", ""),
                "vendors": vendors,
                "products": products,
                "nvd_available": bool(nvd),
                # None = KEV feed unavailable, so we cannot say either way.
                "kev": None if self.kev is None else kev_info is not None,
                "kev_info": kev_info,
                "epss": epss_value,
                "epss_percentile": epss_pct,
                "epss_available": epss_value is not None,
            }

        self.cache.save()
        return records
