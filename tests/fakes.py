"""Offline stand-ins for the network so tests never touch the internet."""

import requests

from enrichment import EPSS_URL, KEV_URL, NVD_URL


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1111",
            "vendorProject": "Fortinet",
            "product": "FortiOS",
            "vulnerabilityName": "Fortinet FortiOS auth bypass",
            "dateAdded": "2026-11-01",
            "dueDate": "2026-11-22",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
}

EPSS_PAYLOAD = {
    "data": [
        {"cve": "CVE-2026-1111", "epss": "0.91000", "percentile": "0.99000"},
        {"cve": "CVE-2026-2222", "epss": "0.02000", "percentile": "0.55000"},
    ]
}


def nvd_payload(cve_id, score, cpe):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": f"Description of {cve_id}."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
                    "configurations": [
                        {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}
                    ],
                }
            }
        ]
    }


class FakeHttp:
    """Routes the three enrichment endpoints to canned data and counts calls."""

    def __init__(self, kev=KEV_PAYLOAD, epss=EPSS_PAYLOAD, nvd=None, fail=()):
        self.kev = kev
        self.epss = epss
        self.nvd = nvd if nvd is not None else {
            "CVE-2026-1111": nvd_payload("CVE-2026-1111", 9.8, "cpe:2.3:o:fortinet:fortios:7.0.0:*:*:*:*:*:*:*"),
            "CVE-2026-2222": nvd_payload("CVE-2026-2222", 5.3, "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"),
        }
        self.fail = set(fail)
        self.calls = {"kev": 0, "epss": 0, "nvd": 0}

    def get(self, url, params=None, headers=None, timeout=None):
        if url == KEV_URL:
            self.calls["kev"] += 1
            if "kev" in self.fail:
                return FakeResponse({}, 503)
            return FakeResponse(self.kev)
        if url == EPSS_URL:
            self.calls["epss"] += 1
            if "epss" in self.fail:
                return FakeResponse({}, 503)
            return FakeResponse(self.epss)
        if url == NVD_URL:
            self.calls["nvd"] += 1
            if "nvd" in self.fail:
                return FakeResponse({}, 503)
            return FakeResponse(self.nvd.get(params["cveId"], {"vulnerabilities": []}))
        raise AssertionError(f"unexpected network call: {url}")
