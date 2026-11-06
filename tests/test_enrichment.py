import tempfile
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from enrichment import VulnEnricher, extract_cve_ids, severity_from_score
from tests.fakes import FakeHttp
from watchlist import load_watchlist, match_watchlist


def make_enricher(http, cache_path=None, **kwargs):
    return VulnEnricher(cache_path=cache_path, http=http, sleep=lambda s: None, **kwargs)


class HelperTests(unittest.TestCase):
    def test_extract_cve_ids_dedupes_and_uppercases(self):
        ids = extract_cve_ids("Fix for cve-2026-1111", "also CVE-2026-1111 and CVE-2026-2222")
        self.assertEqual(ids, ["CVE-2026-1111", "CVE-2026-2222"])

    def test_extract_cve_ids_ignores_partial_matches(self):
        self.assertEqual(extract_cve_ids("XCVE-2026-1111Y"), [])

    def test_unknown_score_is_unknown_not_invented(self):
        self.assertEqual(severity_from_score(None), ("unknown", "⚪ UNKNOWN"))

    def test_severity_boundaries(self):
        self.assertEqual(severity_from_score(9.0)[0], "critical")
        self.assertEqual(severity_from_score(7.0)[0], "high")
        self.assertEqual(severity_from_score(4.0)[0], "medium")
        self.assertEqual(severity_from_score(3.9)[0], "low")


class EnricherTests(unittest.TestCase):
    def test_combines_kev_epss_and_nvd(self):
        records = make_enricher(FakeHttp()).enrich(["CVE-2026-1111", "CVE-2026-2222"])

        hot = records["CVE-2026-1111"]
        self.assertTrue(hot["kev"])
        self.assertTrue(hot["kev_info"]["ransomware"])
        self.assertEqual(hot["score"], 9.8)
        self.assertAlmostEqual(hot["epss"], 0.91)
        self.assertIn("fortinet", hot["vendors"])
        self.assertIn("fortios", hot["products"])

        quiet = records["CVE-2026-2222"]
        self.assertIs(quiet["kev"], False)
        self.assertIn("exchange server", quiet["products"])

    def test_kev_outage_is_unknown_not_false(self):
        records = make_enricher(FakeHttp(fail={"kev"})).enrich(["CVE-2026-1111"])
        self.assertIsNone(records["CVE-2026-1111"]["kev"])

    def test_nvd_outage_leaves_score_none(self):
        records = make_enricher(FakeHttp(fail={"nvd"})).enrich(["CVE-2026-1111"])
        self.assertIsNone(records["CVE-2026-1111"]["score"])
        self.assertTrue(records["CVE-2026-1111"]["kev"])  # other sources still work

    def test_epss_outage_leaves_epss_none(self):
        records = make_enricher(FakeHttp(fail={"epss"})).enrich(["CVE-2026-1111"])
        self.assertIsNone(records["CVE-2026-1111"]["epss"])

    def test_unknown_cve_gets_empty_record_without_error(self):
        records = make_enricher(FakeHttp()).enrich(["CVE-2026-9999"])
        self.assertIsNone(records["CVE-2026-9999"]["score"])
        self.assertIs(records["CVE-2026-9999"]["kev"], False)

    def test_results_are_cached_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            first = FakeHttp()
            make_enricher(first, cache).enrich(["CVE-2026-1111"])
            self.assertEqual(first.calls, {"kev": 1, "epss": 1, "nvd": 1})

            second = FakeHttp()
            records = make_enricher(second, cache).enrich(["CVE-2026-1111"])
            self.assertEqual(second.calls, {"kev": 0, "epss": 0, "nvd": 0})
            self.assertTrue(records["CVE-2026-1111"]["kev"])

    def test_corrupt_cache_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            cache.write_text("{not json", encoding="utf-8")
            records = make_enricher(FakeHttp(), cache).enrich(["CVE-2026-1111"])
            self.assertTrue(records["CVE-2026-1111"]["kev"])

    def test_nvd_lookup_cap_and_throttle(self):
        sleeps = []
        http = FakeHttp()
        enricher = VulnEnricher(http=http, sleep=sleeps.append, max_nvd_lookups=1)
        records = enricher.enrich(["CVE-2026-1111", "CVE-2026-2222"])

        self.assertEqual(http.calls["nvd"], 1)
        self.assertEqual(records["CVE-2026-1111"]["score"], 9.8)
        self.assertIsNone(records["CVE-2026-2222"]["score"])

    def test_nvd_throttles_between_lookups(self):
        sleeps = []
        enricher = VulnEnricher(http=FakeHttp(), sleep=sleeps.append)
        enricher.enrich(["CVE-2026-1111", "CVE-2026-2222"])
        self.assertEqual(sleeps, [6.5])  # no API key -> conservative delay

        sleeps.clear()
        keyed = VulnEnricher(http=FakeHttp(), sleep=sleeps.append, nvd_api_key="k")
        keyed.enrich(["CVE-2026-1111", "CVE-2026-2222"])
        self.assertEqual(sleeps, [0.7])


class WatchlistTests(unittest.TestCase):
    def test_load_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watchlist.txt"
            path.write_text("# my stack\nFortinet\n\nMicrosoft Exchange  # mail\nfortinet\n", encoding="utf-8")
            self.assertEqual(load_watchlist(path), ["fortinet", "microsoft exchange"])

    def test_missing_file_gives_empty_list(self):
        self.assertEqual(load_watchlist("/nonexistent/watchlist.txt"), [])

    def test_matches_whole_words_only(self):
        terms = ["exchange"]
        self.assertEqual(match_watchlist(terms, texts=["Microsoft Exchange flaw"]), ["exchange"])
        self.assertEqual(match_watchlist(terms, texts=["Crypto exchanged hands"]), [])

    def test_matches_cpe_style_names(self):
        hits = match_watchlist(["exchange server"], vendors_products=["exchange server", "microsoft"])
        self.assertEqual(hits, ["exchange server"])

    def test_empty_watchlist_matches_nothing(self):
        self.assertEqual(match_watchlist([], texts=["Fortinet"]), [])


if __name__ == "__main__":
    unittest.main()
