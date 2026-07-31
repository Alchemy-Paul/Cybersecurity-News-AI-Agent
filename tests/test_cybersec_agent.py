import unittest

from cybersec_agent import CybersecNewsAgent


class CybersecAgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = CybersecNewsAgent()
        self.agent.stories = [
            {
                "title": "Critical RCE in enterprise VPN",
                "url": "https://example.com/vpn",
                "source": "Example Feed",
                "points": 42,
                "comments": 8,
                "created": "2026-07-30T12:00:00Z",
                "summary": "A severe vulnerability affects enterprise VPN appliances.",
                "cves": [{"id": "CVE-2026-12345", "tag": "🔴 CRITICAL"}],
            },
            {
                "title": "Phishing campaign targets finance teams",
                "url": "https://example.com/phish",
                "source": "Example Feed",
                "points": 20,
                "comments": 3,
                "created": "2026-07-30T11:00:00Z",
                "summary": "Attackers impersonate finance executives to steal credentials.",
            },
        ]

    def test_sanitize_text_removes_html_and_truncates(self):
        raw = "<p>Hello <b>world</b> &amp; friends</p>"
        result = self.agent.sanitize_text(raw, max_length=20)
        self.assertEqual(result, "Hello world & friends")

    def test_build_briefing_prompt_contains_required_sections(self):
        prompt = self.agent.build_briefing_prompt(self.agent.stories[:2])
        self.assertIn("EXECUTIVE SUMMARY", prompt)
        self.assertIn("CRITICAL HIGHLIGHTS", prompt)
        self.assertIn("RECOMMENDED ACTIONS", prompt)
        self.assertIn("CVE-2026-12345", prompt)

    def test_score_story_relevance_increases_for_cve_and_engagement(self):
        base_story = {
            "title": "Routine update",
            "summary": "A standard patch was released.",
            "points": 15,
            "comments": 4,
            "source": "Example Feed",
        }
        cve_story = {
            "title": "Critical RCE in VPN appliance",
            "summary": "A severe vulnerability affects enterprise VPN appliances.",
            "points": 50,
            "comments": 20,
            "source": "Example Feed",
            "cves": [{"id": "CVE-2026-12345", "tag": "🔴 CRITICAL"}],
        }

        base_score = self.agent.score_story_relevance(base_story)
        cve_score = self.agent.score_story_relevance(cve_story)

        self.assertGreater(cve_score, base_score)
        self.assertIn("cve", self.agent.score_story_relevance(cve_story, return_reasons=True).lower())

    def test_enrich_cve_entry_uses_fallback_for_unknown_cve(self):
        enriched = self.agent.enrich_cve_entry(
            "CVE-9999-99999",
            title="Critical auth bypass in VPN",
            summary="A security issue allows attackers to bypass login controls.",
        )

        self.assertEqual(enriched["tag"], "🔴 CRITICAL")
        self.assertEqual(enriched["severity"], "critical")
        self.assertIn("auth bypass", enriched["summary"].lower())


if __name__ == "__main__":
    unittest.main()
