#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Automated Test Suite: SIH 2026 Dark Web Threat Actor De-anonymization Platform
=============================================================================
Tests all core engines:
1. Tor Misconfiguration Scanner & Clearnet Origin Attribution
2. Cross-Marketplace Threat Actor Profiling & Relationship Graph
3. AI Stylometric Persona Identification & Behavioral Profiling
4. Timeline Querying & Export Generation (CSV, JSON)
"""

import os
import sys
import unittest
import json
import tempfile

# Set environment paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'bin'))

from lib.tor_origin_attribution import TorMisconfigScanner
from lib.threat_actor_engine import ThreatActorEngine
from lib.ai_stylometry_engine import AIStylometryEngine
from lib.objects.ThreatActors import ThreatActor


class TestDeanonymizationPlatform(unittest.TestCase):
    """Unit and Integration tests for De-anonymization Suite."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.engine = ThreatActorEngine(db_path=self.temp_db.name)
        self.scanner = TorMisconfigScanner()
        self.stylometry = AIStylometryEngine()

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_tor_misconfiguration_origin_attribution(self):
        """Test active probe detection of /server-status and clearnet origin attribution."""
        custom_samples = {
            "/server-status": """
                <html><head><title>Apache Status</title></head><body>
                <h1>Apache Server Status for srv-darkmarket.clearnet-host.com (via 185.220.101.45)</h1>
                <dl><dt>Server Version: Apache/2.4.41 (Ubuntu)</dt></dl>
                <table><tr><th>VHost</th><th>Client</th></tr>
                <tr><td>srv-darkmarket.clearnet-host.com</td><td>185.220.101.45</td></tr>
                </table></body></html>
            """,
            "tls_cert": {
                "valid": True,
                "common_name": "srv-darkmarket.clearnet-host.com",
                "sans": ["srv-darkmarket.clearnet-host.com", "darkspectrelk7v43.onion"],
                "serial_number": "04:a1:b2:c3:d4:e5:f6:01:23:45:67:89:ab:cd:ef",
                "fingerprint_sha256": "4a71b899e120f812bb449011aa8877223344556677889900aabbccddeeff0011",
                "issuer": "Let's Encrypt Authority X3",
                "has_clearnet_domain": True
            },
            "favicon_bytes": b"TEST_FAVICON_PAYLOAD"
        }

        audit = self.scanner.scan_misconfigurations("http://darkspectrelk7v43.onion", custom_html_samples=custom_samples)
        
        self.assertIsNotNone(audit)
        self.assertEqual(audit["domain"], "darkspectrelk7v43.onion")
        self.assertGreaterEqual(audit["findings_count"], 1)

        origin = audit["origin_attribution"]
        self.assertTrue(origin["unmasked"])
        self.assertGreaterEqual(origin["attribution_confidence"], 90.0)
        self.assertEqual(origin["primary_origin"]["origin_ip"], "185.220.101.45")
        self.assertEqual(origin["primary_origin"]["hostname"], "srv-darkmarket.clearnet-host.com")
        self.assertEqual(origin["primary_origin"]["isp"], "Hetzner Online GmbH")

    def test_threat_actor_engine_and_graph_generation(self):
        """Test ThreatActor querying, persistence, and relationship graph generation."""
        actors = self.engine.get_all_actors()
        self.assertGreaterEqual(len(actors), 3)

        actor = self.engine.get_actor_by_id("ACTOR-001-DARKSPECTRE")
        self.assertIsNotNone(actor)
        self.assertEqual(actor.get_primary_alias(), "DarkSpectre")
        self.assertEqual(actor.get_risk_level(), "CRITICAL")
        self.assertGreaterEqual(len(actor.get_aliases()), 2)
        self.assertGreaterEqual(len(actor.get_crypto_wallets()), 2)

        # Test graph generation
        graph = self.engine.build_actor_relationship_graph("ACTOR-001-DARKSPECTRE")
        self.assertIn("nodes", graph)
        self.assertIn("links", graph)
        self.assertIn("categories", graph)
        
        node_names = [n["name"] for n in graph["nodes"]]
        self.assertIn("DarkSpectre", node_names)
        self.assertTrue(any("Origin:" in name for name in node_names))

    def test_ai_stylometry_feature_extraction_and_matching(self):
        """Test writeprint NLP feature vector, cosine similarity, and diurnal timezone."""
        text_a = "We are offering high quality database leaks and enterprise corporate access. Proof of funds required... escrow accepted via Dread trusted escrow. Do not message without PGP encryption!!"
        text_b = "Offering high quality corporate database leaks and internal access. Proof of funds required before sample... escrow accepted on forum!! All communication must be encrypted with PGP."

        wp_a = self.stylometry.extract_writeprint(text_a)
        wp_b = self.stylometry.extract_writeprint(text_b)

        self.assertGreater(wp_a["total_words"], 10)
        self.assertGreater(wp_a["lexical"]["ttr"], 0)
        self.assertGreater(wp_a["lexical"]["yules_k"], 0)
        self.assertIn("!", wp_a["punctuation_per_1k"])

        similarity = self.stylometry.compute_stylometric_similarity(wp_a, wp_b)
        self.assertGreaterEqual(similarity["overall_similarity"], 65.0)
        self.assertIn(similarity["confidence_rating"], ["HIGH", "MODERATE"])

        # Test diurnal 24h timezone inference
        timestamps = [
            "2026-08-20 11:20:00", "2026-08-21 13:45:00", "2026-08-22 15:10:00",
            "2026-08-23 17:30:00", "2026-08-24 12:00:00", "2026-08-25 14:15:00"
        ]
        diurnal = self.stylometry.generate_diurnal_timezone_profile(timestamps)
        self.assertEqual(len(diurnal["hourly_distribution"]), 24)
        self.assertIn("UTC", diurnal["estimated_timezone_offset"])

    def test_timeline_events_extraction(self):
        """Test chronological footprint aggregation across actors."""
        events = self.engine.get_timeline_events()
        self.assertGreater(len(events), 5)
        # Check sorted descending
        dates = [e["date"] for e in events]
        self.assertEqual(dates, sorted(dates, reverse=True))


if __name__ == '__main__':
    unittest.main()
