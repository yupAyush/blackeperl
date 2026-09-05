#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Web Route Verification Test Suite for De-anonymization Blueprint
"""

import os
import sys
import unittest
from flask import Flask

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'bin'))
sys.path.insert(0, os.path.join(BASE_DIR, 'var/www'))

from blueprints.deanonymization import deanonymization


class TestDeanonymizationWebRoutes(unittest.TestCase):
    """Test HTTP endpoints registered by the deanonymization blueprint."""

    def setUp(self):
        self.app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'var/www/templates'))
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'sih2026-test-key'

        # Register dummy endpoints referenced by nav_bar.html
        dummy_endpoints = [
            'dashboard.index', 'dashboard.objects_dashboard', 'PasteSubmit.PasteSubmit_page',
            'tags_ui.tags_search_items', 'hunters.trackers_dashboard',
            'crawler_splash.crawlers_dashboard', 'investigations_b.investigations_dashboard',
            'search_b.search_dashboard', 'settings_b.settings_page', 'root.logout'
        ]
        for ep in dummy_endpoints:
            self.app.add_url_rule(f'/{ep.replace(".", "/")}', endpoint=ep, view_func=lambda: 'dummy')

        self.app.register_blueprint(deanonymization)
        self.client = self.app.test_client()

    def test_dashboard_route(self):
        response = self.client.get('/deanonymization')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Threat Actor De-anonymization Suite', response.data)
        self.assertIn(b'DarkSpectre', response.data)

    def test_actor_profile_route(self):
        response = self.client.get('/deanonymization/actor/ACTOR-001-DARKSPECTRE')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'DarkSpectre', response.data)
        self.assertIn(b'Dread Forum', response.data)
        self.assertIn(b'185.220.101.45', response.data)

    def test_relationship_graph_route(self):
        response = self.client.get('/deanonymization/graph/ACTOR-001-DARKSPECTRE')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'networkGraph', response.data)

    def test_api_graph_route(self):
        response = self.client.get('/deanonymization/api/graph/ACTOR-001-DARKSPECTRE')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('nodes', data)
        self.assertIn('links', data)
        self.assertTrue(len(data['nodes']) > 0)

    def test_misconfig_scanner_routes(self):
        # GET
        response = self.client.get('/deanonymization/misconfig')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Tor Hidden Service Misconfiguration Auditor', response.data)

        # POST sample target
        response = self.client.post('/deanonymization/misconfig', data={'onion_url': 'darkspectrelk7v43.onion'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'185.220.101.45', response.data)
        self.assertIn(b'Hetzner Online GmbH', response.data)

    def test_stylometry_routes(self):
        # GET
        response = self.client.get('/deanonymization/stylometry')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AI Stylometric Persona Identification', response.data)

        # POST comparison
        data = {
            'suspect_handle': 'PhantomCipher',
            'text_a': 'Corporate SQL dumps and internal database leaks available now... escrow accepted via Dread!!',
            'text_b': 'Internal corporate SQL dumps and database access available... escrow accepted!!'
        }
        response = self.client.post('/deanonymization/stylometry', data=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'PROBABLE REBRANDED IDENTITY', response.data)

    def test_timeline_route(self):
        response = self.client.get('/deanonymization/timeline')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Threat Actor Activity & Infrastructure Timeline', response.data)

    def test_export_csv_route(self):
        response = self.client.get('/deanonymization/export/csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'text/csv; charset=utf-8')
        self.assertIn(b'Actor ID,Primary Alias', response.data)
        self.assertIn(b'DarkSpectre', response.data)

    def test_export_json_route(self):
        response = self.client.get('/deanonymization/export/json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
        data = response.get_json()
        self.assertIn('threat_actors', data)
        self.assertIn('metadata', data)

    def test_export_report_route(self):
        response = self.client.get('/deanonymization/export/report?actor_id=ACTOR-001-DARKSPECTRE')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'DARK WEB THREAT ACTOR ATTRIBUTION REPORT', response.data)
        self.assertIn(b'185.220.101.45', response.data)


if __name__ == '__main__':
    unittest.main()
