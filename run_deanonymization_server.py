#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
SIH 2026 Dark Web Threat Actor De-anonymization Platform
========================================================
Interactive standalone web runner for hackathon demonstrations,
testing, and live threat actor investigation.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'bin'))
sys.path.insert(0, os.path.join(BASE_DIR, 'var/www'))

from flask import Flask, redirect, url_for
from blueprints.deanonymization import deanonymization

def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, 'var/www/templates'),
        static_folder=os.path.join(BASE_DIR, 'var/www/static')
    )
    app.config['SECRET_KEY'] = 'sih2026-blackpearl-deanonymization-secret'

    # Register stub endpoints for standard AIL nav_bar compatibility
    dummy_endpoints = [
        'dashboard.index', 'dashboard.objects_dashboard', 'PasteSubmit.PasteSubmit_page',
        'tags_ui.tags_search_items', 'hunters.trackers_dashboard',
        'crawler_splash.crawlers_dashboard', 'investigations_b.investigations_dashboard',
        'search_b.search_dashboard', 'settings_b.settings_page', 'root.logout'
    ]
    for ep in dummy_endpoints:
        def make_dummy(endpoint_name):
            def handler():
                return redirect(url_for('deanonymization.dashboard'))
            return handler
        app.add_url_rule(f'/{ep.replace(".", "/")}', endpoint=ep, view_func=make_dummy(ep))

    # Root redirect to De-anonymization Dashboard
    @app.route('/')
    def root_redirect():
        return redirect(url_for('deanonymization.dashboard'))

    # Register De-anonymization Blueprint
    app.register_blueprint(deanonymization)

    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7000))
    app = create_app()
    print("\n" + "=" * 70)
    print("  BLACK PEARL: Dark Web Threat Actor De-anonymization Platform")
    print("  SIH 2026 Problem Statement Implementation")
    print("=" * 70)
    print(f"  [+] Web UI Dashboard : http://127.0.0.1:{port}/deanonymization")
    print(f"  [+] Misconfig Scanner: http://127.0.0.1:{port}/deanonymization/misconfig")
    print(f"  [+] AI Stylometry    : http://127.0.0.1:{port}/deanonymization/stylometry")
    print(f"  [+] Activity Timeline: http://127.0.0.1:{port}/deanonymization/timeline")
    print(f"  [+] PDF/HTML Report  : http://127.0.0.1:{port}/deanonymization/export/report")
    print("=" * 70 + "\n")
    app.run(host='0.0.0.0', port=port, debug=True)
