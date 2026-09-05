#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Blueprint Flask: Dark Web Threat Actor De-anonymization Suite
============================================================
Handles routes for executive dashboard, threat actor profiling,
interactive relationship graphs, live Tor misconfiguration audits,
AI stylometry analysis, timeline queries, and PDF/CSV/JSON reporting.
"""

import os
import sys
import io
import csv
import json
import datetime
from flask import Blueprint, render_template, request, jsonify, Response, redirect, url_for, make_response
from flask_login import login_required

sys.path.append(os.environ.get('AIL_BIN', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) + '/bin'))

from lib.threat_actor_engine import ThreatActorEngine
from lib.tor_origin_attribution import TorMisconfigScanner
from lib.ai_stylometry_engine import AIStylometryEngine
from lib.geoip_service import GeoIPService
from lib.live_intel_feed import LiveIntelFeedEngine

deanonymization = Blueprint(
    'deanonymization',
    __name__,
    template_folder=os.path.join(os.environ.get('AIL_FLASK', os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'templates/deanonymization')
)

engine = ThreatActorEngine()
scanner = TorMisconfigScanner()
stylometry = AIStylometryEngine()
geoip = GeoIPService()
feed_engine = LiveIntelFeedEngine(geoip_service=geoip)

# Demo target alias used by the UI "Demo Target" button
DEMO_ONION = "darkspectrelk7v43.onion"

# Keywords that trigger synthetic demo samples instead of live probing
_DEMO_KEYWORDS = ("sample", "darkspectre", "demo", "showcase", "test")


def _is_demo_target(onion_url: str) -> bool:
    """Return True if the target string matches any known demo keyword."""
    lower = onion_url.lower()
    return any(kw in lower for kw in _DEMO_KEYWORDS)


def _build_demo_samples() -> dict:
    """
    Rich synthetic Apache status / TLS / favicon payload used for offline demos.
    Mirrors a realistic misconfigured darknet marketplace backend.
    """
    return {
        "/server-status": """
            <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
            <html><head><title>Apache Status</title></head><body>
            <h1>Apache Server Status for srv-darkmarket.clearnet-host.com (via 185.220.101.45)</h1>
            <dl>
              <dt>Server Version: Apache/2.4.41 (Ubuntu)</dt>
              <dt>Server MPM: event</dt>
              <dt>Server uptime: 18 days 4 hours 12 minutes</dt>
              <dt>Total accesses: 489201 - Total Traffic: 1.8 GB</dt>
              <dt>CPU Usage: u1.2 s.8 cu0 cs0 - .0128% CPU load</dt>
            </dl>
            <table border="0">
              <tr><th>VHost</th><th>Client</th><th>Request</th></tr>
              <tr><td>srv-darkmarket.clearnet-host.com:80</td><td>185.220.101.45</td><td>GET /api/v1/listings HTTP/1.1</td></tr>
              <tr><td>darkspectrelk7v43.onion:80</td><td>127.0.0.1</td><td>POST /order/submit HTTP/1.1</td></tr>
            </table></body></html>
        """,
        "tls_cert": {
            "valid": True,
            "common_name": "srv-darkmarket.clearnet-host.com",
            "sans": ["srv-darkmarket.clearnet-host.com", "api.darkmarket-host.com", "darkspectrelk7v43.onion"],
            "serial_number": "04:a1:b2:c3:d4:e5:f6:01:23:45:67:89:ab:cd:ef",
            "fingerprint_sha256": "4a71b899e120f812bb449011aa8877223344556677889900aabbccddeeff0011",
            "issuer": "Let's Encrypt Authority X3",
            "has_clearnet_domain": True,
        },
        "favicon_bytes": b"SAMPLE_FAVICON_DARKNET_PAYLOAD_BYTES",
    }


# ===================== DASHBOARD =====================

@deanonymization.route('/deanonymization', methods=['GET'])
@deanonymization.route('/deanonymization/dashboard', methods=['GET'])
def dashboard():
    """Executive De-anonymization Overview & Tactical Command Dashboard."""
    category_filter = request.args.get('category')
    risk_filter = request.args.get('risk')

    actors = engine.get_all_actors(category_filter=category_filter, risk_filter=risk_filter)
    audits = engine.get_all_scan_audits(limit=10)

    # Compute high-level statistics
    total_actors = len(actors)
    total_unmasked_services = sum(len(a.get_associated_infrastructure()) for a in actors)
    avg_confidence = round(sum(a.get_attribution_confidence() for a in actors) / max(total_actors, 1), 1)
    critical_actors = sum(1 for a in actors if a.get_risk_level() == 'CRITICAL')

    # Fetch live threat feed statistics & sample items
    feed_stats = feed_engine.get_feed_stats()
    live_indicators = feed_engine.get_live_indicators(limit=15)
    live_advisories = feed_engine.get_live_advisories(limit=12)

    # Gather unmasked origin IPs for mapping
    origin_geo_points = []
    for a in actors:
        for infra in a.get_associated_infrastructure():
            ip = infra.get('origin_ip')
            if ip:
                geo_info = geoip.lookup(ip)
                origin_geo_points.append({
                    "ip": ip,
                    "hostname": infra.get("clearnet_hostname", "N/A"),
                    "location": infra.get("location", f"{geo_info.get('city')}, {geo_info.get('country')}"),
                    "isp": infra.get("isp", geo_info.get("isp", "N/A")),
                    "actor": a.get_primary_alias(),
                    "actor_id": a.actor_id,
                    "onion": infra.get("onion_domain"),
                    "lat": geo_info.get("lat", 52.6171),
                    "lon": geo_info.get("lon", 13.1207),
                    "confidence": a.get_attribution_confidence(),
                    "risk": a.get_risk_level(),
                    "unmasking_method": infra.get("unmasking_method", "Multi-vector Tor audit")
                })

    return render_template(
        'deanonymization/dashboard.html',
        actors=actors,
        audits=audits,
        total_actors=total_actors,
        total_unmasked_services=total_unmasked_services,
        avg_confidence=avg_confidence,
        critical_actors=critical_actors,
        origin_geo_points=origin_geo_points,
        feed_stats=feed_stats,
        live_indicators=live_indicators,
        live_advisories=live_advisories,
        selected_category=category_filter,
        selected_risk=risk_filter
    )


# ===================== GEOSPATIAL & FEED APIS =====================

@deanonymization.route('/deanonymization/api/geo/points', methods=['GET'])
def api_geo_points():
    """
    Returns aggregated geospatial points for Mapbox GL JS rendering and heatmap overlays.
    Includes unmasked threat actor origins, live malicious C2 nodes, and recent audit targets.
    """
    points = []
    actors = engine.get_all_actors()

    # 1. Unmasked actor infrastructure nodes (High/Critical priority)
    for a in actors:
        for infra in a.get_associated_infrastructure():
            ip = infra.get('origin_ip')
            if ip:
                geo = geoip.lookup(ip)
                points.append({
                    "id": f"ACTOR-ORIGIN-{ip}",
                    "type": "actor_origin",
                    "ip": ip,
                    "title": f"Target: {a.get_primary_alias()}",
                    "subtitle": infra.get("onion_domain", "Tor Service"),
                    "hostname": infra.get("clearnet_hostname", "N/A"),
                    "actor_id": a.actor_id,
                    "actor_alias": a.get_primary_alias(),
                    "risk_level": a.get_risk_level(),
                    "confidence": a.get_attribution_confidence(),
                    "unmasking_method": infra.get("unmasking_method", "Tor Status Leak"),
                    "isp": infra.get("isp", geo.get("isp", "N/A")),
                    "asn": infra.get("asn", geo.get("asn", "N/A")),
                    "location": infra.get("location", f"{geo.get('city')}, {geo.get('country')}"),
                    "lat": float(geo.get("lat", 0.0)),
                    "lon": float(geo.get("lon", 0.0)),
                    "weight": 1.0 if a.get_risk_level() == 'CRITICAL' else 0.8
                })

    # 2. Live threat feed indicators (C2 bots, scanners)
    live_inds = feed_engine.get_live_indicators(limit=40)
    for ind in live_inds:
        lat = ind.get("lat", 0.0)
        lon = ind.get("lon", 0.0)
        if lat != 0.0 and lon != 0.0:
            points.append({
                "id": ind.get("indicator_id"),
                "type": "live_c2",
                "ip": ind.get("ip"),
                "title": f"Active C2: {ind.get('ip')}",
                "subtitle": ind.get("source"),
                "actor_id": "",
                "actor_alias": ind.get("malware_family", "Malicious Node"),
                "risk_level": ind.get("threat_level", "HIGH"),
                "confidence": 88.0 if ind.get("threat_level") == "CRITICAL" else 72.0,
                "unmasking_method": f"{ind.get('source')} Ingestion",
                "isp": ind.get("isp", "Unknown ISP"),
                "asn": ind.get("asn", "N/A"),
                "location": f"{ind.get('city', 'Unknown')}, {ind.get('country', 'Unknown')}",
                "lat": lat,
                "lon": lon,
                "weight": ind.get("weight", 0.6)
            })

    # 3. Unmasked Tor audit origins
    audits = engine.get_all_scan_audits(limit=15)
    for aud in audits:
        if aud.get("unmasked") and aud.get("origin_ip"):
            ip = aud.get("origin_ip")
            geo = geoip.lookup(ip)
            points.append({
                "id": f"AUDIT-{aud.get('scan_id')}",
                "type": "audit_origin",
                "ip": ip,
                "title": f"Audit: {aud.get('onion_target')}",
                "subtitle": "Unmasked via Tor Auditor",
                "actor_id": "",
                "actor_alias": aud.get("domain", "Hidden Service"),
                "risk_level": "CRITICAL",
                "confidence": aud.get("attribution_confidence", 90.0),
                "unmasking_method": "Live Misconfig Audit",
                "isp": geo.get("isp", "N/A"),
                "asn": geo.get("asn", "N/A"),
                "location": aud.get("location") or f"{geo.get('city')}, {geo.get('country')}",
                "lat": float(geo.get("lat", 0.0)),
                "lon": float(geo.get("lon", 0.0)),
                "weight": 0.95
            })

    return jsonify({
        "status": "success",
        "total_points": len(points),
        "features": points
    })


@deanonymization.route('/deanonymization/api/geo/lookup', methods=['POST', 'GET'])
def api_geo_lookup():
    """
    Real-time on-demand IP / Domain Geolocation & DNS Resolution API.
    Accepts an IP or hostname and returns complete geographic and network coordinates.
    """
    target = ""
    if request.method == 'POST':
        if request.is_json:
            target = request.json.get('target', '')
        else:
            target = request.form.get('target', '')
    else:
        target = request.args.get('target', '')

    if not target:
        return jsonify({"success": False, "error": "Target parameter is required."}), 400

    result = geoip.lookup(target)
    return jsonify(result)


@deanonymization.route('/deanonymization/api/feeds/sync', methods=['POST'])
def api_feeds_sync():
    """
    Trigger live threat intelligence feed synchronization.
    Fetches SANS ISC, Emerging Threats, CISA KEV, and The Hacker News.
    """
    max_ips = int(request.args.get('max_ips', 15))
    sync_result = feed_engine.sync_all_feeds(max_ips=max_ips)
    stats = feed_engine.get_feed_stats()
    sync_result["stats"] = stats
    return jsonify(sync_result)


@deanonymization.route('/deanonymization/api/feeds/live', methods=['GET'])
def api_feeds_live():
    """
    Returns latest live threat indicators and advisories for dynamic dashboard streaming.
    """
    threat_level = request.args.get('threat_level')
    limit = int(request.args.get('limit', 20))
    indicators = feed_engine.get_live_indicators(limit=limit, threat_level=threat_level)
    advisories = feed_engine.get_live_advisories(limit=limit)
    stats = feed_engine.get_feed_stats()

    return jsonify({
        "status": "success",
        "indicators": indicators,
        "advisories": advisories,
        "stats": stats
    })


@deanonymization.route('/deanonymization/api/quick_scan', methods=['POST'])
def api_quick_scan():
    """
    Rapid inline Tor Hidden Service Misconfiguration Auditor API.
    Audits .onion target without page reload and returns structured unmasking findings.
    Supports live Tor SOCKS, Tor2Web gateway fallback, and demo/synthetic mode.
    """
    onion_url = ""
    if request.is_json:
        onion_url = request.json.get('onion_url', '')
    else:
        onion_url = request.form.get('onion_url', '')

    if not onion_url:
        return jsonify({"success": False, "error": "Target .onion URL is required."}), 400

    custom_samples = _build_demo_samples() if _is_demo_target(onion_url) else None

    audit_result = scanner.scan_misconfigurations(onion_url, custom_html_samples=custom_samples)
    engine.save_scan_audit(audit_result)
    # Promote an unmasked service into a tracked actor (dashboard/map/timeline)
    actor_id = engine.upsert_actor_from_audit(audit_result)

    # If unmasked, geolocate the origin IP
    origin = audit_result.get("origin_attribution", {})
    if origin.get("unmasked") and origin.get("primary_origin", {}).get("origin_ip"):
        geo = geoip.lookup(origin["primary_origin"]["origin_ip"])
        audit_result["geo"] = geo

    return jsonify({
        "success": True,
        "scrape_mode": audit_result.get("scrape_mode", "unknown"),
        "gateways_used": audit_result.get("gateways_used", []),
        "actor_id": actor_id,
        "audit": audit_result
    })


@deanonymization.route('/deanonymization/api/demo_scan', methods=['GET', 'POST'])
def api_demo_scan():
    """
    Returns a pre-built demo scan result for DarkSpectre marketplace.
    Used by the UI Demo button — no live network requests needed.
    """
    audit_result = scanner.scan_misconfigurations(DEMO_ONION, custom_html_samples=_build_demo_samples())
    engine.save_scan_audit(audit_result)
    origin = audit_result.get("origin_attribution", {})
    if origin.get("unmasked") and origin.get("primary_origin", {}).get("origin_ip"):
        geo = geoip.lookup(origin["primary_origin"]["origin_ip"])
        audit_result["geo"] = geo
    return jsonify({
        "success": True,
        "scrape_mode": "demo",
        "demo": True,
        "audit": audit_result
    })


# ===================== THREAT ACTORS =====================

@deanonymization.route('/deanonymization/actor/<actor_id>', methods=['GET'])
def actor_profile(actor_id):
    """Detailed Threat Actor Dossier."""
    actor = engine.get_actor_by_id(actor_id)
    if not actor:
        return render_template('deanonymization/actor_profile.html', error=f"Actor {actor_id} not found.", actor=None)

    data = actor.to_dict()
    # Generate diurnal profile for this actor
    sample_timestamps = [
        "2026-08-20 11:20:00", "2026-08-21 13:45:00", "2026-08-22 15:10:00",
        "2026-08-23 17:30:00", "2026-08-24 12:00:00", "2026-08-25 14:15:00",
        "2026-08-26 16:50:00", "2026-08-27 18:20:00", "2026-08-28 13:10:00"
    ]
    diurnal_profile = stylometry.generate_diurnal_timezone_profile(sample_timestamps)

    return render_template('deanonymization/actor_profile.html', actor=data, diurnal_profile=diurnal_profile)


# ===================== RELATIONSHIP GRAPH =====================

@deanonymization.route('/deanonymization/graph/<actor_id>', methods=['GET'])
def relationship_graph(actor_id):
    """Interactive ECharts/Cytoscape Relationship Graph view."""
    actor = engine.get_actor_by_id(actor_id)
    graph_data = engine.build_actor_relationship_graph(actor_id)
    actors = engine.get_all_actors()

    return render_template(
        'deanonymization/relationship_graph.html',
        actor=actor.to_dict() if actor else None,
        graph_data=graph_data,
        all_actors=actors,
        selected_actor_id=actor_id
    )


@deanonymization.route('/deanonymization/api/graph/<actor_id>', methods=['GET'])
def api_graph_data(actor_id):
    """JSON API endpoint for dynamic graph data fetching."""
    graph_data = engine.build_actor_relationship_graph(actor_id)
    return jsonify(graph_data)


# ===================== LIVE MISCONFIG SCANNER =====================

@deanonymization.route('/deanonymization/misconfig', methods=['GET', 'POST'])
def misconfig_scanner_page():
    """Interactive Tor Hidden Service Misconfiguration Auditor."""
    audit_result = None
    target_url = request.form.get('onion_url') or request.args.get('target', '')

    if request.method == 'POST' and target_url:
        # Demo/sample mode: inject synthetic rich payload
        custom_samples = _build_demo_samples() if _is_demo_target(target_url) else None

        audit_result = scanner.scan_misconfigurations(target_url, custom_html_samples=custom_samples)
        engine.save_scan_audit(audit_result)
        # Promote an unmasked service into a tracked actor (dashboard/map/timeline)
        engine.upsert_actor_from_audit(audit_result)

    recent_audits = engine.get_all_scan_audits(limit=15)
    return render_template('deanonymization/misconfig_scanner.html', audit_result=audit_result, target_url=target_url, recent_audits=recent_audits)


# ===================== AI STYLOMETRY WORKBENCH =====================

@deanonymization.route('/deanonymization/stylometry', methods=['GET', 'POST'])
def stylometry_page():
    """AI Stylometry Analysis & Rebranded Persona Matcher."""
    comparison_result = None
    text_a = request.form.get('text_a', '')
    text_b = request.form.get('text_b', '')
    suspect_handle = request.form.get('suspect_handle', 'PhantomCipher')

    if request.method == 'POST':
        if text_a and text_b:
            wp_a = stylometry.extract_writeprint(text_a)
            wp_b = stylometry.extract_writeprint(text_b)
            sim = stylometry.compute_stylometric_similarity(wp_a, wp_b)
            diurnal = stylometry.generate_diurnal_timezone_profile([])
            comparison_result = {
                "handle": suspect_handle,
                "writeprint_a": wp_a,
                "writeprint_b": wp_b,
                "similarity": sim,
                "diurnal_profile": diurnal
            }
        elif text_a and suspect_handle:
            # Match against known threat actor profiles
            comparison_result = stylometry.match_rebranded_persona(suspect_handle, text_a)

    # Pre-fill sample texts for easy demonstration if empty
    sample_text_known = """We are offering high quality database leaks and enterprise corporate access. Proof of funds required... escrow accepted via Dread trusted escrow. Do not message without PGP encryption!! Validated corporate SQL dumps available now."""
    sample_text_suspect = """Offering high quality corporate SQL dumps and internal access. Proof of funds required before sample release... trusted escrow accepted on forum!! All communication must be encrypted with PGP."""

    return render_template(
        'deanonymization/stylometry.html',
        comparison_result=comparison_result,
        text_a=text_a or sample_text_known,
        text_b=text_b or sample_text_suspect,
        suspect_handle=suspect_handle
    )


# ===================== TIMELINE EXPLORER =====================

@deanonymization.route('/deanonymization/timeline', methods=['GET'])
def timeline_page():
    """Chronological Activity & Footprint Inspector."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    events = engine.get_timeline_events(start_date=start_date, end_date=end_date)
    return render_template('deanonymization/timeline.html', events=events, start_date=start_date, end_date=end_date)


# ===================== MULTI-FORMAT EXPORTS =====================

@deanonymization.route('/deanonymization/export/csv', methods=['GET'])
def export_csv():
    """Export threat actor intelligence table to CSV format."""
    actors = engine.get_all_actors()
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Actor ID", "Primary Alias", "Category", "Risk Level", "Status",
        "Attribution Confidence (%)", "First Seen", "Last Seen",
        "Associated Aliases", "PGP Key IDs", "Crypto Wallets",
        "Unmasked Clearnet Origin IPs", "Location / ISP"
    ])

    for a in actors:
        d = a.to_dict()
        aliases_str = "; ".join([f"{al['handle']} ({al['platform']})" for al in d.get("aliases", [])])
        pgp_str = "; ".join([p.get("key_id", "") for p in d.get("pgp_keys", [])])
        wallets_str = "; ".join([f"{w['currency']}: {w['address']}" for w in d.get("crypto_wallets", [])])
        origin_ips = "; ".join([infra.get("origin_ip", "") for infra in d.get("associated_infrastructure", []) if infra.get("origin_ip")])
        locations = "; ".join([f"{infra.get('origin_ip')}: {infra.get('location')} ({infra.get('isp')})" for infra in d.get("associated_infrastructure", []) if infra.get("origin_ip")])

        writer.writerow([
            d["actor_id"], d["primary_alias"], d["category"], d["risk_level"], d["status"],
            d["attribution_confidence"], d["first_seen"], d["last_seen"],
            aliases_str, pgp_str, wallets_str, origin_ips, locations
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=darkweb_threat_actor_intelligence.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


@deanonymization.route('/deanonymization/export/json', methods=['GET'])
def export_json():
    """Export complete threat intelligence dataset in structured JSON format."""
    actor_id = request.args.get('actor_id')
    if actor_id:
        actor = engine.get_actor_by_id(actor_id)
        data = actor.to_dict() if actor else {}
        filename = f"threat_actor_{actor_id}.json"
    else:
        actors = [a.to_dict() for a in engine.get_all_actors()]
        audits = engine.get_all_scan_audits(limit=50)
        data = {
            "metadata": {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "framework": "Black Pearl De-anonymization Platform",
                "classification": "LAW ENFORCEMENT SENSITIVE / TLP:AMBER",
                "total_actors": len(actors),
                "total_audits": len(audits)
            },
            "threat_actors": actors,
            "tor_misconfiguration_audits": audits
        }
        filename = "darkweb_threat_intelligence_dossier.json"

    response = make_response(json.dumps(data, indent=2))
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "application/json"
    return response


@deanonymization.route('/deanonymization/export/report', methods=['GET'])
def export_report():
    """Generate printable Law Enforcement Intelligence Report."""
    actor_id = request.args.get('actor_id', 'ACTOR-001-DARKSPECTRE')
    actor = engine.get_actor_by_id(actor_id)
    if not actor:
        actor = engine.get_all_actors()[0]

    data = actor.to_dict()
    graph_data = engine.build_actor_relationship_graph(data["actor_id"])
    diurnal = stylometry.generate_diurnal_timezone_profile([])

    return render_template(
        'deanonymization/report_template.html',
        actor=data,
        graph_data=graph_data,
        diurnal=diurnal,
        now=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
