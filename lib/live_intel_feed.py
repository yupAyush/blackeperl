#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Live Cyber Threat Intelligence Ingestion & Scraping Engine
=========================================================
Pulls real threat intelligence from live public feeds:
  1. SANS Internet Storm Center Threat API (Active Attacker IPs)
  2. Emerging Threats Compromised IP Blocklist (Active C2s)
  3. CISA Known Exploited Vulnerabilities Catalog (KEV JSON)
  4. The Hacker News Security Advisories (RSS/XML Feed)

Parses, extracts indicators, performs batch geolocation through GeoIPService,
and persists intelligence into SQLite for real-time map & telemetry streaming.
"""

import os
import sys
import re
import json
import time
import sqlite3
import datetime
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

sys.path.append(os.path.join(os.environ.get('AIL_BIN', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from lib.geoip_service import GeoIPService

DB_FILE_PATH = os.path.join(
    os.environ.get('AIL_HOME', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    'DATA_DEANONYMIZATION.db'
)

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BlackPearl-ThreatIntel/2.0"


class LiveIntelFeedEngine:
    """
    Scrapes and normalizes real-world threat feeds.
    Provides automated IOC extraction, geolocation correlation,
    and structured SQLite streaming storage.
    """

    def __init__(self, db_path: str = DB_FILE_PATH, geoip_service: Optional[GeoIPService] = None):
        self.db_path = db_path
        self.geoip = geoip_service or GeoIPService(db_path=db_path)
        self._init_tables()

    def _init_tables(self):
        """Create tables for storing ingested live indicators and advisories."""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS live_threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT,
                    value TEXT,
                    source TEXT,
                    malware_family TEXT,
                    threat_level TEXT,
                    lat REAL,
                    lon REAL,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    asn TEXT,
                    attacks_count INTEGER,
                    details_json TEXT,
                    discovered_at TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS live_intel_advisories (
                    advisory_id TEXT PRIMARY KEY,
                    source TEXT,
                    title TEXT,
                    cve_id TEXT,
                    severity TEXT,
                    summary TEXT,
                    url TEXT,
                    published_at TEXT,
                    ingested_at TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS feed_sync_audit (
                    sync_id TEXT PRIMARY KEY,
                    sources_queried TEXT,
                    indicators_added INTEGER,
                    advisories_added INTEGER,
                    synced_at TEXT,
                    status TEXT
                )
            """)
            conn.commit()

            # If empty, run initial baseline ingestion
            cur.execute("SELECT COUNT(*) FROM live_threat_indicators")
            count = cur.fetchone()[0]
            conn.close()

            if count == 0:
                print("[*] Initializing live threat feeds baseline...", file=sys.stderr)
                self.sync_all_feeds(max_ips=12)
        except Exception as e:
            print(f"[!] LiveIntelFeedEngine init error: {e}", file=sys.stderr)

    def fetch_sans_isc_threatlist(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch active attacking IPs from SANS Internet Storm Center API."""
        url = "https://isc.sans.edu/api/threatlist?json"
        extracted = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # SANS returns list of dicts with 'ipv4', 'attacks', 'count'
                items = data if isinstance(data, list) else data.get("threatlist", [])
                for item in items[:limit]:
                    ip = item.get("ipv4")
                    if ip:
                        extracted.append({
                            "ip": ip,
                            "attacks": int(item.get("attacks", 1)),
                            "count": int(item.get("count", 1)),
                            "source": "SANS ISC Threatlist",
                            "malware_family": "Automated Scanner / Brute-force",
                            "threat_level": "HIGH" if int(item.get("attacks", 1)) > 50 else "MEDIUM"
                        })
        except Exception as e:
            print(f"[!] SANS ISC threatlist fetch warning: {e}", file=sys.stderr)
        return extracted

    def fetch_emerging_threats_ips(self, limit: int = 12) -> List[Dict[str, Any]]:
        """Fetch active compromised C2 node IPs from Emerging Threats rule set."""
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        extracted = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=6) as resp:
                lines = resp.read().decode("utf-8", errors="ignore").splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#") and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                        extracted.append({
                            "ip": line,
                            "attacks": 100,
                            "count": 1,
                            "source": "Emerging Threats C2",
                            "malware_family": "Active Compromised Host / C2 Node",
                            "threat_level": "CRITICAL"
                        })
                        count += 1
                        if count >= limit:
                            break
        except Exception as e:
            print(f"[!] Emerging Threats fetch warning: {e}", file=sys.stderr)
        return extracted

    def fetch_cisa_kev_advisories(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch actively exploited vulnerabilities from CISA KEV JSON catalog."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        extracted = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulns = data.get("vulnerabilities", [])
                # Take the most recently added CVEs
                for v in sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:limit]:
                    cve = v.get("cveID", "CVE-UNKNOWN")
                    extracted.append({
                        "advisory_id": f"CISA-{cve}",
                        "source": "CISA KEV Catalog",
                        "title": f"{cve}: {v.get('vendorProject', 'Vendor')} {v.get('product', '')} Vulnerability",
                        "cve_id": cve,
                        "severity": "CRITICAL",
                        "summary": v.get("shortDescription", ""),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                        "published_at": v.get("dateAdded", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"))
                    })
        except Exception as e:
            print(f"[!] CISA KEV catalog fetch warning: {e}", file=sys.stderr)
        return extracted

    def fetch_the_hackers_news_rss(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Parse breaking cybersecurity intelligence from The Hacker News RSS feed."""
        url = "https://feeds.feedburner.com/TheHackersNews"
        extracted = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=6) as resp:
                xml_data = resp.read()
                root = ET.fromstring(xml_data)

                # Find channel items
                channel = root.find("channel")
                items = channel.findall("item") if channel is not None else root.findall(".//item")

                for item in items[:limit]:
                    title_elem = item.find("title")
                    link_elem = item.find("link")
                    desc_elem = item.find("description")
                    pub_elem = item.find("pubDate")

                    title = title_elem.text if title_elem is not None else "Breaking Intelligence Alert"
                    link = link_elem.text if link_elem is not None else "https://thehackernews.com"
                    desc = desc_elem.text if desc_elem is not None else ""
                    # Clean HTML tags in description
                    desc_clean = re.sub(r"<[^>]+>", "", desc).strip()
                    if len(desc_clean) > 220:
                        desc_clean = desc_clean[:220] + "..."

                    # Extract CVE if mentioned
                    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", title + " " + desc)
                    cve = cve_match.group(0) if cve_match else "INTEL-ADVISORY"

                    severity = "CRITICAL" if any(w in title.lower() for w in ["zero-day", "ransomware", "breach", "critical", "apt"]) else "HIGH"

                    advisory_id = f"THN-{abs(hash(title)) % 1000000:06d}"
                    extracted.append({
                        "advisory_id": advisory_id,
                        "source": "The Hacker News Feed",
                        "title": title,
                        "cve_id": cve,
                        "severity": severity,
                        "summary": desc_clean,
                        "url": link,
                        "published_at": pub_elem.text[:25] if pub_elem is not None and pub_elem.text else datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
                    })
        except Exception as e:
            print(f"[!] The Hacker News RSS fetch warning: {e}", file=sys.stderr)
        return extracted

    def sync_all_feeds(self, max_ips: int = 15) -> Dict[str, Any]:
        """
        Pull fresh intelligence from all live feeds, geolocate newly extracted IPs,
        and update SQLite tables. Returns summary counts.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        all_ip_items = []
        all_advisories = []

        # 1. Fetch IP threat feeds
        sans_items = self.fetch_sans_isc_threatlist(limit=max_ips // 2 + 2)
        et_items = self.fetch_emerging_threats_ips(limit=max_ips // 2 + 2)
        all_ip_items.extend(sans_items)
        all_ip_items.extend(et_items)

        # 2. Fetch threat advisories
        cisa_adv = self.fetch_cisa_kev_advisories(limit=10)
        thn_adv = self.fetch_the_hackers_news_rss(limit=10)
        all_advisories.extend(cisa_adv)
        all_advisories.extend(thn_adv)

        # 3. Batch geolocate the unique IPs
        unique_ips = list({item["ip"] for item in all_ip_items if item.get("ip")})
        geo_map = self.geoip.batch_resolve(unique_ips)

        # 4. Save indicators to database
        indicators_saved = 0
        advisories_saved = 0

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        for item in all_ip_items:
            ip = item["ip"]
            geo = geo_map.get(ip, {})
            ind_id = f"IOC-{ip.replace('.', '-')}"
            try:
                cur.execute("""
                    INSERT OR REPLACE INTO live_threat_indicators
                    (indicator_id, indicator_type, value, source, malware_family, threat_level, lat, lon, country, city, isp, asn, attacks_count, details_json, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ind_id, "ip", ip, item.get("source", "Live Threat Feed"),
                    item.get("malware_family", "Generic Scanner"),
                    item.get("threat_level", "HIGH"),
                    float(geo.get("lat", 0.0)),
                    float(geo.get("lon", 0.0)),
                    geo.get("country", "Unknown"),
                    geo.get("city", "Unknown"),
                    geo.get("isp", "N/A"),
                    geo.get("asn", "N/A"),
                    int(item.get("attacks", 1)),
                    json.dumps(item),
                    now
                ))
                indicators_saved += 1
            except Exception as e:
                print(f"[!] Error saving indicator {ip}: {e}", file=sys.stderr)

        for adv in all_advisories:
            try:
                cur.execute("""
                    INSERT OR REPLACE INTO live_intel_advisories
                    (advisory_id, source, title, cve_id, severity, summary, url, published_at, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    adv["advisory_id"], adv["source"], adv["title"], adv["cve_id"],
                    adv["severity"], adv["summary"], adv["url"], adv["published_at"], now
                ))
                advisories_saved += 1
            except Exception as e:
                print(f"[!] Error saving advisory {adv.get('advisory_id')}: {e}", file=sys.stderr)

        # Record sync audit
        sync_id = f"SYNC-{int(time.time())}"
        cur.execute("""
            INSERT INTO feed_sync_audit
            (sync_id, sources_queried, indicators_added, advisories_added, synced_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            sync_id,
            "SANS ISC; Emerging Threats; CISA KEV; The Hacker News",
            indicators_saved,
            advisories_saved,
            now,
            "SUCCESS"
        ))

        conn.commit()
        conn.close()

        return {
            "success": True,
            "sync_id": sync_id,
            "timestamp": now,
            "indicators_synced": indicators_saved,
            "advisories_synced": advisories_saved,
            "total_threat_ips": len(unique_ips)
        }

    def get_live_indicators(self, limit: int = 50, threat_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve latest threat indicators with geolocation for Mapbox plotting."""
        indicators = []
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            if threat_level and threat_level.upper() != "ALL":
                cur.execute("""
                    SELECT indicator_id, indicator_type, value, source, malware_family, threat_level,
                           lat, lon, country, city, isp, asn, attacks_count, discovered_at
                    FROM live_threat_indicators
                    WHERE threat_level = ?
                    ORDER BY discovered_at DESC LIMIT ?
                """, (threat_level.upper(), limit))
            else:
                cur.execute("""
                    SELECT indicator_id, indicator_type, value, source, malware_family, threat_level,
                           lat, lon, country, city, isp, asn, attacks_count, discovered_at
                    FROM live_threat_indicators
                    ORDER BY discovered_at DESC LIMIT ?
                """, (limit,))

            rows = cur.fetchall()
            conn.close()
            for r in rows:
                indicators.append({
                    "indicator_id": r[0],
                    "type": r[1],
                    "ip": r[2],
                    "source": r[3],
                    "malware_family": r[4],
                    "threat_level": r[5],
                    "lat": float(r[6]),
                    "lon": float(r[7]),
                    "country": r[8],
                    "city": r[9],
                    "isp": r[10],
                    "asn": r[11],
                    "attacks_count": r[12],
                    "discovered_at": r[13],
                    "weight": 0.85 if r[5] == "CRITICAL" else 0.55
                })
        except Exception as e:
            print(f"[!] Error reading indicators: {e}", file=sys.stderr)
        return indicators

    def get_live_advisories(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Retrieve recent security advisories from CISA KEV and threat feeds."""
        advisories = []
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                SELECT advisory_id, source, title, cve_id, severity, summary, url, published_at
                FROM live_intel_advisories
                ORDER BY ingested_at DESC LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            conn.close()
            for r in rows:
                advisories.append({
                    "advisory_id": r[0],
                    "source": r[1],
                    "title": r[2],
                    "cve_id": r[3],
                    "severity": r[4],
                    "summary": r[5],
                    "url": r[6],
                    "published_at": r[7]
                })
        except Exception as e:
            print(f"[!] Error reading advisories: {e}", file=sys.stderr)
        return advisories

    def get_feed_stats(self) -> Dict[str, Any]:
        """Return high-level metrics on live threat intelligence ingestion."""
        stats = {
            "total_indicators": 0,
            "total_advisories": 0,
            "critical_indicators": 0,
            "last_synced": "Never"
        }
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM live_threat_indicators")
            stats["total_indicators"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM live_intel_advisories")
            stats["total_advisories"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM live_threat_indicators WHERE threat_level = 'CRITICAL'")
            stats["critical_indicators"] = cur.fetchone()[0]

            cur.execute("SELECT synced_at FROM feed_sync_audit ORDER BY synced_at DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                stats["last_synced"] = row[0]
            conn.close()
        except Exception as e:
            print(f"[!] Error reading stats: {e}", file=sys.stderr)
        return stats


if __name__ == "__main__":
    engine = LiveIntelFeedEngine()
    print("Syncing live feeds...")
    res = engine.sync_all_feeds(max_ips=8)
    print("Sync response:", json.dumps(res, indent=2))
    print("Live indicators sample:", len(engine.get_live_indicators(10)))
    print("Live advisories sample:", len(engine.get_live_advisories(5)))
