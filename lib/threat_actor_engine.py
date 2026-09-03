#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Threat Actor Management & Cross-Marketplace Relationship Graph Engine
====================================================================
Maintains unified threat actor dossiers, maps relationships across darknet markets,
and builds interactive graph network structures for visual pivoting and timeline analysis.
"""

import os
import sys
import json
import sqlite3
import datetime
from typing import Dict, List, Any, Optional

sys.path.append(os.path.join(os.environ.get('AIL_BIN', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from lib.objects.ThreatActors import ThreatActor

DB_FILE_PATH = os.path.join(
    os.environ.get('AIL_HOME', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    'DATA_DEANONYMIZATION.db'
)

# Realistic pre-populated darknet threat actor profiles for SIH 2026 demonstration and investigation
INITIAL_THREAT_ACTORS = [
    {
        "actor_id": "ACTOR-001-DARKSPECTRE",
        "primary_alias": "DarkSpectre",
        "category": "Ransomware Operator & Data Broker",
        "risk_level": "CRITICAL",
        "status": "Active",
        "attribution_confidence": 94.5,
        "first_seen": "2023-04-12",
        "last_seen": "2026-08-28",
        "summary": "High-profile dark web broker specializing in compromised corporate credentials, healthcare exfiltrations, and ransomware affiliate operations. Active across Dread, BreachForums, and Exploit. Operates custom leak sites on Tor.",
        "tags": ["ransomware", "data-broker", "breach-forums", "dread", "high-value-target"],
        "aliases": [
            {"handle": "DarkSpectre", "platform": "Dread Forum", "url": "http://dread4u...onion/u/DarkSpectre", "first_seen": "2023-04-12", "reputation_rep": "+350"},
            {"handle": "Spectre_Ops", "platform": "BreachForums", "url": "https://breachforums.../user/Spectre_Ops", "first_seen": "2023-09-01", "reputation_rep": "God Tier"},
            {"handle": "GhostVendor_EU", "platform": "Archetyp Market", "url": "http://archetyp...onion/vendor/GhostVendor_EU", "first_seen": "2024-01-15", "reputation_rep": "Level 6 Vendor"},
            {"handle": "Vortex_Security", "platform": "Exploit.in", "url": "https://exploit.in/user/Vortex_Security", "first_seen": "2025-06-10", "reputation_rep": "Trusted Member"}
        ],
        "pgp_keys": [
            {
                "key_id": "0x4A72B91DF38D92B1",
                "fingerprint": "8F31 4A72 B91D F38D 92B1 C044 118A 5590 E312 99AA",
                "uid_email": "spectre_ops@onionmail.org",
                "created_date": "2023-04-10",
                "bit_length": 4096,
                "algorithm": "RSA"
            }
        ],
        "crypto_wallets": [
            {
                "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                "currency": "Bitcoin (BTC)",
                "first_seen": "2023-04-15",
                "last_seen": "2026-08-25",
                "total_received_btc": 42.85,
                "total_received_usd": 2785000.0,
                "tx_count": 184
            },
            {
                "address": "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkFxbTNsFoBkEhyzaQH6y9Br2NqPekMQm8CgU3WeN5PegYSW7zkFFasb54",
                "currency": "Monero (XMR)",
                "first_seen": "2024-02-10",
                "last_seen": "2026-08-27",
                "total_received_usd": 650000.0,
                "tx_count": 92
            },
            {
                "address": "0x8466b50B53c521d0B4B163d186596F94fB8466f1",
                "currency": "Ethereum (ETH)",
                "first_seen": "2024-05-18",
                "last_seen": "2026-07-30",
                "total_received_usd": 310000.0,
                "tx_count": 48
            }
        ],
        "communication_channels": [
            {"type": "Telegram", "handle": "@Spectre_Leaked_Feed", "verified": True},
            {"type": "Jabber / XMPP", "handle": "spectre_ops@exploit.im", "verified": True},
            {"type": "Tox ID", "handle": "76A123BC88D4E190223A4590BC771239845EFA98341029384756102938475610293847", "verified": False}
        ],
        "marketplaces": [
            {"marketplace": "Archetyp Market", "vendor_name": "GhostVendor_EU", "rating": 4.98, "reviews_count": 1420, "positive_percent": 99.4, "escrow_trust_score": 98},
            {"marketplace": "Bohemia Marketplace", "vendor_name": "DarkSpectre_HQ", "rating": 4.92, "reviews_count": 890, "positive_percent": 98.1, "escrow_trust_score": 94}
        ],
        "associated_infrastructure": [
            {
                "onion_domain": "darkspectrelk7v43.onion",
                "service_type": "Ransomware Data Leak Portal",
                "origin_ip": "185.220.101.45",
                "clearnet_hostname": "srv-darkmarket.clearnet-host.com",
                "location": "Frankfurt, Germany",
                "isp": "Hetzner Online GmbH",
                "asn": "AS24940",
                "unmasking_method": "Apache /server-status leak + Favicon Murmur3 match"
            },
            {
                "onion_domain": "spectrepayescrow9.onion",
                "service_type": "Automated Crypto Payment Gateway",
                "origin_ip": "194.26.29.112",
                "clearnet_hostname": "vps-ransomware-c2.offshore.is",
                "location": "Reykjavik, Iceland",
                "isp": "FlokiNET ehf",
                "asn": "AS200651",
                "unmasking_method": "SSL Certificate Serial Match in Censys Index"
            }
        ]
    },
    {
        "actor_id": "ACTOR-002-CRYPTOSHADOW",
        "primary_alias": "CryptoShadow",
        "category": "Carding & Financial Money Laundering",
        "risk_level": "HIGH",
        "status": "Active",
        "attribution_confidence": 88.0,
        "first_seen": "2023-11-20",
        "last_seen": "2026-08-20",
        "summary": "Specializes in high-volume dumps of stolen credit cards, cloned bank accounts, and automated crypto mixer services. Known for laundering proceeds across multiple blockchain hops.",
        "tags": ["carding", "money-laundering", "crypto-mixer", "financial-crime"],
        "aliases": [
            {"handle": "CryptoShadow", "platform": "Club2CRD", "url": "https://club2crd.../user/CryptoShadow", "first_seen": "2023-11-20", "reputation_rep": "Verified Seller"},
            {"handle": "ShadowMixer_Pro", "platform": "Dread Forum", "url": "http://dread4u...onion/u/ShadowMixer_Pro", "first_seen": "2024-03-01", "reputation_rep": "+180"},
            {"handle": "DumpKing_Global", "platform": "Brian's Club Mirror", "url": "http://bclub...onion/v/DumpKing", "first_seen": "2024-07-15", "reputation_rep": "Top 10 Vendor"}
        ],
        "pgp_keys": [
            {
                "key_id": "0x98BE23114400FA12",
                "fingerprint": "11A4 98BE 2311 4400 FA12 9901 BB44 5511 8822 3344",
                "uid_email": "cryptoshadow@secmail.pro",
                "created_date": "2023-11-18",
                "bit_length": 4096,
                "algorithm": "RSA"
            }
        ],
        "crypto_wallets": [
            {
                "address": "1NbEPRwbBZrFDsx1QW19iDs8jQLevzzcms",
                "currency": "Bitcoin (BTC)",
                "first_seen": "2023-11-22",
                "last_seen": "2026-08-19",
                "total_received_btc": 88.10,
                "total_received_usd": 5726500.0,
                "tx_count": 512
            },
            {
                "address": "TNPZ3rN5EcX1imDS2gEh5jPJXeiW5QN8Yr",
                "currency": "Tether (USDT TRC20)",
                "first_seen": "2024-04-10",
                "last_seen": "2026-08-18",
                "total_received_usd": 1450000.0,
                "tx_count": 320
            }
        ],
        "communication_channels": [
            {"type": "Telegram", "handle": "@ShadowCashSupport", "verified": True},
            {"type": "Session ID", "handle": "05a91b283948571029384756102938475610293847561029384756102938475610", "verified": True}
        ],
        "marketplaces": [
            {"marketplace": "Abacus Market", "vendor_name": "DumpKing_Global", "rating": 4.88, "reviews_count": 960, "positive_percent": 97.2, "escrow_trust_score": 91}
        ],
        "associated_infrastructure": [
            {
                "onion_domain": "shadowmixer994k2.onion",
                "service_type": "Tumbling & Mixing Service",
                "origin_ip": "91.215.85.17",
                "clearnet_hostname": "node-escrow-api.bulletproof.su",
                "location": "Victoria, Seychelles",
                "isp": "B-Cloud Hosting Services",
                "asn": "AS58065",
                "unmasking_method": "Favicon MurmurHash3 + PHPInfo leak"
            }
        ]
    },
    {
        "actor_id": "ACTOR-003-NEXUSHACKER",
        "primary_alias": "NexusRecon",
        "category": "Initial Access Broker & Cyber Mercenary",
        "risk_level": "CRITICAL",
        "status": "Rebranded",
        "attribution_confidence": 91.2,
        "first_seen": "2022-08-14",
        "last_seen": "2026-08-30",
        "summary": "Corporate network penetration broker selling VPN, Citrix, and domain admin credentials of critical infrastructure. Recently suspected of rebranding to new persona 'PhantomCipher'.",
        "tags": ["initial-access-broker", "corporate-breach", "rebranded-persona", "critical-infrastructure"],
        "aliases": [
            {"handle": "NexusRecon", "platform": "XSS.is", "url": "https://xss.is/user/NexusRecon", "first_seen": "2022-08-14", "reputation_rep": "Verified VIP"},
            {"handle": "PhantomCipher", "platform": "BreachForums", "url": "https://breachforums.../user/PhantomCipher", "first_seen": "2025-10-01", "reputation_rep": "New Member (Flagged)"}
        ],
        "pgp_keys": [
            {
                "key_id": "0x3344110099AA8877",
                "fingerprint": "EE88 3344 1100 99AA 8877 1234 5678 90AB CDEF 1122",
                "uid_email": "nexusrecon@proton.me",
                "created_date": "2022-08-10",
                "bit_length": 4096,
                "algorithm": "RSA"
            }
        ],
        "crypto_wallets": [
            {
                "address": "bc1q9d84u2z9p3m2h1k4j6f8x0c2v4b6n8m0q2w4e6",
                "currency": "Bitcoin (BTC)",
                "first_seen": "2022-08-20",
                "last_seen": "2026-08-29",
                "total_received_btc": 26.50,
                "total_received_usd": 1722500.0,
                "tx_count": 68
            }
        ],
        "communication_channels": [
            {"type": "Telegram", "handle": "@NexusRecon_Official", "verified": True},
            {"type": "Tox ID", "handle": "8811223344556677889900AABBCCDDEEFF0011223344556677889900AABBCCDDEE", "verified": True}
        ],
        "marketplaces": [],
        "associated_infrastructure": [
            {
                "onion_domain": "nexusaccessbroker.onion",
                "service_type": "Corporate RDP/VPN Access Store",
                "origin_ip": "194.135.25.68",
                "clearnet_hostname": "core-rdp-broker.offshore-net.ru",
                "location": "Moscow, Russia",
                "isp": "Serverius Holding B.V.",
                "asn": "AS50673",
                "unmasking_method": "OpenSSH Host Key Passive Correlation + Git Config remote leak"
            }
        ]
    }
]


class ThreatActorEngine:
    """
    Core management engine for Threat Actor intelligence storage,
    querying, graph construction, and timeline extraction.
    """

    def __init__(self, db_path: str = DB_FILE_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize SQLite storage schema for threat actors and scan audit logs."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                actor_id TEXT PRIMARY KEY,
                primary_alias TEXT,
                category TEXT,
                risk_level TEXT,
                status TEXT,
                attribution_confidence REAL,
                first_seen TEXT,
                last_seen TEXT,
                data_json TEXT,
                updated_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tor_scan_audits (
                scan_id TEXT PRIMARY KEY,
                onion_target TEXT,
                domain TEXT,
                unmasked INTEGER,
                attribution_confidence REAL,
                origin_ip TEXT,
                origin_hostname TEXT,
                location TEXT,
                findings_count INTEGER,
                data_json TEXT,
                scanned_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stylometric_comparisons (
                comparison_id TEXT PRIMARY KEY,
                target_a_name TEXT,
                target_b_name TEXT,
                overall_similarity REAL,
                lexical_similarity REAL,
                punctuation_similarity REAL,
                ngram_similarity REAL,
                diurnal_overlap REAL,
                verdict TEXT,
                data_json TEXT,
                created_at TEXT
            )
        """)

        conn.commit()

        # Check if threat actors table is empty, if so populate with initial baseline profiles
        cursor.execute("SELECT COUNT(*) FROM threat_actors")
        count = cursor.fetchone()[0]
        if count == 0:
            for actor in INITIAL_THREAT_ACTORS:
                self._upsert_actor_dict(actor, cursor=cursor)
            conn.commit()

        conn.close()

    def _upsert_actor_dict(self, actor: Dict[str, Any], cursor: Optional[sqlite3.Cursor] = None):
        """Insert or update a threat actor record."""
        should_close = False
        if cursor is None:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            should_close = True

        cursor.execute("""
            INSERT OR REPLACE INTO threat_actors
            (actor_id, primary_alias, category, risk_level, status, attribution_confidence, first_seen, last_seen, data_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            actor["actor_id"],
            actor["primary_alias"],
            actor.get("category", "Threat Actor"),
            actor.get("risk_level", "HIGH"),
            actor.get("status", "Active"),
            float(actor.get("attribution_confidence", 85.0)),
            actor.get("first_seen", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")),
            actor.get("last_seen", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")),
            json.dumps(actor),
            datetime.datetime.now(datetime.timezone.utc).isoformat()
        ))

        if should_close:
            conn.commit()
            conn.close()

    def get_all_actors(self, category_filter: Optional[str] = None, risk_filter: Optional[str] = None) -> List[ThreatActor]:
        """Fetch all tracked threat actors with optional filtering."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT data_json FROM threat_actors WHERE 1=1"
        params = []
        if category_filter:
            query += " AND category = ?"
            params.append(category_filter)
        if risk_filter:
            query += " AND risk_level = ?"
            params.append(risk_filter)

        query += " ORDER BY attribution_confidence DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        actors = []
        for r in rows:
            data = json.loads(r[0])
            actors.append(ThreatActor(data["actor_id"], data))
        return actors

    def get_actor_by_id(self, actor_id: str) -> Optional[ThreatActor]:
        """Fetch a specific threat actor by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT data_json FROM threat_actors WHERE actor_id = ?", (actor_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            data = json.loads(row[0])
            return ThreatActor(data["actor_id"], data)
        return None

    def save_actor(self, actor_dict: Dict[str, Any]):
        """Save or update a threat actor dossier."""
        self._upsert_actor_dict(actor_dict)

    def save_scan_audit(self, audit_result: Dict[str, Any]):
        """Save a Tor hidden service misconfiguration audit result."""
        import uuid
        scan_id = str(uuid.uuid4())
        origin = audit_result.get("origin_attribution", {})
        primary = origin.get("primary_origin") or {}

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO tor_scan_audits
            (scan_id, onion_target, domain, unmasked, attribution_confidence, origin_ip, origin_hostname, location, findings_count, data_json, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            audit_result.get("target"),
            audit_result.get("domain"),
            1 if origin.get("unmasked") else 0,
            float(origin.get("attribution_confidence", 0.0)),
            primary.get("origin_ip", "Unresolved"),
            primary.get("hostname", "N/A"),
            f"{primary.get('city', '')}, {primary.get('country', '')}".strip(", "),
            int(audit_result.get("findings_count", 0)),
            json.dumps(audit_result),
            audit_result.get("scan_timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
        ))
        conn.commit()
        conn.close()
        return scan_id

    def get_all_scan_audits(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent Tor scan audits."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT data_json FROM tor_scan_audits ORDER BY scanned_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [json.loads(r[0]) for r in rows]

    def build_actor_relationship_graph(self, actor_id: str) -> Dict[str, Any]:
        """
        Build an interactive network graph (nodes and links) for Cytoscape.js or ECharts
        centered around the specified threat actor.
        """
        actor = self.get_actor_by_id(actor_id)
        if not actor:
            return {"nodes": [], "links": [], "categories": []}

        data = actor.to_dict()
        nodes = []
        links = []
        categories = [
            {"name": "Threat Actor", "itemStyle": {"color": "#ef4444"}},
            {"name": "Handle / Alias", "itemStyle": {"color": "#3b82f6"}},
            {"name": "PGP Key", "itemStyle": {"color": "#10b981"}},
            {"name": "Crypto Wallet", "itemStyle": {"color": "#f59e0b"}},
            {"name": "Marketplace", "itemStyle": {"color": "#8b5cf6"}},
            {"name": "Communication", "itemStyle": {"color": "#06b6d4"}},
            {"name": "Tor Infrastructure", "itemStyle": {"color": "#ec4899"}},
            {"name": "Clearnet Origin IP", "itemStyle": {"color": "#dc2626"}}
        ]

        # 1. Central Actor Node
        actor_node_id = f"actor_{actor_id}"
        nodes.append({
            "id": actor_node_id,
            "name": actor.get_primary_alias(),
            "category": 0,
            "symbolSize": 55,
            "value": f"Confidence: {actor.get_attribution_confidence()}%",
            "tooltip": f"<b>{actor.get_primary_alias()}</b><br/>Category: {actor.get_category()}<br/>Risk: {actor.get_risk_level()}<br/>Confidence: {actor.get_attribution_confidence()}%"
        })

        # 2. Aliases / Handles
        for i, alias in enumerate(data.get("aliases", [])):
            handle_node_id = f"handle_{actor_id}_{i}"
            nodes.append({
                "id": handle_node_id,
                "name": f"{alias['handle']} ({alias['platform']})",
                "category": 1,
                "symbolSize": 38,
                "value": alias.get("reputation_rep", ""),
                "tooltip": f"<b>{alias['handle']}</b><br/>Platform: {alias['platform']}<br/>Reputation: {alias.get('reputation_rep', 'N/A')}<br/>First seen: {alias.get('first_seen', 'N/A')}"
            })
            links.append({
                "source": actor_node_id,
                "target": handle_node_id,
                "value": "OPERATES_AS",
                "label": {"show": True, "formatter": "OPERATES_AS"}
            })

        # 3. PGP Keys
        for i, pgp in enumerate(data.get("pgp_keys", [])):
            pgp_node_id = f"pgp_{actor_id}_{i}"
            nodes.append({
                "id": pgp_node_id,
                "name": f"PGP: {pgp['key_id']}",
                "category": 2,
                "symbolSize": 42,
                "value": pgp.get("uid_email", ""),
                "tooltip": f"<b>PGP Key: {pgp['key_id']}</b><br/>Fingerprint: {pgp.get('fingerprint')}<br/>UID Email: {pgp.get('uid_email')}<br/>Algorithm: {pgp.get('algorithm')} ({pgp.get('bit_length')} bit)"
            })
            links.append({
                "source": actor_node_id,
                "target": pgp_node_id,
                "value": "SIGNS_WITH",
                "label": {"show": True, "formatter": "SIGNS_WITH"}
            })

        # 4. Crypto Wallets
        for i, wallet in enumerate(data.get("crypto_wallets", [])):
            wallet_node_id = f"wallet_{actor_id}_{i}"
            short_addr = f"{wallet['address'][:8]}...{wallet['address'][-6:]}"
            nodes.append({
                "id": wallet_node_id,
                "name": f"{wallet['currency'][:3]}: {short_addr}",
                "category": 3,
                "symbolSize": 40,
                "value": f"${wallet.get('total_received_usd', 0):,.0f}",
                "tooltip": f"<b>{wallet['currency']}</b><br/>Address: {wallet['address']}<br/>Total Received: ${wallet.get('total_received_usd', 0):,.2f}<br/>Tx Count: {wallet.get('tx_count', 0)}"
            })
            links.append({
                "source": actor_node_id,
                "target": wallet_node_id,
                "value": "CONTROLS_WALLET",
                "label": {"show": True, "formatter": "RECEIVES"}
            })

        # 5. Marketplaces
        for i, mkt in enumerate(data.get("marketplaces", [])):
            mkt_node_id = f"mkt_{actor_id}_{i}"
            nodes.append({
                "id": mkt_node_id,
                "name": mkt["marketplace"],
                "category": 4,
                "symbolSize": 36,
                "value": f"Rating: {mkt['rating']}/5",
                "tooltip": f"<b>{mkt['marketplace']}</b><br/>Vendor: {mkt['vendor_name']}<br/>Rating: {mkt['rating']}/5 ({mkt['reviews_count']} reviews)<br/>Trust Score: {mkt['escrow_trust_score']}%"
            })
            links.append({
                "source": actor_node_id,
                "target": mkt_node_id,
                "value": "VENDS_ON",
                "label": {"show": True, "formatter": "VENDS_ON"}
            })

        # 6. Communication Channels
        for i, comm in enumerate(data.get("communication_channels", [])):
            comm_node_id = f"comm_{actor_id}_{i}"
            nodes.append({
                "id": comm_node_id,
                "name": f"{comm['type']}: {comm['handle']}",
                "category": 5,
                "symbolSize": 34,
                "value": "Verified" if comm.get("verified") else "Unverified",
                "tooltip": f"<b>{comm['type']} Channel</b><br/>Handle: {comm['handle']}<br/>Verified: {comm.get('verified')}"
            })
            links.append({
                "source": actor_node_id,
                "target": comm_node_id,
                "value": "COMMUNICATES_VIA",
                "label": {"show": True, "formatter": "COMMS"}
            })

        # 7. Tor Infrastructure & Unmasked Clearnet Origin IPs
        for i, infra in enumerate(data.get("associated_infrastructure", [])):
            onion_node_id = f"onion_{actor_id}_{i}"
            nodes.append({
                "id": onion_node_id,
                "name": infra["onion_domain"],
                "category": 6,
                "symbolSize": 44,
                "value": infra["service_type"],
                "tooltip": f"<b>Tor Hidden Service</b><br/>Domain: {infra['onion_domain']}<br/>Type: {infra['service_type']}"
            })
            links.append({
                "source": actor_node_id,
                "target": onion_node_id,
                "value": "OPERATES_SERVICE",
                "label": {"show": True, "formatter": "HOSTS"}
            })

            if infra.get("origin_ip"):
                origin_node_id = f"origin_ip_{actor_id}_{i}"
                nodes.append({
                    "id": origin_node_id,
                    "name": f"Origin: {infra['origin_ip']}",
                    "category": 7,
                    "symbolSize": 48,
                    "value": infra.get("location", ""),
                    "tooltip": f"<b>Unmasked Origin Server</b><br/>IP: {infra['origin_ip']}<br/>Hostname: {infra.get('clearnet_hostname', 'N/A')}<br/>Location: {infra.get('location')}<br/>ISP: {infra.get('isp')} ({infra.get('asn')})<br/>Unmasking Method: {infra.get('unmasking_method')}"
                })
                links.append({
                    "source": onion_node_id,
                    "target": origin_node_id,
                    "value": "UNMASKED_TO_ORIGIN",
                    "label": {"show": True, "formatter": "UNMASKED_ORIGIN"}
                })

        return {
            "actor": data,
            "nodes": nodes,
            "links": links,
            "categories": categories
        }

    def get_timeline_events(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Extract chronological activity footprints across all tracked threat actors
        for timeline querying.
        """
        actors = self.get_all_actors()
        events = []

        for actor in actors:
            d = actor.to_dict()
            actor_name = d["primary_alias"]

            # Actor First Seen Event
            if d.get("first_seen"):
                events.append({
                    "date": d["first_seen"],
                    "actor_id": d["actor_id"],
                    "actor_name": actor_name,
                    "event_type": "Actor Profile Created",
                    "category": d["category"],
                    "description": f"Threat actor '{actor_name}' first indexed on dark web monitoring network.",
                    "severity": "INFO",
                    "source": "AIL Threat Actor Ingestion"
                })

            # Aliases events
            for alias in d.get("aliases", []):
                if alias.get("first_seen"):
                    events.append({
                        "date": alias["first_seen"],
                        "actor_id": d["actor_id"],
                        "actor_name": actor_name,
                        "event_type": "New Forum/Market Alias",
                        "category": alias["platform"],
                        "description": f"Actor '{actor_name}' registered or began operating under handle '{alias['handle']}' on {alias['platform']}.",
                        "severity": "MEDIUM",
                        "source": alias["platform"]
                    })

            # PGP Key events
            for pgp in d.get("pgp_keys", []):
                if pgp.get("created_date"):
                    events.append({
                        "date": pgp["created_date"],
                        "actor_id": d["actor_id"],
                        "actor_name": actor_name,
                        "event_type": "PGP Key Generation",
                        "category": "Cryptography",
                        "description": f"PGP Key ID {pgp['key_id']} generated with email '{pgp.get('uid_email')}'.",
                        "severity": "HIGH",
                        "source": "PGP Keyring"
                    })

            # Infrastructure unmasking events
            for infra in d.get("associated_infrastructure", []):
                events.append({
                    "date": d.get("last_seen", "2026-08-01"),
                    "actor_id": d["actor_id"],
                    "actor_name": actor_name,
                    "event_type": "Origin Server Unmasked",
                    "category": "Deanonymization",
                    "description": f"Tor hidden service '{infra['onion_domain']}' de-anonymized to origin IP {infra.get('origin_ip')} ({infra.get('location')}) via {infra.get('unmasking_method')}.",
                    "severity": "CRITICAL",
                    "source": "Tor Misconfig Engine"
                })

        # Filter by date range if provided
        if start_date:
            events = [e for e in events if e["date"] >= start_date]
        if end_date:
            events = [e for e in events if e["date"] <= end_date]

        # Sort chronologically descending
        events.sort(key=lambda x: x["date"], reverse=True)
        return events
