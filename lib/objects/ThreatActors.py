#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
AIL ThreatActor Object Model
============================
Defines the ThreatActor entity for cross-marketplace persona aggregation,
linking handles, PGP keys, crypto wallets, trust metrics, and origin infrastructure.
"""

import os
import sys
import json
import datetime
from typing import Dict, List, Any, Optional

sys.path.append(os.path.join(os.environ.get('AIL_BIN', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

try:
    from lib.objects.abstract_daterange_object import AbstractDaterangeObject
except Exception:
    class AbstractDaterangeObject:
        def __init__(self, obj_type, obj_id):
            self.type = obj_type
            self.id = obj_id


class ThreatActor(AbstractDaterangeObject):
    """
    Unified Threat Actor Entity representing a dark web operator
    tracked across multiple forums, marketplaces, and communication platforms.
    """

    def __init__(self, actor_id: str, data: Optional[Dict[str, Any]] = None):
        super(ThreatActor, self).__init__('threat-actor', actor_id)
        self.actor_id = actor_id
        self.data = data or {}

    def get_actor_id(self) -> str:
        return self.actor_id

    def get_global_id(self) -> str:
        return f"threat-actor:{self.actor_id}"

    def get_primary_alias(self) -> str:
        return self.data.get('primary_alias', self.actor_id)

    def get_aliases(self) -> List[Dict[str, Any]]:
        """List of aliases: [{'handle': 'DarkSpectre', 'platform': 'Dread', 'url': '...', 'first_seen': '...'}]"""
        return self.data.get('aliases', [])

    def get_category(self) -> str:
        """Category: Ransomware Operator, Data Broker, Initial Access Broker, Narcotics Vendor, Carder, etc."""
        return self.data.get('category', 'Threat Actor')

    def get_risk_level(self) -> str:
        """Risk Level: CRITICAL, HIGH, MEDIUM, LOW"""
        return self.data.get('risk_level', 'HIGH')

    def get_status(self) -> str:
        """Status: Active, Inactive, Rebranded, Apprehended"""
        return self.data.get('status', 'Active')

    def get_pgp_keys(self) -> List[Dict[str, Any]]:
        """List of PGP key metadata: [{'fingerprint': '...', 'key_id': '...', 'uid_email': '...', 'first_seen': '...'}]"""
        return self.data.get('pgp_keys', [])

    def get_crypto_wallets(self) -> List[Dict[str, Any]]:
        """List of crypto wallets: [{'address': '...', 'currency': 'BTC', 'first_seen': '...', 'total_received_usd': 120000}]"""
        return self.data.get('crypto_wallets', [])

    def get_communication_channels(self) -> List[Dict[str, Any]]:
        """List of communication IDs: [{'type': 'Telegram', 'handle': '@SpectreOps'}, {'type': 'Jabber', 'handle': 'spectre@exploit.im'}]"""
        return self.data.get('communication_channels', [])

    def get_marketplaces(self) -> List[Dict[str, Any]]:
        """Marketplace trust links: [{'marketplace': 'Archetyp', 'vendor_name': 'DarkSpectre', 'rating': 4.98, 'sales_count': 1420, 'trust_score': 98}]"""
        return self.data.get('marketplaces', [])

    def get_associated_infrastructure(self) -> List[Dict[str, Any]]:
        """Infrastructure: [{'onion_domain': 'darkspectre4a8s7d.onion', 'origin_ip': '185.220.101.45', 'service_type': 'C2 / Escrow'}]"""
        return self.data.get('associated_infrastructure', [])

    def get_attribution_confidence(self) -> float:
        return float(self.data.get('attribution_confidence', 85.0))

    def get_first_seen(self) -> str:
        return self.data.get('first_seen', datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'))

    def get_last_seen(self) -> str:
        return self.data.get('last_seen', datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize actor object to clean dictionary."""
        return {
            "actor_id": self.actor_id,
            "global_id": self.get_global_id(),
            "primary_alias": self.get_primary_alias(),
            "aliases": self.get_aliases(),
            "category": self.get_category(),
            "risk_level": self.get_risk_level(),
            "status": self.get_status(),
            "pgp_keys": self.get_pgp_keys(),
            "crypto_wallets": self.get_crypto_wallets(),
            "communication_channels": self.get_communication_channels(),
            "marketplaces": self.get_marketplaces(),
            "associated_infrastructure": self.get_associated_infrastructure(),
            "attribution_confidence": self.get_attribution_confidence(),
            "summary": self.data.get('summary', ''),
            "stylometric_profile_id": self.data.get('stylometric_profile_id'),
            "first_seen": self.get_first_seen(),
            "last_seen": self.get_last_seen(),
            "tags": self.data.get('tags', [])
        }
