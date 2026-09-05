#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
AIL Tor Misconfiguration Scanner Module
=======================================
Subscribes to Onion / Domain queues, executes misconfiguration probes,
extracts TLS certificate details, and registers unmasked origin servers in AIL.
"""

import os
import sys
import json
import logging

sys.path.append(os.environ.get('AIL_BIN', os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from modules.abstract_module import AbstractModule
except Exception:
    class AbstractModule:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.proceed = True
            self.pending_seconds = 2

from lib.tor_origin_attribution import TorMisconfigScanner
from lib.threat_actor_engine import ThreatActorEngine


class TorMisconfigModule(AbstractModule):
    """
    Asynchronous queue worker for Tor Misconfiguration Audits.
    """

    def __init__(self):
        super(TorMisconfigModule, self).__init__(module_name='TorMisconfigScanner')
        self.scanner = TorMisconfigScanner()
        self.engine = ThreatActorEngine()
        self.pending_seconds = 2

    def process_domain(self, domain_name: str) -> dict:
        """Execute audit on a newly discovered domain or hidden service."""
        if not domain_name or not domain_name.endswith('.onion'):
            return {}

        self.logger.info(f"Auditing Tor hidden service for misconfigurations: {domain_name}")
        result = self.scanner.scan_misconfigurations(domain_name)
        
        # Save audit record
        scan_id = self.engine.save_scan_audit(result)
        self.logger.info(f"Saved audit {scan_id} for {domain_name}. Unmasked: {result.get('origin_attribution', {}).get('unmasked')}")
        return result


if __name__ == '__main__':
    module = TorMisconfigModule()
    print("[*] TorMisconfigScanner module initialized successfully.")
