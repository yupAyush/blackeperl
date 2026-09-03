#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Autonomous Scan Daemon
======================
Background scheduler that continuously audits tracked .onion services,
monitors darknet forums for threat actor activity, and updates attribution intelligence.
"""

import os
import sys
import time
import json
import logging
import datetime

sys.path.append(os.environ.get('AIL_BIN', os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from lib.tor_origin_attribution import TorMisconfigScanner
from lib.threat_actor_engine import ThreatActorEngine
from lib.ai_stylometry_engine import AIStylometryEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('AutonomousScanDaemon')


class AutonomousScanDaemon:
    """
    Autonomous orchestration worker for continuous threat actor de-anonymization.
    """

    def __init__(self, interval_seconds: int = 60):
        self.interval = interval_seconds
        self.scanner = TorMisconfigScanner()
        self.actor_engine = ThreatActorEngine()
        self.stylometry_engine = AIStylometryEngine()
        self.running = False

    def run_cycle(self):
        """Execute one autonomous scanning iteration."""
        logger.info("Starting autonomous de-anonymization intelligence cycle...")
        actors = self.actor_engine.get_all_actors()
        
        for actor in actors:
            data = actor.to_dict()
            for infra in data.get("associated_infrastructure", []):
                onion = infra.get("onion_domain")
                if onion:
                    logger.info(f"Autonomous audit probing hidden service: {onion} (Actor: {actor.get_primary_alias()})")
                    # Run simulated / live probe
                    audit = self.scanner.scan_misconfigurations(onion)
                    self.actor_engine.save_scan_audit(audit)

        logger.info("Autonomous scan cycle completed successfully.")

    def start(self):
        self.running = True
        logger.info(f"AutonomousScanDaemon active (Interval: {self.interval}s)")
        try:
            while self.running:
                self.run_cycle()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            logger.info("AutonomousScanDaemon stopped.")


if __name__ == '__main__':
    daemon = AutonomousScanDaemon(interval_seconds=300)
    daemon.run_cycle()
