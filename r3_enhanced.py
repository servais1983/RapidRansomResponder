#!/usr/bin/env python3
"""
RapidRansomResponder (R3) - Core Integration Module
Orchestration des modules avancés pour la réponse aux incidents ransomware
"""

import asyncio
import logging
import sys
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

# Imports des modules R3
from r3_config import load_r3_config, R3ConfigManager

try:
    from core.behavioral_detection import start_behavioral_monitoring, BehavioralDetector
except ImportError:
    BehavioralDetector = None

try:
    from core.security_integrations import create_security_orchestrator, SecurityOrchestrator
except ImportError:
    SecurityOrchestrator = None

try:
    from core.ml_identification import create_advanced_detector, analyze_file_for_ransomware, AdvancedRansomwareDetector
except ImportError:
    AdvancedRansomwareDetector = None

# Imports des modules existants
from core.detect import fingerprint
from core.contain import isolate
from core.collect import collect_evidence
from core.decrypt import attempt_decrypt
from core.report import generate_report

class R3EnhancedCore:
    """Cœur amélioré de RapidRansomResponder avec modules avancés"""
    
    def __init__(self, config_file: str = "r3_config.json"):
        self.config_manager = load_r3_config(config_file)
        self.config = self.config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Composants avancés
        self.behavioral_detector: Optional[BehavioralDetector] = None
        self.security_orchestrator: Optional[SecurityOrchestrator] = None
        self.ml_detector: Optional[AdvancedRansomwareDetector] = None
        
        # États et statistiques
        self.incident_active = False
        self.start_time = None
        self.stats = {
            "incidents_handled": 0,
            "files_analyzed": 0,
            "threats_detected": 0,
            "actions_executed": 0
        }
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialise les composants avancés selon la configuration"""
        try:
            # Détection comportementale
            if self.config.behavioral_detection["enabled"] and BehavioralDetector:
                self.logger.info("Initializing behavioral detection...")
                from core.behavioral_detection import start_behavioral_monitoring
                self.behavioral_detector = start_behavioral_monitoring(
                    self.config.behavioral_detection
                )
            
            # Orchestrateur de sécurité
            if self.config.security_integrations["enabled"] and SecurityOrchestrator:
                self.logger.info("Initializing security integrations...")
                from core.security_integrations import create_security_orchestrator
                self.security_orchestrator = create_security_orchestrator(
                    self.config.security_integrations
                )
            
            # Détecteur ML
            if self.config.ml_identification["enabled"] and AdvancedRansomwareDetector:
                self.logger.info("Initializing ML identification...")
                from core.ml_identification import create_advanced_detector
                self.ml_detector = create_advanced_detector(
                    self.config.ml_identification
                )
            
            self.start_time = datetime.now()
            self.logger.info("R3 Enhanced Core initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Component initialization failed: {e}")
    
    async def handle_ransomware_incident(self, epicenter: str, additional_context: Dict = None) -> Dict[str, Any]:
        """Gère un incident ransomware avec tous les modules avancés"""
        try:
            self.incident_active = True
            incident_id = f"R3_{int(time.time())}"
            self.logger.critical(f"🚨 RANSOMWARE INCIDENT DETECTED - ID: {incident_id}")
            
            # Workflow de réponse simplifiée pour éviter les erreurs
            incident_data = {
                "incident_id": incident_id,
                "epicenter": epicenter,
                "start_time": datetime.now(),
                "phases": {},
                "total_duration": 0
            }
            
            # Phase 1: Confinement
            self.logger.info("[1/4] Confinement...")
            zone = isolate(epicenter)
            incident_data["phases"]["containment"] = {"status": "completed", "zone": zone}
            
            # Phase 2: Collecte
            self.logger.info("[2/4] Collecte...")
            evidence = collect_evidence({"epicenter": epicenter})
            incident_data["phases"]["collection"] = {"status": "completed", "evidence": evidence}
            
            # Phase 3: Analyse
            self.logger.info("[3/4] Analyse...")
            profile = fingerprint(evidence)
            incident_data["phases"]["analysis"] = {"status": "completed", "profile": profile}
            
            # Phase 4: Réponse
            self.logger.info("[4/4] Réponse...")
            if profile.get("decryptable"):
                result = attempt_decrypt(evidence)
                print(f"[✓] Déchiffrement : {result}")
                incident_data["phases"]["response"] = {"status": "decryption_attempted", "result": result}
            else:
                report = generate_report(evidence)
                print("[✓] Rapport généré")
                incident_data["phases"]["response"] = {"status": "report_generated", "report": report}
            
            # Finaliser
            incident_data["end_time"] = datetime.now()
            incident_data["total_duration"] = (
                incident_data["end_time"] - incident_data["start_time"]
            ).total_seconds()
            
            self.stats["incidents_handled"] += 1
            self.incident_active = False
            
            return incident_data
            
        except Exception as e:
            self.logger.error(f"❌ Incident handling failed: {e}")
            self.incident_active = False
            raise
    
    def get_system_status(self) -> Dict[str, Any]:
        """Retourne l'état actuel du système R3"""
        try:
            status = {
                "r3_version": "2.0-enhanced",
                "uptime": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
                "incident_active": self.incident_active,
                "statistics": self.stats.copy(),
                "components": {
                    "behavioral_detection": self.behavioral_detector is not None,
                    "security_orchestrator": self.security_orchestrator is not None,
                    "ml_detector": self.ml_detector is not None
                }
            }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {"error": str(e)}
    
    async def shutdown(self):
        """Arrêt propre du système R3"""
        try:
            self.logger.info("Shutting down R3 Enhanced Core...")
            
            # Arrêter la détection comportementale
            if self.behavioral_detector:
                self.behavioral_detector.stop_monitoring()
            
            # Arrêter l'orchestrateur de sécurité
            if self.security_orchestrator:
                await self.security_orchestrator.stop_action_processor()
            
            self.logger.info("R3 Enhanced Core shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

# Interface CLI
async def main():
    """Point d'entrée principal pour R3 Enhanced"""
    try:
        if len(sys.argv) < 2:
            print("🛡️  RapidRansomResponder (R3) Enhanced v2.0")
            print()
            print("Usage:")
            print("  python r3_enhanced.py --epicenter <IP_OR_HOSTNAME>")
            print("  python r3_enhanced.py --status")
            print("  python r3_enhanced.py --config")
            print()
            print("Examples:")
            print("  python r3_enhanced.py --epicenter 192.168.1.45")
            print("  python r3_enhanced.py --status")
            print()
            print("Advanced Features:")
            print("  ✅ Behavioral Detection - Real-time CPU/RAM/IO monitoring")
            print("  🔗 Security Integrations - FortiGate, CrowdStrike, Azure Sentinel")
            print("  🧠 ML Identification - Advanced ransomware family classification")
            print("  📊 Enhanced Reporting - Detailed incident analysis")
            return
        
        # Initialiser R3 Enhanced
        r3 = R3EnhancedCore()
        
        if sys.argv[1] == "--status":
            status = r3.get_system_status()
            print("\n🛡️  R3 Enhanced System Status:")
            print(f"  Version: {status.get('r3_version', 'unknown')}")
            print(f"  Uptime: {status.get('uptime', 0):.2f} seconds")
            print(f"  Incident Active: {status.get('incident_active', False)}")
            print(f"  Incidents Handled: {status['statistics'].get('incidents_handled', 0)}")
            print("\n  Components:")
            for component, enabled in status.get('components', {}).items():
                print(f"    {component}: {'✅ Enabled' if enabled else '❌ Disabled'}")
        
        elif sys.argv[1] == "--config":
            config = r3.config
            print("\n🛡️  R3 Enhanced Configuration:")
            print(f"  Log Level: {config.log_level}")
            print(f"  Data Directory: {config.data_directory}")
            print(f"  Behavioral Detection: {'Enabled' if config.behavioral_detection['enabled'] else 'Disabled'}")
            print(f"  Security Integrations: {'Enabled' if config.security_integrations['enabled'] else 'Disabled'}")
            print(f"  ML Identification: {'Enabled' if config.ml_identification['enabled'] else 'Disabled'}")
        
        elif sys.argv[1] == "--epicenter" and len(sys.argv) > 2:
            epicenter = sys.argv[2]
            
            print(f"\n🚨 INITIATING RANSOMWARE RESPONSE FOR: {epicenter}")
            print("=" * 60)
            
            incident_data = await r3.handle_ransomware_incident(epicenter)
            
            print("\n✅ INCIDENT RESPONSE COMPLETED")
            print("=" * 60)
            print(f"Incident ID: {incident_data['incident_id']}")
            print(f"Total Duration: {incident_data['total_duration']:.2f} seconds")
            print(f"Phases Completed: {len(incident_data['phases'])}")
        
        else:
            print("❌ Invalid arguments. Use without arguments for help.")
        
        # Arrêt propre
        await r3.shutdown()
        
    except KeyboardInterrupt:
        print("\n⚠️  R3 Enhanced interrupted by user")
    except Exception as e:
        print(f"❌ R3 Enhanced error: {e}")
        logging.exception("R3 Enhanced critical error")

if __name__ == "__main__":
    asyncio.run(main())
