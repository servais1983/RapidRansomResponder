#!/usr/bin/env python3
"""
Module de détection comportementale en temps réel
Analyse les patterns CPU/RAM/IO pour détecter les activités ransomware
"""

import psutil
import time
import threading
import queue
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Optional
import logging

@dataclass
class BehaviorMetrics:
    """Métriques comportementales pour l'analyse"""
    cpu_usage: float
    memory_usage: float
    disk_io_read: int
    disk_io_write: int
    network_connections: int
    process_count: int
    file_operations: int
    timestamp: float

@dataclass
class ThreatAlert:
    """Alerte de menace détectée"""
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    threat_type: str
    confidence: float
    details: Dict
    timestamp: float
    affected_processes: List[int]

class BehavioralDetector:
    """Détecteur comportemental pour activités ransomware"""
    
    def __init__(self, sampling_interval=1.0, history_window=300):
        self.sampling_interval = sampling_interval
        self.history_window = history_window
        self.metrics_history = []
        self.is_monitoring = False
        self.alert_queue = queue.Queue()
        self.monitoring_thread = None
        
        # Seuils de détection (calibrés pour environnements professionnels)
        self.thresholds = {
            'cpu_spike': 80.0,          # % CPU prolongé
            'memory_spike': 85.0,       # % RAM
            'disk_io_anomaly': 50e6,    # 50MB/s en lecture/écriture
            'process_creation_rate': 10, # nouveaux processus/minute
            'file_encryption_pattern': 100, # opérations fichiers/minute
            'network_anomaly': 50       # connexions simultanées
        }
        
        # Patterns de comportement ransomware
        self.ransomware_patterns = {
            'mass_file_encryption': {
                'high_cpu_usage': True,
                'high_disk_write': True,
                'specific_file_extensions': ['.encrypt', '.locked', '.crypto'],
                'ransom_note_files': ['README.txt', 'HOW_TO_DECRYPT.txt', 'DECRYPT_INSTRUCTIONS.txt']
            },
            'lateral_movement': {
                'network_scanning': True,
                'smb_connections': True,
                'admin_share_access': True
            },
            'data_exfiltration': {
                'high_network_upload': True,
                'compressed_archives': True,
                'suspicious_destinations': True
            }
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def start_monitoring(self):
        """Démarre la surveillance comportementale"""
        if self.is_monitoring:
            self.logger.warning("Monitoring already running")
            return
            
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("Behavioral monitoring started")

    def stop_monitoring(self):
        """Arrête la surveillance comportementale"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join()
        self.logger.info("Behavioral monitoring stopped")

    def _monitoring_loop(self):
        """Boucle principale de surveillance"""
        while self.is_monitoring:
            try:
                metrics = self._collect_system_metrics()
                self.metrics_history.append(metrics)
                
                # Maintenir la fenêtre d'historique
                if len(self.metrics_history) > self.history_window:
                    self.metrics_history.pop(0)
                
                # Analyser les métriques pour détecter des anomalies
                alerts = self._analyze_metrics(metrics)
                for alert in alerts:
                    self.alert_queue.put(alert)
                    self.logger.warning(f"THREAT DETECTED: {alert.threat_type} - {alert.threat_level}")
                
                time.sleep(self.sampling_interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")

    def _collect_system_metrics(self) -> BehaviorMetrics:
        """Collecte les métriques système actuelles"""
        try:
            # Métriques CPU/RAM
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Métriques I/O disque
            disk_io = psutil.disk_io_counters()
            disk_read = disk_io.read_bytes if disk_io else 0
            disk_write = disk_io.write_bytes if disk_io else 0
            
            # Métriques réseau
            network_connections = len(psutil.net_connections())
            
            # Nombre de processus
            process_count = len(psutil.pids())
            
            return BehaviorMetrics(
                cpu_usage=cpu_percent,
                memory_usage=memory.percent,
                disk_io_read=disk_read,
                disk_io_write=disk_write,
                network_connections=network_connections,
                process_count=process_count,
                file_operations=self._estimate_file_operations(),
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return BehaviorMetrics(0, 0, 0, 0, 0, 0, 0, time.time())

    def _estimate_file_operations(self) -> int:
        """Estime le nombre d'opérations fichiers par seconde"""
        try:
            file_handles = 0
            for proc in psutil.process_iter(['pid', 'num_fds']):
                try:
                    file_handles += proc.info['num_fds'] or 0
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return file_handles
        except:
            return 0

    def _analyze_metrics(self, current_metrics: BehaviorMetrics) -> List[ThreatAlert]:
        """Analyse les métriques pour détecter des comportements suspects"""
        alerts = []
        
        if len(self.metrics_history) < 10:  # Besoin d'historique minimal
            return alerts
            
        # Détection de pics CPU prolongés
        recent_cpu = [m.cpu_usage for m in self.metrics_history[-10:]]
        if np.mean(recent_cpu) > self.thresholds['cpu_spike']:
            alerts.append(ThreatAlert(
                threat_level="HIGH",
                threat_type="SUSTAINED_HIGH_CPU",
                confidence=0.8,
                details={"avg_cpu": np.mean(recent_cpu), "duration": "10+ seconds"},
                timestamp=time.time(),
                affected_processes=[]
            ))
        
        # Détection d'anomalies I/O disque
        if len(self.metrics_history) >= 2:
            prev_metrics = self.metrics_history[-2]
            io_write_rate = (current_metrics.disk_io_write - prev_metrics.disk_io_write) / self.sampling_interval
            
            if io_write_rate > self.thresholds['disk_io_anomaly']:
                alerts.append(ThreatAlert(
                    threat_level="CRITICAL",
                    threat_type="MASS_FILE_ENCRYPTION_PATTERN",
                    confidence=0.9,
                    details={"write_rate_mb_s": io_write_rate / 1024 / 1024},
                    timestamp=time.time(),
                    affected_processes=self._get_high_io_processes()
                ))
        
        # Détection de création massive de processus
        recent_process_counts = [m.process_count for m in self.metrics_history[-60:]]  # Dernière minute
        if len(recent_process_counts) >= 60:
            process_creation_rate = (max(recent_process_counts) - min(recent_process_counts))
            if process_creation_rate > self.thresholds['process_creation_rate']:
                alerts.append(ThreatAlert(
                    threat_level="MEDIUM",
                    threat_type="RAPID_PROCESS_CREATION",
                    confidence=0.7,
                    details={"creation_rate": process_creation_rate},
                    timestamp=time.time(),
                    affected_processes=[]
                ))
        
        # Détection d'activité réseau anormale
        if current_metrics.network_connections > self.thresholds['network_anomaly']:
            alerts.append(ThreatAlert(
                threat_level="MEDIUM",
                threat_type="NETWORK_ANOMALY",
                confidence=0.6,
                details={"active_connections": current_metrics.network_connections},
                timestamp=time.time(),
                affected_processes=[]
            ))
            
        return alerts

    def _get_high_io_processes(self) -> List[int]:
        """Identifie les processus avec une activité I/O élevée"""
        high_io_pids = []
        try:
            for proc in psutil.process_iter(['pid', 'io_counters']):
                try:
                    io_info = proc.info['io_counters']
                    if io_info and io_info.write_bytes > 10 * 1024 * 1024:  # 10MB+
                        high_io_pids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        return high_io_pids

    def get_recent_alerts(self, max_alerts=10) -> List[ThreatAlert]:
        """Récupère les alertes récentes"""
        alerts = []
        try:
            while not self.alert_queue.empty() and len(alerts) < max_alerts:
                alerts.append(self.alert_queue.get_nowait())
        except queue.Empty:
            pass
        return alerts

    def get_system_health_status(self) -> Dict:
        """Retourne l'état de santé système actuel"""
        if not self.metrics_history:
            return {"status": "UNKNOWN", "details": "No metrics available"}
            
        latest = self.metrics_history[-1]
        recent_alerts = self.get_recent_alerts()
        
        # Déterminer le niveau de menace global
        threat_level = "LOW"
        if any(alert.threat_level == "CRITICAL" for alert in recent_alerts):
            threat_level = "CRITICAL"
        elif any(alert.threat_level == "HIGH" for alert in recent_alerts):
            threat_level = "HIGH"
        elif any(alert.threat_level == "MEDIUM" for alert in recent_alerts):
            threat_level = "MEDIUM"
            
        return {
            "status": threat_level,
            "current_metrics": {
                "cpu_usage": latest.cpu_usage,
                "memory_usage": latest.memory_usage,
                "active_processes": latest.process_count,
                "network_connections": latest.network_connections
            },
            "active_alerts": len(recent_alerts),
            "monitoring_duration": len(self.metrics_history) * self.sampling_interval
        }

def create_detector(config: Optional[Dict] = None) -> BehavioralDetector:
    """Factory function pour créer un détecteur configuré"""
    detector = BehavioralDetector()
    
    if config:
        # Appliquer la configuration personnalisée
        if 'sampling_interval' in config:
            detector.sampling_interval = config['sampling_interval']
        if 'thresholds' in config:
            detector.thresholds.update(config['thresholds'])
            
    return detector

# Interface pour intégration avec le système principal
def start_behavioral_monitoring(config: Optional[Dict] = None) -> BehavioralDetector:
    """Démarre le monitoring comportemental"""
    detector = create_detector(config)
    detector.start_monitoring()
    return detector

if __name__ == "__main__":
    # Test du module
    detector = start_behavioral_monitoring()
    
    try:
        print("Monitoring behavioral patterns... Press Ctrl+C to stop")
        while True:
            time.sleep(5)
            status = detector.get_system_health_status()
            alerts = detector.get_recent_alerts()
            
            print(f"System Status: {status['status']} | CPU: {status['current_metrics']['cpu_usage']:.1f}% | RAM: {status['current_metrics']['memory_usage']:.1f}%")
            
            if alerts:
                print(f"  -> {len(alerts)} new alerts detected")
                for alert in alerts:
                    print(f"     [{alert.threat_level}] {alert.threat_type} (confidence: {alert.confidence:.2f})")
                    
    except KeyboardInterrupt:
        detector.stop_monitoring()
        print("\nMonitoring stopped.")
