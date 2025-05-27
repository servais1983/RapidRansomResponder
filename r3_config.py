#!/usr/bin/env python3
"""
Configuration centrale pour RapidRansomResponder
Orchestration des modules avancés et gestion des paramètres
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass 
class R3Configuration:
    """Configuration principale de R3"""
    
    # Configuration générale
    log_level: str = "INFO"
    log_file: str = "r3.log"
    data_directory: str = "data/"
    models_directory: str = "models/"
    reports_directory: str = "reports/"
    
    # Configuration de détection comportementale
    behavioral_detection: Dict[str, Any] = None
    
    # Configuration d'intégrations sécurité
    security_integrations: Dict[str, Any] = None
    
    # Configuration ML
    ml_identification: Dict[str, Any] = None
    
    # Configuration de base de données
    database: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialise les configurations par défaut"""
        if self.behavioral_detection is None:
            self.behavioral_detection = {
                "enabled": True,
                "sampling_interval": 1.0,
                "history_window": 300,
                "thresholds": {
                    "cpu_spike": 80.0,
                    "memory_spike": 85.0,
                    "disk_io_anomaly": 50000000,
                    "process_creation_rate": 10,
                    "file_encryption_pattern": 100,
                    "network_anomaly": 50
                }
            }
        
        if self.security_integrations is None:
            self.security_integrations = {
                "enabled": False,
                "fortigate": {
                    "enabled": False,
                    "host": "",
                    "api_key": "",
                    "verify_ssl": True
                },
                "crowdstrike": {
                    "enabled": False,
                    "client_id": "",
                    "client_secret": "",
                    "base_url": "https://api.crowdstrike.com"
                },
                "azure_sentinel": {
                    "enabled": False,
                    "tenant_id": "",
                    "client_id": "",
                    "client_secret": "",
                    "workspace_id": ""
                }
            }
        
        if self.ml_identification is None:
            self.ml_identification = {
                "enabled": True,
                "model_path": "models/",
                "taxonomy_db": "ransomware_taxonomy.db",
                "yara_rules_enabled": True,
                "cache_enabled": True,
                "batch_analysis_enabled": True
            }
        
        if self.database is None:
            self.database = {
                "type": "sqlite",
                "path": "r3_database.db",
                "backup_enabled": True,
                "backup_interval": 3600
            }

class R3ConfigManager:
    """Gestionnaire de configuration pour R3"""
    
    def __init__(self, config_file: str = "r3_config.json"):
        self.config_file = Path(config_file)
        self.config = R3Configuration()
        self.logger = logging.getLogger(__name__)
        
        # Charger la configuration si elle existe
        if self.config_file.exists():
            self.load_config()
        else:
            self.save_config()
    
    def load_config(self) -> R3Configuration:
        """Charge la configuration depuis le fichier JSON"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Mettre à jour la configuration avec les données chargées
            for key, value in config_data.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
            
            self.logger.info(f"Configuration loaded from {self.config_file}")
            return self.config
            
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return self.config
    
    def save_config(self):
        """Sauvegarde la configuration dans le fichier JSON"""
        try:
            config_dict = asdict(self.config)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Configuration saved to {self.config_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
    
    def update_config(self, section: str, updates: Dict[str, Any]):
        """Met à jour une section de la configuration"""
        try:
            if hasattr(self.config, section):
                current_section = getattr(self.config, section)
                if isinstance(current_section, dict):
                    current_section.update(updates)
                else:
                    setattr(self.config, section, updates)
                
                self.save_config()
                self.logger.info(f"Updated configuration section: {section}")
            else:
                self.logger.warning(f"Unknown configuration section: {section}")
                
        except Exception as e:
            self.logger.error(f"Failed to update config: {e}")
    
    def get_config(self) -> R3Configuration:
        """Retourne la configuration actuelle"""
        return self.config
    
    def validate_config(self) -> bool:
        """Valide la configuration actuelle"""
        try:
            # Vérifier les répertoires obligatoires
            directories = [
                self.config.data_directory,
                self.config.models_directory,
                self.config.reports_directory
            ]
            
            for directory in directories:
                Path(directory).mkdir(parents=True, exist_ok=True)
            
            # Valider la configuration de détection comportementale
            if self.config.behavioral_detection["enabled"]:
                required_thresholds = [
                    "cpu_spike", "memory_spike", "disk_io_anomaly",
                    "process_creation_rate", "file_encryption_pattern", "network_anomaly"
                ]
                
                for threshold in required_thresholds:
                    if threshold not in self.config.behavioral_detection["thresholds"]:
                        self.logger.warning(f"Missing threshold: {threshold}")
                        return False
            
            # Valider les intégrations de sécurité
            if self.config.security_integrations["enabled"]:
                for integration, settings in self.config.security_integrations.items():
                    if integration == "enabled":
                        continue
                    
                    if settings.get("enabled", False):
                        if integration == "fortigate":
                            if not settings.get("host") or not settings.get("api_key"):
                                self.logger.warning(f"FortiGate integration missing required parameters")
                                return False
                        
                        elif integration == "crowdstrike":
                            if not settings.get("client_id") or not settings.get("client_secret"):
                                self.logger.warning(f"CrowdStrike integration missing required parameters")
                                return False
                        
                        elif integration == "azure_sentinel":
                            required_params = ["tenant_id", "client_id", "client_secret", "workspace_id"]
                            if not all(settings.get(param) for param in required_params):
                                self.logger.warning(f"Azure Sentinel integration missing required parameters")
                                return False
            
            self.logger.info("Configuration validation successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False
    
    def setup_logging(self):
        """Configure le système de logging basé sur la configuration"""
        try:
            log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
            
            # Configuration du logging
            logging.basicConfig(
                level=log_level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(self.config.log_file),
                    logging.StreamHandler()
                ]
            )
            
            self.logger.info(f"Logging configured with level: {self.config.log_level}")
            
        except Exception as e:
            print(f"Failed to setup logging: {e}")
    
    def get_integration_config(self, integration_name: str) -> Optional[Dict[str, Any]]:
        """Récupère la configuration d'une intégration spécifique"""
        try:
            if integration_name in self.config.security_integrations:
                return self.config.security_integrations[integration_name]
            return None
        except Exception as e:
            self.logger.error(f"Failed to get integration config for {integration_name}: {e}")
            return None
    
    def is_integration_enabled(self, integration_name: str) -> bool:
        """Vérifie si une intégration est activée"""
        try:
            integration_config = self.get_integration_config(integration_name)
            return integration_config.get("enabled", False) if integration_config else False
        except Exception as e:
            self.logger.error(f"Failed to check integration status for {integration_name}: {e}")
            return False
    
    def create_default_config_file(self):
        """Crée un fichier de configuration d'exemple"""
        example_config = R3Configuration()
        
        # Ajouter des exemples de configuration
        example_config.security_integrations["fortigate"] = {
            "enabled": False,
            "host": "192.168.1.1",
            "api_key": "YOUR_FORTIGATE_API_KEY_HERE",
            "verify_ssl": True
        }
        
        example_config.security_integrations["crowdstrike"] = {
            "enabled": False,
            "client_id": "YOUR_CROWDSTRIKE_CLIENT_ID",
            "client_secret": "YOUR_CROWDSTRIKE_CLIENT_SECRET",
            "base_url": "https://api.crowdstrike.com"
        }
        
        self.config = example_config
        
        # Sauvegarder avec un nom différent pour éviter d'écraser
        example_file = self.config_file.parent / "r3_config_example.json"
        
        try:
            config_dict = asdict(self.config)
            
            with open(example_file, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            print(f"Example configuration created: {example_file}")
            print("Copy this file to r3_config.json and customize it for your environment")
            
        except Exception as e:
            print(f"Failed to create example config: {e}")

def load_r3_config(config_file: str = "r3_config.json") -> R3ConfigManager:
    """Charge la configuration R3 avec validation"""
    config_manager = R3ConfigManager(config_file)
    
    # Valider la configuration
    if not config_manager.validate_config():
        print("Warning: Configuration validation failed. Some features may not work properly.")
    
    # Configurer le logging
    config_manager.setup_logging()
    
    return config_manager

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "create-example":
        # Créer un fichier de configuration d'exemple
        config_manager = R3ConfigManager()
        config_manager.create_default_config_file()
    else:
        # Charger et valider la configuration
        config_manager = load_r3_config()
        config = config_manager.get_config()
        
        print("R3 Configuration Status:")
        print(f"  Behavioral Detection: {'Enabled' if config.behavioral_detection['enabled'] else 'Disabled'}")
        print(f"  Security Integrations: {'Enabled' if config.security_integrations['enabled'] else 'Disabled'}")
        print(f"  ML Identification: {'Enabled' if config.ml_identification['enabled'] else 'Disabled'}")
        
        # Afficher les intégrations activées
        enabled_integrations = []
        for name, settings in config.security_integrations.items():
            if name != "enabled" and isinstance(settings, dict) and settings.get("enabled", False):
                enabled_integrations.append(name)
        
        if enabled_integrations:
            print(f"  Active Integrations: {', '.join(enabled_integrations)}")
        else:
            print("  Active Integrations: None")
        
        print(f"\nConfiguration file: {config_manager.config_file}")
        print(f"Log file: {config.log_file}")
        print(f"Data directory: {config.data_directory}")
        
        print("\nUse 'python r3_config.py create-example' to generate an example configuration file.")
