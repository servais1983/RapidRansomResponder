#!/usr/bin/env python3
"""
Module d'intégration firewall/EDR/Cloud APIs
Orchestration automatisée des systèmes de sécurité pour réponse incident
"""

import requests
import json
import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import paramiko
import subprocess
from datetime import datetime, timedelta
import base64

@dataclass
class SecurityAction:
    """Action de sécurité à effectuer"""
    action_type: str  # BLOCK_IP, ISOLATE_HOST, QUARANTINE_FILE, etc.
    target: str
    priority: str  # LOW, MEDIUM, HIGH, CRITICAL
    system: str    # Système source de l'action
    timestamp: datetime
    details: Dict
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    error_message: Optional[str] = None

class SecurityIntegration(ABC):
    """Interface abstrate pour intégrations sécurité"""
    
    @abstractmethod
    async def authenticate(self) -> bool:
        pass
    
    @abstractmethod
    async def execute_action(self, action: SecurityAction) -> bool:
        pass
    
    @abstractmethod
    async def get_status(self) -> Dict:
        pass

class FortiGateIntegration(SecurityIntegration):
    """Intégration FortiGate Firewall"""
    
    def __init__(self, host: str, api_key: str, verify_ssl: bool = True):
        self.host = host
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}/api/v2"
        self.session = None
        self.logger = logging.getLogger(f"{__name__}.FortiGate")
    
    async def authenticate(self) -> bool:
        """Authentification FortiGate API"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with session.get(
                    f"{self.base_url}/cmdb/system/status",
                    headers=headers,
                    ssl=self.verify_ssl
                ) as response:
                    if response.status == 200:
                        self.logger.info("FortiGate authentication successful")
                        return True
                    else:
                        self.logger.error(f"FortiGate auth failed: {response.status}")
                        return False
        except Exception as e:
            self.logger.error(f"FortiGate auth error: {e}")
            return False
    
    async def execute_action(self, action: SecurityAction) -> bool:
        """Exécute une action sur FortiGate"""
        try:
            if action.action_type == "BLOCK_IP":
                return await self._block_ip(action.target, action.details)
            elif action.action_type == "ISOLATE_HOST":
                return await self._isolate_host(action.target, action.details)
            elif action.action_type == "CREATE_POLICY":
                return await self._create_firewall_policy(action.details)
            else:
                self.logger.warning(f"Unsupported action type: {action.action_type}")
                return False
        except Exception as e:
            self.logger.error(f"Action execution failed: {e}")
            return False
    
    async def _block_ip(self, ip: str, details: Dict) -> bool:
        """Bloque une adresse IP"""
        policy_data = {
            "name": f"RANSOMWARE_BLOCK_{ip}_{int(datetime.now().timestamp())}",
            "srcintf": [{"name": "any"}],
            "dstintf": [{"name": "any"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": f"blocked_ip_{ip.replace('.', '_')}"}],
            "action": "deny",
            "schedule": "always",
            "service": [{"name": "ALL"}],
            "nat": "disable"
        }
        
        # Créer l'objet adresse d'abord
        addr_data = {
            "name": f"blocked_ip_{ip.replace('.', '_')}",
            "subnet": f"{ip} 255.255.255.255",
            "type": "ipmask"
        }
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Créer l'adresse
            async with session.post(
                f"{self.base_url}/cmdb/firewall/address",
                headers=headers,
                json=addr_data,
                ssl=self.verify_ssl
            ) as response:
                if response.status not in [200, 424]:  # 424 = already exists
                    self.logger.error(f"Failed to create address object: {response.status}")
                    return False
            
            # Créer la politique de blocage
            async with session.post(
                f"{self.base_url}/cmdb/firewall/policy",
                headers=headers,
                json=policy_data,
                ssl=self.verify_ssl
            ) as response:
                if response.status == 200:
                    self.logger.info(f"Successfully blocked IP: {ip}")
                    return True
                else:
                    self.logger.error(f"Failed to create blocking policy: {response.status}")
                    return False
    
    async def _isolate_host(self, host_ip: str, details: Dict) -> bool:
        """Isole un hôte du réseau"""
        # Créer une politique restrictive pour l'hôte
        isolation_policy = {
            "name": f"ISOLATION_{host_ip}_{int(datetime.now().timestamp())}",
            "srcintf": [{"name": "any"}],
            "dstintf": [{"name": "any"}],
            "srcaddr": [{"name": f"isolated_host_{host_ip.replace('.', '_')}"}],
            "dstaddr": [{"name": "all"}],
            "action": "deny",
            "schedule": "always",
            "service": [{"name": "ALL"}],
            "comments": f"Ransomware isolation - {details.get('reason', 'Auto-isolation')}"
        }
        
        return await self._create_firewall_policy(isolation_policy)
    
    async def _create_firewall_policy(self, policy_data: Dict) -> bool:
        """Crée une politique firewall"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                async with session.post(
                    f"{self.base_url}/cmdb/firewall/policy",
                    headers=headers,
                    json=policy_data,
                    ssl=self.verify_ssl
                ) as response:
                    return response.status == 200
        except Exception as e:
            self.logger.error(f"Policy creation failed: {e}")
            return False
    
    async def get_status(self) -> Dict:
        """Récupère le statut FortiGate"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with session.get(
                    f"{self.base_url}/cmdb/system/status",
                    headers=headers,
                    ssl=self.verify_ssl
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "system": "FortiGate",
                            "status": "operational",
                            "version": data.get("version", "unknown"),
                            "serial": data.get("serial", "unknown")
                        }
        except Exception as e:
            self.logger.error(f"Status check failed: {e}")
            
        return {"system": "FortiGate", "status": "error"}

class CrowdStrikeIntegration(SecurityIntegration):
    """Intégration CrowdStrike Falcon EDR"""
    
    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.access_token = None
        self.token_expires = None
        self.logger = logging.getLogger(f"{__name__}.CrowdStrike")
    
    async def authenticate(self) -> bool:
        """Authentification CrowdStrike API"""
        try:
            auth_url = f"{self.base_url}/oauth2/token"
            
            async with aiohttp.ClientSession() as session:
                data = {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
                
                async with session.post(auth_url, data=data) as response:
                    if response.status == 201:
                        token_data = await response.json()
                        self.access_token = token_data["access_token"]
                        self.token_expires = datetime.now() + timedelta(seconds=token_data["expires_in"])
                        self.logger.info("CrowdStrike authentication successful")
                        return True
                    else:
                        self.logger.error(f"CrowdStrike auth failed: {response.status}")
                        return False
        except Exception as e:
            self.logger.error(f"CrowdStrike auth error: {e}")
            return False
    
    async def execute_action(self, action: SecurityAction) -> bool:
        """Exécute une action sur CrowdStrike"""
        if not await self._ensure_authenticated():
            return False
            
        try:
            if action.action_type == "ISOLATE_HOST":
                return await self._isolate_host(action.target)
            elif action.action_type == "QUARANTINE_FILE":
                return await self._quarantine_file(action.target, action.details)
            elif action.action_type == "RUN_RTR_COMMAND":
                return await self._run_rtr_command(action.target, action.details.get("command"))
            else:
                self.logger.warning(f"Unsupported action: {action.action_type}")
                return False
        except Exception as e:
            self.logger.error(f"CrowdStrike action failed: {e}")
            return False
    
    async def _ensure_authenticated(self) -> bool:
        """Vérifie et renouvelle l'authentification si nécessaire"""
        if not self.access_token or datetime.now() >= self.token_expires:
            return await self.authenticate()
        return True
    
    async def _isolate_host(self, device_id: str) -> bool:
        """Isole un hôte via CrowdStrike"""
        url = f"{self.base_url}/devices/entities/devices-actions/v2"
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            data = {
                "ids": [device_id],
                "action_name": "contain"
            }
            
            async with session.post(url, headers=headers, json=data) as response:
                if response.status == 202:
                    self.logger.info(f"Host isolation initiated: {device_id}")
                    return True
                else:
                    self.logger.error(f"Host isolation failed: {response.status}")
                    return False
    
    async def _quarantine_file(self, file_hash: str, details: Dict) -> bool:
        """Met en quarantaine un fichier"""
        url = f"{self.base_url}/iocs/entities/indicators/v1"
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            data = {
                "indicators": [{
                    "type": "sha256",
                    "value": file_hash,
                    "policy": "detect",
                    "share_level": "red",
                    "description": f"Ransomware file - {details.get('reason', 'Auto-quarantine')}"
                }]
            }
            
            async with session.post(url, headers=headers, json=data) as response:
                return response.status == 201
    
    async def get_status(self) -> Dict:
        """Récupère le statut CrowdStrike"""
        if not await self._ensure_authenticated():
            return {"system": "CrowdStrike", "status": "authentication_failed"}
            
        try:
            url = f"{self.base_url}/sensors/queries/sensors/v1"
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.access_token}"}
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return {"system": "CrowdStrike", "status": "operational"}
        except Exception as e:
            self.logger.error(f"CrowdStrike status check failed: {e}")
            
        return {"system": "CrowdStrike", "status": "error"}

class AzureSentinelIntegration(SecurityIntegration):
    """Intégration Microsoft Azure Sentinel"""
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, workspace_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.workspace_id = workspace_id
        self.access_token = None
        self.token_expires = None
        self.logger = logging.getLogger(f"{__name__}.AzureSentinel")
    
    async def authenticate(self) -> bool:
        """Authentification Azure AD"""
        try:
            auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"
            
            async with aiohttp.ClientSession() as session:
                data = {
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "resource": "https://management.azure.com/"
                }
                
                async with session.post(auth_url, data=data) as response:
                    if response.status == 200:
                        token_data = await response.json()
                        self.access_token = token_data["access_token"]
                        self.token_expires = datetime.now() + timedelta(seconds=int(token_data["expires_in"]))
                        self.logger.info("Azure Sentinel authentication successful")
                        return True
                    else:
                        self.logger.error(f"Azure auth failed: {response.status}")
                        return False
        except Exception as e:
            self.logger.error(f"Azure auth error: {e}")
            return False
    
    async def execute_action(self, action: SecurityAction) -> bool:
        """Exécute une action sur Azure Sentinel"""
        if not await self._ensure_authenticated():
            return False
            
        try:
            if action.action_type == "CREATE_INCIDENT":
                return await self._create_incident(action.details)
            elif action.action_type == "UPDATE_WATCHLIST":
                return await self._update_watchlist(action.target, action.details)
            elif action.action_type == "TRIGGER_PLAYBOOK":
                return await self._trigger_playbook(action.target, action.details)
            else:
                self.logger.warning(f"Unsupported Azure action: {action.action_type}")
                return False
        except Exception as e:
            self.logger.error(f"Azure Sentinel action failed: {e}")
            return False
    
    async def _ensure_authenticated(self) -> bool:
        """Vérifie et renouvelle l'authentification si nécessaire"""
        if not self.access_token or datetime.now() >= self.token_expires:
            return await self.authenticate()
        return True
    
    async def _create_incident(self, details: Dict) -> bool:
        """Crée un incident Azure Sentinel"""
        url = f"https://management.azure.com/subscriptions/{details['subscription_id']}/resourceGroups/{details['resource_group']}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_id}/providers/Microsoft.SecurityInsights/incidents/{details['incident_id']}"
        
        incident_data = {
            "properties": {
                "title": details.get("title", "Ransomware Incident"),
                "description": details.get("description", "Automated ransomware incident creation"),
                "severity": details.get("severity", "High"),
                "status": "New",
                "classification": "Undetermined",
                "owner": {
                    "assignedTo": details.get("assignee"),
                    "email": details.get("assignee_email")
                }
            }
        }
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            async with session.put(url, headers=headers, json=incident_data) as response:
                return response.status in [200, 201]
    
    async def get_status(self) -> Dict:
        """Récupère le statut Azure Sentinel"""
        if not await self._ensure_authenticated():
            return {"system": "Azure Sentinel", "status": "authentication_failed"}
            
        return {"system": "Azure Sentinel", "status": "operational"}

class SecurityOrchestrator:
    """Orchestrateur central pour les intégrations de sécurité"""
    
    def __init__(self):
        self.integrations: Dict[str, SecurityIntegration] = {}
        self.action_queue = asyncio.Queue()
        self.logger = logging.getLogger(f"{__name__}.SecurityOrchestrator")
        self.running = False
        self.worker_task = None
    
    def add_integration(self, name: str, integration: SecurityIntegration):
        """Ajoute une intégration"""
        self.integrations[name] = integration
        self.logger.info(f"Added integration: {name}")
    
    async def initialize_all(self) -> Dict[str, bool]:
        """Initialise toutes les intégrations"""
        results = {}
        for name, integration in self.integrations.items():
            try:
                success = await integration.authenticate()
                results[name] = success
                if success:
                    self.logger.info(f"Successfully initialized: {name}")
                else:
                    self.logger.error(f"Failed to initialize: {name}")
            except Exception as e:
                self.logger.error(f"Initialization error for {name}: {e}")
                results[name] = False
        return results
    
    async def execute_coordinated_response(self, threat_data: Dict) -> List[SecurityAction]:
        """Exécute une réponse coordonnée basée sur les données de menace"""
        actions = []
        
        # Analyser la menace et déterminer les actions appropriées
        if threat_data.get("type") == "RANSOMWARE_DETECTED":
            # Actions immédiates pour ransomware
            epicenter_ip = threat_data.get("epicenter_ip")
            affected_hosts = threat_data.get("affected_hosts", [])
            malicious_hashes = threat_data.get("file_hashes", [])
            
            # 1. Bloquer l'IP source si disponible
            if epicenter_ip:
                action = SecurityAction(
                    action_type="BLOCK_IP",
                    target=epicenter_ip,
                    priority="CRITICAL",
                    system="FirewallOrchestrator",
                    timestamp=datetime.now(),
                    details={"reason": "Ransomware epicenter", "source": "R3_Detection"}
                )
                actions.append(action)
                await self.action_queue.put(action)
            
            # 2. Isoler les hôtes affectés
            for host in affected_hosts:
                action = SecurityAction(
                    action_type="ISOLATE_HOST",
                    target=host,
                    priority="CRITICAL",
                    system="EDROrchestrator",
                    timestamp=datetime.now(),
                    details={"reason": "Ransomware infection", "isolation_type": "network"}
                )
                actions.append(action)
                await self.action_queue.put(action)
            
            # 3. Quarantaine des fichiers malveillants
            for file_hash in malicious_hashes:
                action = SecurityAction(
                    action_type="QUARANTINE_FILE",
                    target=file_hash,
                    priority="HIGH",
                    system="EDROrchestrator",
                    timestamp=datetime.now(),
                    details={"reason": "Ransomware payload", "hash_type": "sha256"}
                )
                actions.append(action)
                await self.action_queue.put(action)
            
            # 4. Créer un incident Azure Sentinel
            if "azure_sentinel" in self.integrations:
                incident_id = f"RANSOMWARE_{int(datetime.now().timestamp())}"
                action = SecurityAction(
                    action_type="CREATE_INCIDENT",
                    target=incident_id,
                    priority="HIGH",
                    system="AzureSentinel",
                    timestamp=datetime.now(),
                    details={
                        "title": f"Ransomware Attack Detected - {epicenter_ip}",
                        "description": f"Automated detection of ransomware activity. Epicenter: {epicenter_ip}, Affected hosts: {len(affected_hosts)}",
                        "severity": "Critical",
                        "incident_id": incident_id,
                        "subscription_id": threat_data.get("azure_subscription_id"),
                        "resource_group": threat_data.get("azure_resource_group")
                    }
                )
                actions.append(action)
                await self.action_queue.put(action)
        
        return actions
    
    async def start_action_processor(self):
        """Démarre le processeur d'actions asynchrone"""
        if self.running:
            return
            
        self.running = True
        self.worker_task = asyncio.create_task(self._process_actions())
        self.logger.info("Action processor started")
    
    async def stop_action_processor(self):
        """Arrête le processeur d'actions"""
        self.running = False
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Action processor stopped")
    
    async def _process_actions(self):
        """Traite les actions dans la queue"""
        while self.running:
            try:
                # Attendre une action avec timeout
                action = await asyncio.wait_for(self.action_queue.get(), timeout=1.0)
                
                # Déterminer quelle intégration utiliser
                target_integrations = self._determine_target_integrations(action)
                
                # Exécuter l'action sur les intégrations appropriées
                for integration_name in target_integrations:
                    if integration_name in self.integrations:
                        try:
                            action.status = "IN_PROGRESS"
                            success = await self.integrations[integration_name].execute_action(action)
                            
                            if success:
                                action.status = "COMPLETED"
                                self.logger.info(f"Action completed: {action.action_type} on {integration_name}")
                            else:
                                action.status = "FAILED"
                                action.error_message = f"Execution failed on {integration_name}"
                                self.logger.error(f"Action failed: {action.action_type} on {integration_name}")
                                
                        except Exception as e:
                            action.status = "FAILED"
                            action.error_message = str(e)
                            self.logger.error(f"Action error: {action.action_type} on {integration_name}: {e}")
                
            except asyncio.TimeoutError:
                # Timeout normal, continuer la boucle
                continue
            except Exception as e:
                self.logger.error(f"Action processor error: {e}")
    
    def _determine_target_integrations(self, action: SecurityAction) -> List[str]:
        """Détermine quelles intégrations utiliser pour une action"""
        integration_map = {
            "BLOCK_IP": ["fortigate", "firewall"],
            "ISOLATE_HOST": ["crowdstrike", "fortigate", "edr"],
            "QUARANTINE_FILE": ["crowdstrike", "edr"],
            "CREATE_INCIDENT": ["azure_sentinel", "siem"],
            "RUN_RTR_COMMAND": ["crowdstrike", "edr"],
            "UPDATE_WATCHLIST": ["azure_sentinel", "siem"]
        }
        
        possible_integrations = integration_map.get(action.action_type, [])
        available_integrations = []
        
        for integration_name in self.integrations.keys():
            if any(pattern in integration_name.lower() for pattern in possible_integrations):
                available_integrations.append(integration_name)
        
        return available_integrations
    
    async def get_system_status(self) -> Dict:
        """Récupère le statut de tous les systèmes intégrés"""
        status_report = {
            "orchestrator_status": "operational" if self.running else "stopped",
            "integrations": {},
            "queue_size": self.action_queue.qsize(),
            "timestamp": datetime.now().isoformat()
        }
        
        for name, integration in self.integrations.items():
            try:
                status = await integration.get_status()
                status_report["integrations"][name] = status
            except Exception as e:
                status_report["integrations"][name] = {"system": name, "status": "error", "error": str(e)}
        
        return status_report

# Configuration factory
def create_security_orchestrator(config: Dict) -> SecurityOrchestrator:
    """Crée un orchestrateur configuré avec les intégrations spécifiées"""
    orchestrator = SecurityOrchestrator()
    
    # FortiGate
    if "fortigate" in config:
        fg_config = config["fortigate"]
        fortigate = FortiGateIntegration(
            host=fg_config["host"],
            api_key=fg_config["api_key"],
            verify_ssl=fg_config.get("verify_ssl", True)
        )
        orchestrator.add_integration("fortigate", fortigate)
    
    # CrowdStrike
    if "crowdstrike" in config:
        cs_config = config["crowdstrike"]
        crowdstrike = CrowdStrikeIntegration(
            client_id=cs_config["client_id"],
            client_secret=cs_config["client_secret"],
            base_url=cs_config.get("base_url", "https://api.crowdstrike.com")
        )
        orchestrator.add_integration("crowdstrike", crowdstrike)
    
    # Azure Sentinel
    if "azure_sentinel" in config:
        az_config = config["azure_sentinel"]
        azure_sentinel = AzureSentinelIntegration(
            tenant_id=az_config["tenant_id"],
            client_id=az_config["client_id"],
            client_secret=az_config["client_secret"],
            workspace_id=az_config["workspace_id"]
        )
        orchestrator.add_integration("azure_sentinel", azure_sentinel)
    
    return orchestrator

if __name__ == "__main__":
    # Exemple d'utilisation
    async def main():
        # Configuration d'exemple (ne pas utiliser en production)
        config = {
            "fortigate": {
                "host": "192.168.1.1",
                "api_key": "your_api_key_here",
                "verify_ssl": False  # Pour tests uniquement
            },
            "crowdstrike": {
                "client_id": "your_client_id",
                "client_secret": "your_client_secret"
            }
        }
        
        orchestrator = create_security_orchestrator(config)
        
        # Initialiser les intégrations
        init_results = await orchestrator.initialize_all()
        print(f"Initialization results: {init_results}")
        
        # Démarrer le processeur d'actions
        await orchestrator.start_action_processor()
        
        # Simuler une détection de ransomware
        threat_data = {
            "type": "RANSOMWARE_DETECTED",
            "epicenter_ip": "192.168.1.100",
            "affected_hosts": ["192.168.1.101", "192.168.1.102"],
            "file_hashes": ["a1b2c3d4e5f6..."],
            "confidence": 0.95
        }
        
        # Exécuter la réponse coordonnée
        actions = await orchestrator.execute_coordinated_response(threat_data)
        print(f"Executed {len(actions)} security actions")
        
        # Attendre un moment pour le traitement
        await asyncio.sleep(5)
        
        # Vérifier le statut
        status = await orchestrator.get_system_status()
        print(f"System status: {json.dumps(status, indent=2)}")
        
        # Arrêter l'orchestrateur
        await orchestrator.stop_action_processor()
    
    # Exécuter l'exemple
    asyncio.run(main())
