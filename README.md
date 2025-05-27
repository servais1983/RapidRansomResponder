![image](https://github.com/user-attachments/assets/965ca636-8668-4df1-b2e4-e13a5b66a7e1)

# 🛡️ RapidRansomResponder (R3) Enhanced v2.0

**Solution CLI avancée de réponse automatisée aux attaques ransomware avec modules d'intelligence artificielle et intégrations de sécurité professionnelles.**

## 🚀 Nouveautés v2.0

### ✅ Détection Comportementale en Temps Réel
- Surveillance CPU/RAM/IO avec seuils adaptatifs
- Détection d'anomalies basée sur l'apprentissage des patterns normaux
- Alertes en temps réel avec niveaux de confiance

### 🔗 Intégrations Sécurité Professionnelles
- **FortiGate** : Blocage automatique d'IPs et isolation réseau
- **CrowdStrike Falcon** : Quarantaine de fichiers et commandes RTR
- **Azure Sentinel** : Création d'incidents et déclenchement de playbooks

### 🧠 Identification ML Avancée
- Classification automatique des familles de ransomware
- Analyse heuristique avec règles YARA
- Base de données taxonomique des variants connus
- Recommandations de réponse spécifiques par famille

### 📊 Rapports Enrichis
- Timeline détaillée des phases d'incident
- Analyse de l'efficacité du confinement
- Recommandations personnalisées
- Export JSON pour intégration SIEM

## 🔥 Fonctionnalités Core

- **Confinement intelligent** : Isolation rapide avec orchestration multi-systèmes
- **Collecte de preuves critiques** : Capture automatisée enrichie avec métriques comportementales
- **Identification automatique** : Analyse ML + signatures pour détecter les variants
- **Tentative de déchiffrement** : Application de techniques connues sur variants identifiés
- **Rapport IR automatisé** : Génération de rapports d'incident professionnels

## 📁 Architecture Enhanced

```
r3/
├── core/
│   ├── behavioral_detection.py    # 🆕 Surveillance temps réel
│   ├── security_integrations.py   # 🆕 Orchestrateur sécurité
│   ├── ml_identification.py       # 🆕 IA classification
│   ├── core.py                    # Moteur principal
│   ├── detect.py                  # Détection signatures
│   ├── collect.py                 # Collecte evidence
│   ├── contain.py                 # Confinement
│   ├── decrypt.py                 # Déchiffrement
│   ├── report.py                  # Rapports
│   └── utils.py                   # Utilitaires
├── r3_enhanced.py                 # 🆕 Point d'entrée v2.0
├── r3_config.py                   # 🆕 Gestionnaire config
├── r3.py                          # Point d'entrée classique
├── requirements.txt               # Dépendances
├── install.sh                     # Installation
└── README.md
```

## 🛠️ Installation

### Installation Rapide
```bash
# Cloner le dépôt
git clone https://github.com/servais1983/RapidRansomResponder.git
cd RapidRansomResponder

# Installation automatique
chmod +x install.sh
./install.sh
```

### Installation Manuelle
```bash
# Installer les dépendances
pip install -r requirements.txt

# Créer la configuration
python r3_config.py create-example
cp r3_config_example.json r3_config.json

# Éditer la configuration selon vos besoins
nano r3_config.json
```

## 🚀 Utilisation Enhanced

### Mode Standard (Réponse Complète)
```bash
# Réponse incident complète avec tous les modules
python r3_enhanced.py --epicenter 192.168.1.45

# Vérifier le statut du système
python r3_enhanced.py --status

# Afficher la configuration
python r3_enhanced.py --config
```

### Mode Classique (Compatibilité)
```bash
# Mode original (sans modules avancés)
python r3.py --epicenter 192.168.1.45
```

## ⚙️ Configuration Avancée

### Créer une configuration personnalisée
```bash
python r3_config.py create-example
```

### Exemple de configuration (r3_config.json)
```json
{
  "behavioral_detection": {
    "enabled": true,
    "sampling_interval": 1.0,
    "thresholds": {
      "cpu_spike": 80.0,
      "memory_spike": 85.0,
      "disk_io_anomaly": 50000000
    }
  },
  "security_integrations": {
    "enabled": true,
    "fortigate": {
      "enabled": true,
      "host": "192.168.1.1",
      "api_key": "YOUR_API_KEY"
    },
    "crowdstrike": {
      "enabled": true,
      "client_id": "YOUR_CLIENT_ID",
      "client_secret": "YOUR_CLIENT_SECRET"
    }
  },
  "ml_identification": {
    "enabled": true,
    "yara_rules_enabled": true,
    "cache_enabled": true
  }
}
```

## 📋 Workflow de Réponse Enhanced

### Phase 1: Détection Avancée
- Analyse comportementale temps réel (CPU/RAM/IO)
- Corrélation avec patterns d'attaque connus
- Génération d'alertes avec niveau de confiance

### Phase 2: Confinement Intelligent  
- Isolation traditionnelle (firewall local)
- Orchestration automatique multi-systèmes
- Blocage coordonné (FortiGate, EDR, Cloud)

### Phase 3: Collecte Enrichie
- Evidence forensique classique
- Métriques comportementales
- Snapshots système complets

### Phase 4: Identification ML
- Classification par famille de ransomware
- Analyse heuristique avec YARA
- Scoring de confiance multi-facteurs

### Phase 5: Réponse Coordonnée
- Stratégie adaptée selon famille identifiée
- Tentative de déchiffrement si outils disponibles
- Actions automatisées via intégrations

### Phase 6: Rapport Professionnel
- Timeline détaillée de l'incident
- Analyse d'efficacité du confinement  
- Recommandations spécifiques
- Export pour intégration SIEM

## 🧠 Familles de Ransomware Supportées

| Famille | Variantes | Outils Déchiffrement | Niveau Menace |
|---------|-----------|---------------------|---------------|
| WannaCry | WCry, WanaCrypt0r | WanaKiwi, wannakey | CRITIQUE |
| Locky | Diablo6, Thor, Asgard2 | Aucun | ÉLEVÉ |
| Ryuk | Hermes | Aucun | CRITIQUE |
| Conti | v2, v3 | Aucun | CRITIQUE |
| LockBit | 2.0, 3.0, Black | Aucun | CRITIQUE |

## 🔗 Intégrations Supportées

### Firewalls
- **FortiGate** : Blocage IP, isolation hôte, politiques firewall
- Support API REST avec authentification sécurisée

### EDR/XDR  
- **CrowdStrike Falcon** : Quarantaine fichiers, isolation hôte, commandes RTR
- Gestion automatique des IoCs

### SIEM/SOAR
- **Azure Sentinel** : Création incidents, mise à jour watchlists
- Déclenchement de playbooks automatiques

## 📊 Métriques et Monitoring

### Surveillance Comportementale
- **CPU** : Détection de pics prolongés (>80%)
- **Mémoire** : Surveillance utilisation RAM (>85%)  
- **I/O Disque** : Détection chiffrement massif (>50MB/s)
- **Réseau** : Anomalies connexions (>50 simultanées)
- **Processus** : Création rapide (>10/minute)

### Indicateurs d'Efficacité
- Temps de détection moyen
- Efficacité du confinement (0-100%)
- Taux de classification correcte
- Temps de réponse total

## 🛡️ Sécurité et Conformité

### Chiffrement
- Communications API sécurisées (TLS 1.3)
- Stockage sécurisé des credentials
- Validation des certificats

### Logging et Audit
- Journalisation complète des actions
- Traçabilité des décisions automatiques
- Export conformité (JSON, SIEM)

### Permissions
- Principe du moindre privilège
- Authentification multi-facteurs supportée
- Séparation des rôles

## 📈 Cas d'Usage Professionnels

### SOC Niveau 1
- Réponse automatique 24/7
- Escalade intelligente
- Réduction MTTR (Mean Time To Response)

### CSIRT/CERT
- Investigation forensique enrichie
- Corrélation multi-sources
- Rapports exécutifs automatiques

### MSP/MSSP
- Réponse multi-clients
- Tableaux de bord centralisés
- SLA garantis

## 🔧 Développement et Extensibilité

### Architecture Modulaire
- Plugins pour nouvelles intégrations
- API REST pour intégration externe
- Hooks pour personnalisations

### Modèles ML Personnalisés
- Entraînement sur données internes
- Adaptation aux environnements spécifiques
- Amélioration continue

## 📄 Licence et Support

Ce projet est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

### Support Professionnel
- Documentation complète : [Wiki du projet]
- Issues GitHub pour bugs/features
- Communauté active sur Discord

## ⚠️ Avertissement Légal

Cet outil est destiné exclusivement aux professionnels de la sécurité informatique et ne doit être utilisé que dans un cadre légal pour répondre à des incidents de sécurité. Toute utilisation abusive est strictement interdite.

L'utilisation de R3 Enhanced implique la manipulation de systèmes critiques et d'intégrations sécurité. Assurez-vous de tester en environnement contrôlé avant déploiement production.

## 🤝 Contribution

Les contributions sont bienvenues ! Voir [CONTRIBUTING.md] pour les guidelines.

### Roadmap Ouverte
- [ ] Dashboard Web (Electron + React)
- [ ] Intégration Splunk/QRadar
- [ ] Module Threat Intelligence
- [ ] Déchiffrement cloud assisté
- [ ] Mobile app pour alertes

---

**RapidRansomResponder Enhanced - Votre première ligne de défense contre les ransomwares.** 🛡️
