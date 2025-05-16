![image](https://github.com/user-attachments/assets/965ca636-8668-4df1-b2e4-e13a5b66a7e1)

# 🛡️ RapidRansomResponder (R3)

Solution CLI de réponse automatisée aux attaques ransomware.

## 🔥 Fonctionnalités

- **Confinement intelligent**: Isolation rapide des machines infectées pour limiter la propagation
- **Collecte de preuves critiques**: Capture automatisée des fichiers, mémoire et logs essentiels
- **Identification automatique des variants**: Analyse heuristique pour détecter le type de ransomware
- **Tentative de déchiffrement**: Application de techniques connues sur les variants identifiés
- **Rapport IR automatisé**: Génération de rapports d'incident détaillés

## 📁 Structure du projet

```
r3/
├── core/
│   ├── core.py
│   ├── detect.py
│   ├── collect.py
│   ├── contain.py
│   ├── decrypt.py
│   ├── report.py
│   └── utils.py
├── r3.py
├── requirements.txt
├── install.sh
└── README.md
```

## 🛠️ Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/RapidRansomResponder.git
cd RapidRansomResponder

# Rendre le script d'installation exécutable
chmod +x install.sh

# Exécuter l'installation
./install.sh
```

## 🚀 Utilisation

```bash
# Format de base
python3 r3.py --epicenter IP_OU_HOSTNAME

# Exemple
python3 r3.py --epicenter 192.168.1.45
```

## 📋 Workflow de réponse aux incidents

1. **Confinement**: Isolation de la machine infectée via pare-feu
2. **Collecte**: Récupération des preuves numériques (fichiers, dump mémoire, logs)
3. **Analyse**: Identification du variant ransomware
4. **Réponse**: Tentative de déchiffrement ou génération de rapport selon le variant

## 🧠 Roadmap

- [ ] Détection comportementale live (CPU/RAM)
- [ ] Intégration firewall/EDR/API cloud
- [ ] R3 Dashboard : Electron + React
- [ ] Identification avancée basée sur Machine Learning
- [ ] Intégration avec bases de données de rançongiciels connues

## 📄 Licence

Ce projet est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## ⚠️ Avertissement

Cet outil est destiné aux professionnels de la sécurité informatique et ne doit être utilisé que dans un cadre légal pour répondre à des incidents de sécurité. Toute utilisation abusive est strictement interdite.
