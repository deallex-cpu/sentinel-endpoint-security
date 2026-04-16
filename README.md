# SENTINEL — Endpoint Security Platform v3.0

Plateforme de sécurité endpoint Windows en temps réel.  
Node.js + PowerShell — 10 modules de protection — Interface style Palo Alto / CrowdStrike.

![Version](https://img.shields.io/badge/version-3.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)
![Modules](https://img.shields.io/badge/modules-10-purple)

## 🚀 Démarrage rapide

```powershell
# 1. Cloner
git clone https://github.com/deallex-cpu/sentinel-endpoint-security.git
cd sentinel-endpoint-security

# 2. Lancer (en admin)
node server.js
# OU double-cliquer LANCER_DASHBOARD.bat
```

📖 **Guide complet d'installation et migration:** voir [INSTALL.md](INSTALL.md)

## 🛡️ 10 Modules de Sécurité

| Module | Description | Auto |
|--------|-------------|------|
| **Auto-Response** | Isole la machine si intrusion détectée | ✅ |
| **IOC Scanner** | Détecte malwares, fichiers suspects, tâches piégées | ✅ |
| **File Integrity** | Vérifie intégrité de 14 fichiers système critiques | ✅ |
| **Ransomware Canary** | 5 fichiers piège → détection en < 30s | ✅ |
| **Hardening** | Score sécurité Windows (10 checks CIS) | ✅ |
| **Threat Intel** | Vérifie IPs contre feeds malicieux | ✅ |
| **USB Monitor** | Détecte branchements USB | ✅ |
| **Process Tree** | Arbre parent-enfant des processus | ✅ |
| **Behavioral AI** | Baseline comportementale + détection anomalies | ✅ |
| **Playbooks** | Règles SI/ALORS automatiques | ✅ |

## ⚡ Réponse automatique aux intrusions

| Déclencheur | Action automatique |
|-------------|--------------------|
| Canary modifié/supprimé | **Isolation réseau immédiate** |
| Alerte Suricata critique | **Isolation réseau** |
| Connexion vers IP malicieuse | **Kill du processus** |
| Spike de connexions inconnues | **Kill des processus inconnus** |
| Fichier système supprimé | **Alerte critique** |

## 🔒 Sécurité du dashboard

- Token CSRF sur toutes les actions
- Protection XSS complète
- Rate-limiting (30 actions/min)
- Validation stricte des entrées
- Headers sécurité (CSP, X-Frame-Options)
- Logging/audit complet
- `execFile()` anti-injection
- Body size limité (4KB)
- Graceful shutdown

## 🎨 Interface

- Design style **Palo Alto Cortex / CrowdStrike Falcon**
- Sidebar navigation avec icônes
- Font Inter (Google Fonts)
- Score posture en temps réel (8 catégories)
- Badges de sévérité (CRITIQUE, ELEVE, MOYEN, FAIBLE)
- Kill switch (isolation d'urgence)

## 📝 Changelog

### v3.0 — Plateforme complète (10 modules)
- Auto-Response Engine + Playbooks
- IOC Scanner (5 types de checks)
- File Integrity Monitor (14 fichiers critiques)
- Ransomware Canary (5 fichiers piège)
- Hardening Checker (10 checks CIS)
- Threat Intelligence (feed stamparm/ipsum)
- USB Device Monitor
- Process Tree
- Behavioral Baseline + Anomaly Detection
- Score posture v3 (8 catégories)

### v2.0 — Audit sécurité
- Redesign UI (Palo Alto style)
- 17 failles de sécurité corrigées
- Token CSRF, rate-limiting, audit trail

### v1.0 — Version initiale
- Dashboard monitoring Defender, Firewall, Suricata, VSS
- Actions manuelles (kill, block, isolate)
