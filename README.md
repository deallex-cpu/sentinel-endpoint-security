# SENTINEL — Endpoint Security Monitoring v2.0

Dashboard de monitoring sécurité endpoint Windows en temps réel.  
Node.js + PowerShell — Interface style Palo Alto / CrowdStrike.

![Version](https://img.shields.io/badge/version-2.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)

## 🛡️ Fonctionnalités

| Module | Description |
|---|---|
| **EDR** | Windows Defender — antivirus, temps réel, signatures |
| **Firewall** | Profils pare-feu Windows — état et règles |
| **DNS** | AdGuard Home — filtrage DNS |
| **IDS** | Suricata — détection d'intrusion réseau |
| **Backup** | Points de restauration VSS — protection ransomware |
| **Réseau** | Ports en écoute, connexions, processus suspects |
| **Événements** | Sysmon + Security Event Log |

## ⚡ Actions de réponse

- Tuer un processus suspect
- Bloquer un port réseau
- Désactiver un programme au démarrage
- Activer le service VSS
- **Kill Switch** — Isoler l'hôte du réseau

## 🚀 Installation

### Prérequis
- Windows 10/11
- Node.js >= 18
- Droits administrateur

### Démarrage rapide
```powershell
# 1. Cloner le repo
git clone https://github.com/deallex-cpu/sentinel-endpoint-security.git
cd sentinel-endpoint-security

# 2. Lancer en mode admin
# Double-cliquer sur LANCER_DASHBOARD.bat
# OU
node server.js
```

### Configuration automatique (tâches planifiées)
```powershell
# PowerShell en administrateur
.\setup_sentinel.ps1
```

## 🔒 Sécurité (v2.0)

- ✅ Authentification par token CSRF
- ✅ Protection XSS (échappement systématique)
- ✅ Rate-limiting (20 actions/minute)
- ✅ Validation stricte des entrées
- ✅ Whitelist des actions autorisées
- ✅ Headers de sécurité (CSP, X-Frame-Options, etc.)
- ✅ Logging/audit de toutes les actions
- ✅ `execFile()` au lieu de `exec()` (anti-injection)
- ✅ Body size limité (2KB)
- ✅ Graceful shutdown

## 📁 Structure

```
├── server.js              # Serveur HTTP sécurisé
├── index.html             # Dashboard (design Palo Alto style)
├── backup_check.ps1       # Check VSS (tâche planifiée)
├── setup_sentinel.ps1     # Configuration des tâches
├── LANCER_DASHBOARD.bat   # Lanceur avec élévation admin
├── start_hidden.vbs       # Exécution cachée du serveur
├── sentinel.config.json   # Configuration (généré auto)
├── sentinel.log           # Log des actions (généré auto)
└── .sentinel-token        # Token CSRF (généré auto)
```

## 📝 Changelog

### v2.0 — Audit de sécurité complet
- Redesign UI (style Palo Alto Cortex / CrowdStrike Falcon)
- Correction de 17 failles de sécurité
- Ajout authentification, rate-limiting, audit trail
- Protection XSS, injection, CSRF
- Lecture Suricata par tail (anti-OOM)
- Configuration externalisée
- Graceful shutdown

### v1.0 — Version initiale
- Dashboard de monitoring endpoint Windows
- Collecte Defender, Firewall, AdGuard, Suricata, VSS
- Actions de réponse (kill, block, isolate)
