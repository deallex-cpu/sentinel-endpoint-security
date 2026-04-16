# 🛠️ GUIDE D'INSTALLATION — SENTINEL v3.0

> Ce guide explique comment installer SENTINEL v3.0 depuis zéro
> OU comment migrer depuis l'ancienne version (v1).

---

## ❓ C'EST QUOI SENTINEL v3.0 ?

SENTINEL est une plateforme de sécurité endpoint pour Windows.
Elle tourne en local sur ta machine (localhost:8888) et surveille:
- Antivirus Defender, Pare-feu, DNS (AdGuard), IDS (Suricata)
- Ports réseau, connexions, programmes au démarrage
- **NOUVEAU v3:** Intégrité fichiers, ransomware canary, hardening,
  threat intelligence, USB, analyse comportementale, réponse automatique

---

## 📝 PRÉREQUIS

- **Windows 10 ou 11**
- **Node.js 18+** — Télécharger: https://nodejs.org/
- **Droits administrateur** (clic droit → Exécuter en tant qu'admin)
- **Git** (optionnel mais recommandé) — Télécharger: https://git-scm.com/

### Vérifier que Node.js est installé
Ouvrir un terminal (cmd ou PowerShell) et taper:
```
node --version
```
Si ça affiche `v18.x.x` ou plus → c'est bon.
Sinon → installer Node.js depuis le lien ci-dessus.

---

## 🆕 INSTALLATION PROPRE (PREMIÈRE FOIS)

### Étape 1 : Télécharger SENTINEL

**Option A — Avec Git (recommandé):**
```powershell
cd C:\Users\Utilisateur\Desktop
mkdir SECURITE_ORDI
cd SECURITE_ORDI
git clone https://github.com/deallex-cpu/sentinel-endpoint-security.git dashboard
cd dashboard
```

**Option B — Sans Git (téléchargement ZIP):**
1. Aller sur https://github.com/deallex-cpu/sentinel-endpoint-security
2. Cliquer le bouton vert **"Code"** → **"Download ZIP"**
3. Extraire le ZIP sur le Bureau dans `SECURITE_ORDI\dashboard`

### Étape 2 : Lancer SENTINEL

**Option simple — Double-clic:**
1. Aller dans le dossier `dashboard`
2. Double-cliquer sur **`LANCER_DASHBOARD.bat`**
3. Accepter l'élévation administrateur
4. Le navigateur s'ouvre automatiquement sur http://localhost:8888

**Option manuelle — Terminal:**
```powershell
# Ouvrir PowerShell en ADMINISTRATEUR
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard
node server.js
```

### Étape 3 : Configuration des tâches automatiques (optionnel)

Pour que SENTINEL démarre automatiquement à chaque ouverture de session:
```powershell
# PowerShell en ADMINISTRATEUR
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard
.\setup_sentinel.ps1
```

### Étape 4 : Vérifier que tout fonctionne

1. Ouvrir http://localhost:8888 dans le navigateur
2. Vérifier que le score de posture s'affiche (en haut à gauche)
3. Vérifier que les modules s'affichent dans la sidebar gauche
4. Les fichiers suivants sont créés automatiquement:
   - `sentinel.config.json` — configuration
   - `.sentinel-token` — token de sécurité (NE PAS SUPPRIMER)
   - `sentinel.log` — journal des actions
   - `fim_baseline.json` — baseline intégrité fichiers
   - `behavioral_baseline.json` — baseline comportementale
   - `canary_files/` — dossier de fichiers piège anti-ransomware
   - `threat_ips.txt` — liste d'IPs malicieuses

---

## 🔄 MIGRATION DEPUIS L'ANCIENNE VERSION (v1 → v3)

### Étape 1 : Arrêter l'ancien SENTINEL

```powershell
# Trouver et tuer le processus node.js de l'ancien SENTINEL
taskkill /F /IM node.exe
```

OU fermer la fenêtre CMD/PowerShell où l'ancien SENTINEL tourne.

### Étape 2 : Sauvegarder l'ancienne version

```powershell
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI

# Renommer l'ancien dossier (le garder au cas où)
Rename-Item -Path "dashboard" -NewName "dashboard_OLD_v1"
```

### Étape 3 : Télécharger la nouvelle version

**Avec Git:**
```powershell
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI
git clone https://github.com/deallex-cpu/sentinel-endpoint-security.git dashboard
cd dashboard
```

**Sans Git:**
1. Aller sur https://github.com/deallex-cpu/sentinel-endpoint-security
2. Cliquer **"Code"** → **"Download ZIP"**
3. Extraire dans `SECURITE_ORDI\dashboard`

### Étape 4 : Récupérer le fichier backup de l'ancienne version

Si tu avais la tâche planifiée `SENTINEL-Backup` qui générait
`backup_status.json`, tu peux le copier:
```powershell
Copy-Item "C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard_OLD_v1\backup_status.json" `
  -Destination "C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard\" -EA SilentlyContinue
```

### Étape 5 : Supprimer les anciennes tâches planifiées

```powershell
# PowerShell en ADMINISTRATEUR
Unregister-ScheduledTask -TaskName 'SENTINEL-Server' -Confirm:$false -EA SilentlyContinue
Unregister-ScheduledTask -TaskName 'SENTINEL-Backup' -Confirm:$false -EA SilentlyContinue
```

### Étape 6 : Reconfigurer les tâches planifiées (v3)

```powershell
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard
.\setup_sentinel.ps1
```

### Étape 7 : Lancer SENTINEL v3

Double-cliquer sur **`LANCER_DASHBOARD.bat`**
OU:
```powershell
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard
node server.js
```

### Étape 8 : Vérifier la migration

1. Ouvrir http://localhost:8888
2. Vérifier que la **sidebar** s'affiche à gauche (nouveau design)
3. Vérifier les nouveaux modules:
   - **Menaces** → doit montrer les risques actifs
   - **Vue d'ensemble** → doit montrer toutes les cards
   - Score posture avec **8 catégories** (au lieu de 5)
4. Après 30 secondes, le scanner IOC se lance automatiquement
5. Après 10 cycles (5 minutes), la baseline comportementale sera active

### Étape 9 : Supprimer l'ancienne version (une fois que tout marche)

```powershell
# SEULEMENT quand tu es sûr que la v3 fonctionne bien !
Remove-Item -Path "C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard_OLD_v1" -Recurse -Force
```

---

## ⚙️ CONFIGURATION

Au premier lancement, SENTINEL crée automatiquement le fichier
`sentinel.config.json`. Tu peux le modifier pour adapter:

```json
{
  "port": 8888,
  "host": "127.0.0.1",
  "suricataEvePath": "C:\\ProgramData\\Suricata\\log\\eve.json",
  "fimEnabled": true,
  "canaryEnabled": true,
  "autoResponseEnabled": true,
  "hardeningEnabled": true,
  "threatIntelEnabled": true,
  "usbMonitorEnabled": true,
  "behavioralEnabled": true,
  "scannerEnabled": true
}
```

**Pour désactiver un module**, mettre `false` à côté de son nom.
**Redémarrer SENTINEL** après modification du fichier config.

---

## 🚨 FICHIERS CANARY ANTI-RANSOMWARE

SENTINEL crée automatiquement un dossier `canary_files/` avec
des fichiers piège (faux documents). Si un ransomware les chiffre
ou les supprime, SENTINEL **isole automatiquement la machine**
du réseau.

**⚠️ NE PAS TOUCHER aux fichiers dans `canary_files/`**
- Ne pas les ouvrir
- Ne pas les modifier
- Ne pas les supprimer
- Ne pas les déplacer

Si tu déclenches le canary par accident:
1. Le dashboard affichera **CANARY DÉCLENCHÉ**
2. La machine sera isolée du réseau
3. Cliquer **"Lever l'isolation"** dans le dashboard
4. Aller dans **Menaces** → cliquer **"Réinitialiser Canary"**

---

## 🔧 DÉPANNAGE

### Le dashboard ne s'ouvre pas
```powershell
# Vérifier que Node.js fonctionne
node --version

# Vérifier que le port 8888 n'est pas utilisé
netstat -an | findstr 8888

# Lancer manuellement pour voir les erreurs
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard
node server.js
```

### Erreur "Token invalide"
Supprimer le fichier `.sentinel-token` et redémarrer SENTINEL.
Un nouveau token sera généré automatiquement.
```powershell
Remove-Item ".sentinel-token" -EA SilentlyContinue
node server.js
```

### La machine est isolée par erreur
```powershell
# Supprimer les règles firewall SENTINEL
Remove-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-IN' -EA SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-OUT' -EA SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SENTINEL-ALLOW-LOOPBACK' -EA SilentlyContinue
```

### Réinitialiser tout
```powershell
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard

# Supprimer tous les fichiers générés
Remove-Item sentinel.config.json -EA SilentlyContinue
Remove-Item .sentinel-token -EA SilentlyContinue
Remove-Item sentinel.log -EA SilentlyContinue
Remove-Item fim_baseline.json -EA SilentlyContinue
Remove-Item behavioral_baseline.json -EA SilentlyContinue
Remove-Item auto_response.log -EA SilentlyContinue
Remove-Item threat_ips.txt -EA SilentlyContinue
Remove-Item canary_files -Recurse -EA SilentlyContinue

# Redémarrer
node server.js
```

---

## 📁 STRUCTURE DES FICHIERS

```
dashboard/
├── server.js                # Serveur principal (10 modules)
├── index.html               # Dashboard (interface web)
├── LANCER_DASHBOARD.bat     # Lanceur rapide (double-clic)
├── setup_sentinel.ps1       # Config tâches planifiées
├── backup_check.ps1         # Vérification VSS
├── start_hidden.vbs         # Lancement caché
├── INSTALL.md               # Ce guide
├── README.md                # Documentation générale
│
├── [GÉNÉRÉS AUTOMATIQUEMENT]
├── sentinel.config.json     # Configuration (modifiable)
├── .sentinel-token          # Token sécurité (NE PAS TOUCHER)
├── sentinel.log             # Journal des actions
├── auto_response.log        # Journal réponses automatiques
├── fim_baseline.json        # Baseline intégrité fichiers
├── behavioral_baseline.json # Baseline comportementale
├── threat_ips.txt           # Cache IPs malicieuses
├── backup_status.json       # Status VSS (via tâche planifiée)
└── canary_files/            # Fichiers piège anti-ransomware
    ├── Budget_2024.xlsx
    ├── Passwords_backup.docx
    ├── Company_Keys.pdf
    ├── Client_Database.csv
    └── Financial_Report.xlsx
```

---

## 🛡️ LES 10 MODULES EXPLIQUÉS

| # | Module | Ce qu'il fait | Automatique ? |
|---|--------|---------------|---------------|
| 1 | **Auto-Response** | Isole la machine si intrusion détectée | ✅ Oui |
| 2 | **IOC Scanner** | Cherche des malwares/virus sur la machine | ✅ Toutes les 30 min |
| 3 | **FIM** | Vérifie que les fichiers Windows n'ont pas été modifiés | ✅ Chaque cycle |
| 4 | **Ransomware Canary** | Détecte un ransomware en < 30 secondes | ✅ Chaque cycle |
| 5 | **Hardening** | Note ta machine sur sa sécurité (score /100) | ✅ Chaque cycle |
| 6 | **Threat Intel** | Vérifie si tu parles à des IPs de hackers | ✅ Refresh 6h |
| 7 | **USB Monitor** | Détecte quand une clé USB est branchée | ✅ Chaque cycle |
| 8 | **Process Tree** | Montre quel programme a lancé quel autre | ✅ Chaque cycle |
| 9 | **Behavioral AI** | Apprend ton utilisation normale et détecte les anomalies | ✅ Après 10 cycles |
| 10 | **Playbooks** | Règles automatiques: SI menace ALORS action | ✅ Oui |

---

## ❓ FAQ

**Q: Est-ce que ça ralentit mon PC ?**
R: Non. SENTINEL utilise ~30 Mo de RAM et fait ses vérifications
toutes les 30 secondes. Entre les vérifications, il ne fait rien.

**Q: Est-ce que ça remplace un antivirus ?**
R: Non. SENTINEL SURVEILLE ton antivirus (Defender) et tes autres
outils de sécurité. C'est un dashboard de monitoring, pas un antivirus.
Il ajoute des couches de protection que Defender n'a pas
(canary, FIM, behavioral, threat intel).

**Q: C'est quoi le score de posture ?**
R: Un score sur 100 qui résume l'état de sécurité de ta machine.
- 80-100 = Excellent (vert)
- 60-79 = Correct mais améliorable (orange)
- 0-59 = Problèmes à régler (rouge)

**Q: C'est quoi l'isolation d'hôte ?**
R: Le bouton d'urgence qui coupe TOUT internet sur ta machine.
Utile si tu détectes une intrusion. Le dashboard reste accessible
car il tourne en local (localhost). Tu peux lever l'isolation
en un clic quand le danger est passé.

**Q: Qu'est-ce qui se passe si le canary se déclenche ?**
R: SENTINEL isole immédiatement ta machine du réseau pour
empêcher le ransomware de se propager. Tu gardes accès au
dashboard pour voir ce qui s'est passé.
