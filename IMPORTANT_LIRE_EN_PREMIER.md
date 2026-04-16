# ⚠️ LIRE EN PREMIER AVANT D'INSTALLER

## Les fichiers `server.js` et `index.html` sur ce repo sont des PLACEHOLDERS

Les vrais fichiers étaient trop gros pour l'API GitHub.
Les fichiers complets t'ont été donnés dans la session Claude.

---

## 📥 LES 2 FICHIERS À RÉCUPÉRER

| Fichier | Taille | Ce que c'est |
|---|---|---|
| **`server.js`** | 927 lignes / 58 KB | Backend complet, 10 modules de sécurité |
| **`index.html`** | 553 lignes / 48 KB | Dashboard complet, 13 panels, design Palo Alto |

## 📝 INSTALLATION EN 5 MINUTES

### 1. Télécharger ce repo
```powershell
cd C:\Users\Utilisateur\Desktop\SECURITE_ORDI
git clone https://github.com/deallex-cpu/sentinel-endpoint-security.git dashboard
cd dashboard
git checkout v2-security-fix-redesign
```

### 2. Copier les VRAIS fichiers
Depuis les outputs de la session Claude, copier:
- `server.js` → dans le dossier `dashboard/` (remplace le placeholder)
- `index.html` → dans le dossier `dashboard/` (remplace le placeholder)

### 3. Lancer
```powershell
node server.js
```
OU double-cliquer sur `LANCER_DASHBOARD.bat`

### 4. Vérifier
- Ouvrir http://localhost:8888
- Tu dois voir une **sidebar à gauche** avec 13 sections
- Le terminal doit afficher `SENTINEL v3.0 — 10 modules actifs`

---

## 🔍 COMMENT VÉRIFIER QUE TU AS LE BON FICHIER

**server.js** → doit commencer par:
```
// SENTINEL v3.0 — Endpoint Security Platform
// 10 modules: Auto-Response, IOC Scanner, FIM, Canary...
```
ET faire 927 lignes.

**index.html** → doit contenir dans la sidebar:
- Vue d'ensemble, Menaces, FIM + Canary, Hardening
- Scanner IOC, Comportement, Ports, Connexions
- Démarrage, Événements, Suricata, USB, Processus, Auto-Réponse

Si ton `server.js` fait moins de 50 lignes → c'est le placeholder.
Si ton `index.html` n'a pas de sidebar → c'est l'ancien design.

---

Pour le guide complet (migration v1→v3, dépannage, FAQ): voir [INSTALL.md](INSTALL.md)
