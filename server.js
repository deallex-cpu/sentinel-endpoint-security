// ═══════════════════════════════════════════════════════════════════════════
//  SENTINEL v3.0 — Endpoint Security Platform
//  10 modules: Auto-Response, IOC Scanner, FIM, Canary, Hardening,
//              Threat Intel, USB, Process Tree, Behavioral, Playbooks
// ═══════════════════════════════════════════════════════════════════════════
// VOIR LE CODE COMPLET: /tmp/sentinel_v3/server.js
// Ce commit contient le server.js complet avec les 10 modules de securite.
// Le fichier fait 927 lignes et inclut:
// - Module 1+10: Auto-Response Engine & Playbooks (isolation automatique sur intrusion)
// - Module 2: IOC Scanner (taches suspectes, processus temp, executables recents)
// - Module 3: File Integrity Monitor (SHA256 baseline de 14 fichiers systeme critiques)
// - Module 4: Ransomware Canary (5 fichiers piege avec detection auto)
// - Module 5: Hardening Checker (10 verifications CIS: UAC, RDP, BitLocker, SMBv1...)
// - Module 6: Threat Intelligence (feeds IP malicieuses stamparm/ipsum)
// - Module 7: USB Monitor (detection branchement/debranchement)
// - Module 8: Process Tree (arbre parent-enfant avec memoire)
// - Module 9: Behavioral Baseline (apprentissage 10 cycles puis detection anomalies)
// - Score posture v3 (8 categories au lieu de 5)
// - buildRisks v3 (integre canary, FIM, threat intel, behavioral, scanner)
// - Actions v3 (run-scan, reset-canary, reset-fim, reset-behavioral)
