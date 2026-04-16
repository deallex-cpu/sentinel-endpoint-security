# ============================================================
#  SENTINEL — Setup complet des tâches planifiées
#  DOIT ÊTRE LANCÉ DANS UN POWERSHELL ADMINISTRATEUR
# ============================================================

$dashPath = 'C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard'
$nodePath = 'C:\Program Files\nodejs\node.exe'
$user     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# --- Vérification admin ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host ''
  Write-Host '  ERREUR : Ce script doit être lancé en tant qu administrateur !' -ForegroundColor Red
  Write-Host '  Clic droit sur PowerShell > Exécuter en tant qu administrateur' -ForegroundColor Yellow
  Write-Host ''
  pause
  exit 1
}

Write-Host ''
Write-Host '  ========================================' -ForegroundColor Cyan
Write-Host '    SENTINEL — Configuration automatique' -ForegroundColor Cyan
Write-Host '  ========================================' -ForegroundColor Cyan
Write-Host ''
# ===========================================
#  TÂCHE 1 : SENTINEL-Server (logon)
#  Lance le serveur Node.js au démarrage, caché
# ===========================================
Write-Host '  [1/2] Configuration SENTINEL-Server...' -ForegroundColor Yellow

$taskServer = 'SENTINEL-Server'
Unregister-ScheduledTask -TaskName $taskServer -Confirm:$false -ErrorAction SilentlyContinue

$vbsPath = Join-Path $dashPath 'start_hidden.vbs'

$actionServer  = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "`"$vbsPath`""
$triggerServer = New-ScheduledTaskTrigger -AtLogOn -User $user

# Pas besoin de droits admin pour le serveur Node
$settingsServer = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Hours 0)

Register-ScheduledTask `
  -TaskName $taskServer `
  -Action $actionServer `
  -Trigger $triggerServer `
  -Settings $settingsServer `
  -Description 'Lance le dashboard SENTINEL au démarrage de session' `
  -Force | Out-Null

$stateServer = (Get-ScheduledTask -TaskName $taskServer -EA SilentlyContinue).State
Write-Host "  [OK] $taskServer : $stateServer" -ForegroundColor Green
Write-Host ''
# ===========================================
#  TÂCHE 2 : SENTINEL-Backup (toutes les 5 min, admin)
#  Vérifie l'état des sauvegardes VSS
# ===========================================
Write-Host '  [2/2] Configuration SENTINEL-Backup...' -ForegroundColor Yellow

$taskBackup = 'SENTINEL-Backup'
Unregister-ScheduledTask -TaskName $taskBackup -Confirm:$false -ErrorAction SilentlyContinue

$scriptPath   = Join-Path $dashPath 'backup_check.ps1'
$actionBackup = New-ScheduledTaskAction `
  -Execute 'powershell.exe' `
  -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""

$triggerBackup = New-ScheduledTaskTrigger `
  -RepetitionInterval (New-TimeSpan -Minutes 5) `
  -Once -At (Get-Date)

$settingsBackup = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

# RunLevel Highest = droits admin pour accéder aux points de restauration
Register-ScheduledTask `
  -TaskName $taskBackup `
  -Action $actionBackup `
  -Trigger $triggerBackup `
  -Settings $settingsBackup `
  -RunLevel Highest `
  -Description 'Vérifie les sauvegardes VSS toutes les 5 minutes (admin)' `
  -Force | Out-Null

$stateBackup = (Get-ScheduledTask -TaskName $taskBackup -EA SilentlyContinue).State
Write-Host "  [OK] $taskBackup : $stateBackup" -ForegroundColor Green
Write-Host ''
# ===========================================
#  Lancement immédiat du backup check
# ===========================================
Write-Host '  Exécution immédiate de backup_check.ps1...' -ForegroundColor Yellow
& powershell.exe -ExecutionPolicy Bypass -File $scriptPath
Write-Host ''

# --- Vérification finale ---
$jsonPath = Join-Path $dashPath 'backup_status.json'
if (Test-Path $jsonPath) {
  $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
  Write-Host '  === RÉSULTAT ===' -ForegroundColor Cyan
  Write-Host "  Points de restauration : $($data.vssCount)" -ForegroundColor White
  Write-Host "  Dernier backup         : $($data.lastBackup)" -ForegroundColor White
  Write-Host "  Age (heures)           : $($data.lastBackupAge)" -ForegroundColor White
  Write-Host "  Service VSS            : $($data.vssService)" -ForegroundColor White
  Write-Host ''
}

Write-Host '  ========================================' -ForegroundColor Green
Write-Host '    SENTINEL configuré avec succès !' -ForegroundColor Green
Write-Host '    Le serveur démarrera automatiquement' -ForegroundColor Green
Write-Host '    au prochain logon.' -ForegroundColor Green
Write-Host '  ========================================' -ForegroundColor Green
Write-Host ''
pause
