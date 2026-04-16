$taskName = 'SENTINEL-Backup'
$scriptPath = 'C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard\backup_check.ps1'

# Supprimer si existe
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Créer sans $settings pour éviter le bug
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -WindowStyle Hidden -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -RunLevel Highest -Force | Out-Null
Write-Output "Tache cree: $(((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State))"

# Lancer le script immédiatement en tant qu'admin pour mise à jour backup_status.json
& powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $scriptPath
