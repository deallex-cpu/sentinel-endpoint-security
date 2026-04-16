# backup_check.ps1 — détecte les points de restauration via plusieurs méthodes
$out = 'C:\Users\Utilisateur\Desktop\SECURITE_ORDI\dashboard\backup_status.json'
$result = [PSCustomObject]@{
  vssCount=0; lastBackup=$null; lastBackupAge=$null; vssService=$false
}

# 1. Service VSS
$vss = Get-Service VSS -ErrorAction SilentlyContinue
$result.vssService = ($vss -ne $null -and $vss.Status -eq 'Running')

# 2. Méthode 1 : WMI SystemRestore (admin user)
try {
  $rps = Get-WmiObject -Class SystemRestore -Namespace root\default -EA Stop
  if ($rps) {
    $result.vssCount = @($rps).Count
    $last = $rps | Sort-Object CreationTime -Descending | Select-Object -First 1
    if ($last) {
      $dt = [Management.ManagementDateTimeConverter]::ToDateTime($last.CreationTime)
      $result.lastBackup = $dt.ToString('o')
      $result.lastBackupAge = [math]::Round(((Get-Date)-$dt).TotalHours,1)
    }
  }
} catch {}

# 3. Méthode 2 : PowerShell Get-ComputerRestorePoint si méthode 1 vide
if ($result.vssCount -eq 0) {
  try {
    $rps2 = Get-ComputerRestorePoint -ErrorAction Stop
    if ($rps2) {
      $result.vssCount = @($rps2).Count
      $last2 = $rps2 | Sort-Object CreationTime -Descending | Select-Object -First 1
      if ($last2) {
        $dt2 = [Management.ManagementDateTimeConverter]::ToDateTime($last2.CreationTime)
        $result.lastBackup = $dt2.ToString('o')
        $result.lastBackupAge = [math]::Round(((Get-Date)-$dt2).TotalHours,1)
      }
    }
  } catch {}
}

# 4. Méthode 3 : Registre Windows (fonctionne même sans droits WMI)
if ($result.vssCount -eq 0) {
  try {
    $rpBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $rpKey = Get-Item $rpBase -EA Stop
    # Les RP sont dans des sous-clés RP000, RP001, etc.
    $rpSubs = Get-ChildItem $rpBase -EA SilentlyContinue | Where-Object {$_.PSChildName -match '^RP\d+$'}
    if ($rpSubs) {
      $result.vssCount = @($rpSubs).Count
      $lastRP = $rpSubs | Sort-Object PSChildName -Descending | Select-Object -First 1
      if ($lastRP) {
        $ts = (Get-ItemProperty $lastRP.PSPath -EA SilentlyContinue).Timestamp
        if ($ts) {
          # Timestamp = nombre de secondes depuis 1970 ou FILETIME selon la version
          try {
            $dt3 = [DateTime]::FromFileTime($ts)
            $result.lastBackup = $dt3.ToString('o')
            $result.lastBackupAge = [math]::Round(((Get-Date)-$dt3).TotalHours,1)
          } catch {}
        }
      }
    }
  } catch {}
}

$result | ConvertTo-Json -Compress | Set-Content -Path $out -Encoding UTF8 -NoNewline
Write-Output "OK: vssCount=$($result.vssCount) vssService=$($result.vssService)"
