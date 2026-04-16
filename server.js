// ═══════════════════════════════════════════════════════════════════
//  SENTINEL v2.0 — Endpoint Security Monitoring Server
//  Security Audit Fix — Toutes failles corrigées
// ═══════════════════════════════════════════════════════════════════

const http   = require('http');
const { execFile } = require('child_process');
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');

// ── CONFIGURATION (plus de chemins en dur) ────────────────────────
const CONFIG_FILE = path.join(__dirname, 'sentinel.config.json');
const DEFAULT_CONFIG = {
  port: 8888,
  host: '127.0.0.1',
  suricataEvePath: 'C:\\ProgramData\\Suricata\\log\\eve.json',
  maxBodySize: 2048,
  suricataMaxReadBytes: 2 * 1024 * 1024,
  rateLimitWindowMs: 60000,
  rateLimitMaxActions: 20,
};

function loadConfig() {
  let cfg = { ...DEFAULT_CONFIG };
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const user = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      cfg = { ...cfg, ...user };
    } else {
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG, null, 2), 'utf8');
    }
  } catch (e) { log('WARN', 'Config load failed', { error: e.message }); }
  return cfg;
}

const config = loadConfig();

// ── AUTH TOKEN CSRF ───────────────────────────────────────────────
const TOKEN_FILE = path.join(__dirname, '.sentinel-token');

function getOrCreateToken() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const t = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
      if (t.length >= 32) return t;
    }
  } catch {}
  const token = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(TOKEN_FILE, token, { encoding: 'utf8', mode: 0o600 }); } catch {}
  return token;
}

const API_TOKEN = getOrCreateToken();

// ── LOGGING (audit trail obligatoire) ─────────────────────────────
const LOG_FILE = path.join(__dirname, 'sentinel.log');

function log(level, msg, data = {}) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...data });
  console.log(entry);
  try { fs.appendFileSync(LOG_FILE, entry + '\n'); } catch {}
}

// ── RATE LIMITER ──────────────────────────────────────────────────
const actionTimestamps = [];

function isRateLimited() {
  const now = Date.now();
  while (actionTimestamps.length && actionTimestamps[0] < now - config.rateLimitWindowMs) {
    actionTimestamps.shift();
  }
  if (actionTimestamps.length >= config.rateLimitMaxActions) return true;
  actionTimestamps.push(now);
  return false;
}

// ── POWERSHELL SÉCURISÉ (execFile au lieu de exec) ────────────────
function psExec(cmd, timeout = 12000) {
  return new Promise(resolve => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
      { timeout, windowsHide: true },
      (err, stdout) => {
        if (err) log('WARN', 'PS exec failed', { cmd: cmd.substring(0, 80), error: err.message });
        resolve(stdout ? stdout.trim() : '');
      }
    );
  });
}

function psJSON(cmd, timeout = 12000, fallback = {}) {
  return new Promise(resolve => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
      { timeout, windowsHide: true },
      (err, stdout) => {
        if (err) {
          log('WARN', 'PS JSON failed', { cmd: cmd.substring(0, 80), error: err.message });
          resolve({ ...fallback, _error: true });
          return;
        }
        try {
          let d = JSON.parse(stdout || JSON.stringify(fallback));
          if (Array.isArray(fallback) && !Array.isArray(d)) d = [d];
          resolve(d);
        } catch {
          log('WARN', 'PS JSON parse failed', { cmd: cmd.substring(0, 80) });
          resolve({ ...fallback, _error: true });
        }
      }
    );
  });
}

// ── VALIDATION D'ENTRÉES ──────────────────────────────────────────
function isValidPid(pid) {
  const n = parseInt(pid);
  return Number.isInteger(n) && n >= 100 && n <= 65535;
}
function isValidPort(port) {
  const n = parseInt(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

// ── PORT RISK ─────────────────────────────────────────────────────
function portRisk(port, addr) {
  const local = addr === '127.0.0.1' || addr === '::1';
  const crit = [445, 139, 135, 3389, 23, 21, 25].includes(port);
  const high = [80, 8080, 8443, 22].includes(port);
  if (crit && !local) return 'CRITIQUE';
  if (crit) return 'MOYEN';
  if (high && !local) return 'MOYEN';
  if (!local) return 'FAIBLE';
  return 'OK';
}

// ── COLLECTEURS DE DONNÉES ────────────────────────────────────────
async function getDefender() {
  return psJSON(
    "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion | ConvertTo-Json -Compress",
    10000, {}
  );
}

async function getFirewall() {
  return psJSON(
    "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress",
    10000, []
  );
}

async function getPorts() {
  const cmd = [
    "$r=foreach($c in (Get-NetTCPConnection -State Listen|Sort-Object LocalPort)){",
    "$p=Get-Process -Id $c.OwningProcess -EA SilentlyContinue;",
    "[PSCustomObject]@{Port=$c.LocalPort;Addr=$c.LocalAddress;Pid=$c.OwningProcess;",
    "Name=if($p){$p.ProcessName}else{'INCONNU'};Path=if($p){$p.Path}else{'?'}}};",
    "$r|ConvertTo-Json -Compress"
  ].join('');
  const data = await psJSON(cmd, 15000, []);
  if (data._error) return [];
  return (Array.isArray(data) ? data : [data]).map(p => ({ ...p, Risk: portRisk(p.Port, p.Addr) }));
}

async function getConnections() {
  const cmd = [
    "$r=Get-NetTCPConnection -State Established|",
    "Where-Object{$_.RemoteAddress -notmatch '^(10\\\\.|172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.|192\\\\.168\\\\.|127\\\\.|::1)'}|",
    "Select-Object -First 40;",
    "$out=foreach($c in $r){$p=Get-Process -Id $c.OwningProcess -EA SilentlyContinue;",
    "[PSCustomObject]@{Remote=$c.RemoteAddress;RemotePort=$c.RemotePort;LocalPort=$c.LocalPort;",
    "Pid=$c.OwningProcess;Name=if($p){$p.ProcessName}else{'INCONNU'}}};",
    "$out|ConvertTo-Json -Compress"
  ].join('');
  return psJSON(cmd, 15000, []);
}

async function getStartup() {
  const cmd = [
    "$items=@();",
    "@('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',",
    "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')|ForEach-Object{",
    "$key=$_;$props=Get-ItemProperty -Path $key -EA SilentlyContinue;",
    "if($props){$props.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}|ForEach-Object{",
    "$items+=[PSCustomObject]@{Name=$_.Name;Path=$_.Value;Key=$key}}}};",
    "$items|ConvertTo-Json -Compress"
  ].join('');
  return psJSON(cmd, 10000, []);
}

async function getEvents() {
  const cmd = [
    "$evts=@();",
    "$sm=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=@(1,3,7,11,12,13)} -MaxEvents 20 -EA SilentlyContinue;",
    "$sn=@{1='PROCESSUS CREE';3='CONNEXION RESEAU';7='DLL CHARGEE';11='FICHIER CREE';12='REGISTRE';13='REGISTRE MODIFIE'};",
    "foreach($e in $sm){$m=$e.Message;if($m.Length -gt 200){$m=$m.Substring(0,200)};",
    "$evts+=[PSCustomObject]@{Source='SYSMON';Time=$e.TimeCreated.ToString('HH:mm:ss');Id=$e.Id;Type=$sn[[int]$e.Id];Msg=$m}};",
    "$sc=Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4625,4720,4732,4698)} -MaxEvents 10 -EA SilentlyContinue;",
    "$secn=@{4625='ECHEC LOGIN';4720='COMPTE CREE';4732='GROUPE MODIFIE';4698='TACHE PLANIFIEE'};",
    "foreach($e in $sc){$m=$e.Message;if($m.Length -gt 200){$m=$m.Substring(0,200)};",
    "$evts+=[PSCustomObject]@{Source='SECURITE';Time=$e.TimeCreated.ToString('HH:mm:ss');Id=$e.Id;Type=$secn[[int]$e.Id];Msg=$m}};",
    "$evts|Sort-Object Time -Descending|Select-Object -First 30|ConvertTo-Json -Compress"
  ].join('');
  return psJSON(cmd, 15000, []);
}

async function getAdGuard() {
  const cmd = [
    "$r=[PSCustomObject]@{ServiceRunning=$false;DnsPort53Open=$false;SystemDnsIsLocal=$false;SystemDns=@()};",
    "$svc=Get-Service AdGuardHome -EA SilentlyContinue;if($svc){$r.ServiceRunning=($svc.Status -eq 'Running')};",
    "$r.DnsPort53Open=($null -ne (Get-NetTCPConnection -State Listen -EA SilentlyContinue|Where-Object{$_.LocalPort -eq 53}));",
    "$dns=(Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue|Where-Object{$_.ServerAddresses.Count -gt 0}|Select-Object -First 1).ServerAddresses;",
    "if($dns){$r.SystemDns=$dns;$r.SystemDnsIsLocal=($dns -contains '127.0.0.1')};",
    "$r|ConvertTo-Json -Compress"
  ].join('');
  return psJSON(cmd, 10000, { ServiceRunning: false, DnsPort53Open: false, SystemDnsIsLocal: false, SystemDns: [] });
}

// ── SURICATA (lecture sécurisée — tail au lieu de readFileSync complet) ──
async function getSuricata() {
  const eveFile = config.suricataEvePath;
  const result = { running: false, rulesLoaded: 0, packetsToday: 0, alertsToday: [], alertCount: 0, kernelDrops: 0, uptime: 0 };

  const status = await psExec("$p=Get-Process suricata -EA SilentlyContinue;if($p){'RUNNING'}else{'STOPPED'}", 5000);
  result.running = status === 'RUNNING';

  if (!fs.existsSync(eveFile)) return result;

  try {
    const stat = fs.statSync(eveFile);
    const readSize = Math.min(stat.size, config.suricataMaxReadBytes);
    const buffer = Buffer.alloc(readSize);
    const fd = fs.openSync(eveFile, 'r');
    fs.readSync(fd, buffer, 0, readSize, Math.max(0, stat.size - readSize));
    fs.closeSync(fd);

    const text = buffer.toString('utf8');
    const firstNL = text.indexOf('\n');
    const clean = firstNL >= 0 ? text.substring(firstNL + 1) : text;
    const lines = clean.split('\n').filter(Boolean);

    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        if (e.event_type === 'stats') {
          result.packetsToday = e.stats?.decoder?.pkts || result.packetsToday;
          result.kernelDrops  = e.stats?.capture?.kernel_drops || 0;
          result.uptime       = e.stats?.uptime || 0;
          result.rulesLoaded  = e.stats?.detect?.engines?.[0]?.rules_loaded || result.rulesLoaded;
        }
        if (e.event_type === 'alert') {
          result.alertCount++;
          if (result.alertsToday.length < 10) result.alertsToday.push({
            time: (e.timestamp || '').slice(11, 19),
            sig: e.alert?.signature || 'Unknown',
            category: e.alert?.category || '',
            severity: e.alert?.severity || 3,
            src: e.src_ip || '', dst: e.dest_ip || ''
          });
        }
      } catch {}
    }
  } catch (e) {
    log('WARN', 'Suricata eve read failed', { error: e.message });
  }
  return result;
}

async function getBackup() {
  const f = path.join(__dirname, 'backup_status.json');
  if (fs.existsSync(f)) {
    try {
      const age = (Date.now() - fs.statSync(f).mtimeMs) / 60000;
      if (age < 60) return JSON.parse(fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, ''));
    } catch (e) { log('WARN', 'Backup file read error', { error: e.message }); }
  }
  return psJSON(
    "$r=[PSCustomObject]@{vssCount=0;lastBackup=$null;lastBackupAge=$null;vssService=$false};$v=Get-Service VSS -EA SilentlyContinue;$r.vssService=($v -ne $null -and $v.Status -eq 'Running');$r|ConvertTo-Json -Compress",
    6000, { vssCount: 0, lastBackup: null, lastBackupAge: null, vssService: false }
  );
}

// ── SCORE POSTURE (erreurs visibles, plus de faux positifs) ───────
function calcPostureScore(d) {
  const def = d.defender || {}, fw = Array.isArray(d.firewall) ? d.firewall : [];
  const ag = d.adguard || {}, sur = d.suricata || {}, bkp = d.backup || {};

  let edr = 30;
  if (def._error) { edr = 0; }
  else {
    if (!def.AntivirusEnabled) edr -= 15;
    if (!def.RealTimeProtectionEnabled) edr -= 10;
    if (!def.BehaviorMonitorEnabled) edr -= 5;
    const raw = def.AntivirusSignatureLastUpdated;
    let ageH = 99;
    if (raw) { const m = raw.match(/\/Date\((\d+)\)/); const dt = m ? new Date(+m[1]) : new Date(raw); if (!isNaN(dt)) ageH = (Date.now() - dt) / 3600000; }
    if (ageH > 48) edr -= 5; else if (ageH > 24) edr -= 2;
  }

  let firewall = 20;
  if (fw._error) { firewall = 0; }
  else { fw.forEach(f => { if (!f.Enabled) firewall -= 7; else if (f.DefaultInboundAction !== 4 && f.DefaultInboundAction !== 'Block') firewall -= 4; }); }

  let backup = 20;
  if (!bkp.vssCount || bkp.vssCount === 0) backup -= 20;
  else if (bkp.lastBackupAge > 48) backup -= 5;

  let ids = 15;
  if (!sur.running) ids -= 15;
  else {
    const dp = sur.packetsToday > 0 ? (sur.kernelDrops / sur.packetsToday) * 100 : 0;
    if (dp > 1) ids -= 8; else if (dp > 0.1) ids -= 3;
    if (sur.alertCount > 0) ids -= 5;
  }

  let network = 15;
  const critP = (d.ports || []).filter(p => p.Risk === 'CRITIQUE').length;
  const unknP = (d.ports || []).filter(p => p.Name === 'INCONNU').length;
  const unknC = (d.connections || []).filter(c => c.Name === 'INCONNU').length;
  if (!ag.ServiceRunning) network -= 5;
  if (!ag.SystemDnsIsLocal) network -= 3;
  network -= Math.min(7, critP * 2 + unknP * 3 + unknC * 2);

  return {
    total: Math.max(0, edr + firewall + backup + ids + network),
    breakdown: {
      edr:      { score: Math.max(0, edr), max: 30 },
      firewall: { score: Math.max(0, firewall), max: 20 },
      backup:   { score: Math.max(0, backup), max: 20 },
      ids:      { score: Math.max(0, ids), max: 15 },
      network:  { score: Math.max(0, network), max: 15 }
    }
  };
}

// ── BUILD RISKS (signale aussi les erreurs de collecte) ───────────
function buildRisks(d) {
  const risks = [];
  const def = d.defender || {}, fw = Array.isArray(d.firewall) ? d.firewall : [];
  const ag = d.adguard || {}, sur = d.suricata || {}, bkp = d.backup || {};

  if (def._error) risks.push({ sev: 'ELEVE', cat: 'SYSTEME', msg: 'Impossible de collecter les donnees Defender — verifier les droits admin' });
  if (fw._error)  risks.push({ sev: 'ELEVE', cat: 'SYSTEME', msg: 'Impossible de collecter les donnees Pare-feu — verifier les droits admin' });

  if (!bkp.vssCount || bkp.vssCount === 0)
    risks.push({ sev: 'CRITIQUE', cat: 'BACKUP', msg: 'Aucun point de restauration VSS — risque ransomware critique', action: 'enable-vss' });
  if (!def.AntivirusEnabled && !def._error)
    risks.push({ sev: 'CRITIQUE', cat: 'EDR', msg: 'Windows Defender desactive' });
  if (!def.RealTimeProtectionEnabled && !def._error)
    risks.push({ sev: 'CRITIQUE', cat: 'EDR', msg: 'Protection temps reel desactivee' });
  if (sur.alertCount > 0)
    risks.push({ sev: 'CRITIQUE', cat: 'IDS', msg: 'Suricata: ' + sur.alertCount + ' alerte(s) IDS detectee(s)' });

  (d.ports || []).filter(p => p.Risk === 'CRITIQUE').forEach(p =>
    risks.push({ sev: 'ELEVE', cat: 'RESEAU', msg: 'Port ' + p.Port + ' (' + p.Name + ') expose sur ' + p.Addr, action: 'block-port', actionParams: { port: p.Port } })
  );

  (d.connections || []).filter(c => c.Name === 'INCONNU').forEach(c =>
    risks.push({ sev: 'ELEVE', cat: 'CONNEXION', msg: 'Connexion vers ' + c.Remote + ':' + c.RemotePort + ' par processus INCONNU (PID ' + c.Pid + ')', action: 'kill-process', actionParams: { pid: c.Pid } })
  );

  const raw = def.AntivirusSignatureLastUpdated;
  let ageH = 0;
  if (raw) { const m = raw.match(/\/Date\((\d+)\)/); const dt = m ? new Date(+m[1]) : new Date(raw); if (!isNaN(dt)) ageH = (Date.now() - dt) / 3600000; }
  if (ageH > 24) risks.push({ sev: 'MOYEN', cat: 'EDR', msg: 'Signatures Defender: ' + Math.round(ageH) + 'h — mise a jour recommandee' });

  fw.forEach(f => { if (!f.Enabled) risks.push({ sev: 'ELEVE', cat: 'FIREWALL', msg: 'Pare-feu ' + f.Name + ' desactive' }); });
  if (!ag.ServiceRunning) risks.push({ sev: 'MOYEN', cat: 'DNS', msg: 'AdGuard Home arrete — filtrage DNS inactif' });
  if (!ag.SystemDnsIsLocal) risks.push({ sev: 'MOYEN', cat: 'DNS', msg: 'DNS systeme ne pointe pas vers 127.0.0.1 (AdGuard)' });

  const dp = sur.packetsToday > 0 ? (sur.kernelDrops / sur.packetsToday) * 100 : 0;
  if (dp > 0.1) risks.push({ sev: 'MOYEN', cat: 'IDS', msg: 'Suricata: ' + dp.toFixed(3) + '% paquets perdus' });

  return risks;
}

// ── ACTIONS (validation stricte, whitelist, audit) ────────────────
const ALLOWED_ACTIONS = new Set([
  'kill-process', 'block-port', 'disable-startup',
  'enable-vss', 'isolate-host', 'lift-isolation'
]);

const ALLOWED_STARTUP_KEYS = new Set([
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
]);

async function handleAction(body) {
  const { action, params } = body;
  if (!action || typeof action !== 'string' || !ALLOWED_ACTIONS.has(action)) {
    log('WARN', 'Action invalide', { action });
    return { ok: false, msg: 'Action non autorisee' };
  }

  log('INFO', 'Action executee', { action, params });

  if (action === 'isolate-host') {
    const cmd = "New-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-IN' -Direction Inbound -Action Block -Profile Any -Enabled True -EA SilentlyContinue; New-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-OUT' -Direction Outbound -Action Block -Profile Any -Enabled True -EA SilentlyContinue; New-NetFirewallRule -DisplayName 'SENTINEL-ALLOW-LOOPBACK' -Direction Outbound -RemoteAddress 127.0.0.1 -Action Allow -Profile Any -Enabled True -EA SilentlyContinue; Write-Output 'ISOLATION_OK'";
    const out = await psExec(cmd, 15000);
    const ok = out.includes('ISOLATION_OK');
    log(ok ? 'INFO' : 'ERROR', 'Isolation hote', { success: ok });
    return ok ? { ok: true, msg: 'HOTE ISOLE — Tout trafic reseau bloque.' } : { ok: false, msg: 'Erreur isolation' };
  }

  if (action === 'lift-isolation') {
    const cmd = "Remove-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-IN' -EA SilentlyContinue; Remove-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-OUT' -EA SilentlyContinue; Remove-NetFirewallRule -DisplayName 'SENTINEL-ALLOW-LOOPBACK' -EA SilentlyContinue; Write-Output 'LIFT_OK'";
    const out = await psExec(cmd, 15000);
    const ok = out.includes('LIFT_OK');
    log(ok ? 'INFO' : 'ERROR', 'Levee isolation', { success: ok });
    return ok ? { ok: true, msg: 'Isolation levee — trafic retabli.' } : { ok: false, msg: 'Erreur levee isolation' };
  }

  if (action === 'kill-process') {
    const pid = parseInt(params?.pid);
    if (!isValidPid(pid)) return { ok: false, msg: 'PID invalide (100-65535)' };
    const out = await psExec('Stop-Process -Id ' + pid + ' -Force -ErrorAction Stop; Write-Output OK', 8000);
    const ok = out.includes('OK');
    log(ok ? 'INFO' : 'ERROR', 'Kill process', { pid, success: ok });
    return ok ? { ok: true, msg: 'Processus PID ' + pid + ' termine' } : { ok: false, msg: 'Impossible de tuer PID ' + pid };
  }

  if (action === 'block-port') {
    const port = parseInt(params?.port);
    if (!isValidPort(port)) return { ok: false, msg: 'Port invalide (1-65535)' };
    const out = await psExec("New-NetFirewallRule -DisplayName 'SENTINEL-Bloc-Port-" + port + "' -Direction Inbound -LocalPort " + port + " -Protocol TCP -Action Block -Profile Any -EA Stop; Write-Output OK", 10000);
    const ok = out.includes('OK');
    log(ok ? 'INFO' : 'ERROR', 'Block port', { port, success: ok });
    return ok ? { ok: true, msg: 'Port ' + port + '/TCP bloque' } : { ok: false, msg: 'Impossible de bloquer port ' + port };
  }

  if (action === 'disable-startup') {
    const { name, key } = params || {};
    if (!name || !key || typeof name !== 'string' || typeof key !== 'string')
      return { ok: false, msg: 'Parametres manquants' };
    if (!ALLOWED_STARTUP_KEYS.has(key)) {
      log('WARN', 'Cle registre non autorisee', { key });
      return { ok: false, msg: 'Cle de registre non autorisee' };
    }
    if (!/^[a-zA-Z0-9\s._\-()]+$/.test(name)) {
      log('WARN', 'Nom startup suspect bloque', { name });
      return { ok: false, msg: 'Nom de programme invalide' };
    }
    const cmd = "& { param($k,$n) Remove-ItemProperty -Path $k -Name $n -ErrorAction Stop; Write-Output 'OK' } -k '" + key + "' -n '" + name + "'";
    const out = await psExec(cmd, 8000);
    const ok = out.includes('OK');
    log(ok ? 'INFO' : 'ERROR', 'Disable startup', { name, key, success: ok });
    return ok ? { ok: true, msg: 'Demarrage "' + name + '" desactive' } : { ok: false, msg: 'Impossible de desactiver "' + name + '"' };
  }

  if (action === 'enable-vss') {
    const out = await psExec("Set-Service VSS -StartupType Automatic; Start-Service VSS -EA Stop; Write-Output OK", 10000);
    const ok = out.includes('OK');
    log(ok ? 'INFO' : 'ERROR', 'Enable VSS', { success: ok });
    return ok ? { ok: true, msg: 'Service VSS active' } : { ok: false, msg: 'Impossible d\'activer VSS' };
  }

  return { ok: false, msg: 'Action inconnue' };
}

// ── COLLECTE GLOBALE ──────────────────────────────────────────────
async function getAllData() {
  const [defender, firewall, ports, connections, events, startup, adguard, suricata, backup] = await Promise.all([
    getDefender(), getFirewall(), getPorts(), getConnections(),
    getEvents(), getStartup(), getAdGuard(), getSuricata(), getBackup()
  ]);
  const d = { defender, firewall, ports, connections, events, startup, adguard, suricata, backup };
  const posture = calcPostureScore(d);
  const risks = buildRisks(d);
  const sysmonActive = (Array.isArray(events) ? events : []).some(e => e.Source === 'SYSMON');
  return { ...d, posture, risks, sysmonActive, ts: new Date().toLocaleTimeString('fr-CA') };
}

// ── CACHE HTML + INJECTION TOKEN ──────────────────────────────────
let cachedHtml = null;
let cachedMtime = 0;

function getHtml() {
  const htmlPath = path.join(__dirname, 'index.html');
  try {
    const mtime = fs.statSync(htmlPath).mtimeMs;
    if (!cachedHtml || mtime !== cachedMtime) {
      cachedHtml = fs.readFileSync(htmlPath, 'utf8');
      cachedMtime = mtime;
    }
    return cachedHtml.replace('{{SENTINEL_TOKEN}}', API_TOKEN);
  } catch (e) {
    log('ERROR', 'index.html read failed', { error: e.message });
    return '<h1>Erreur: index.html introuvable</h1>';
  }
}

// ── SECURITY HEADERS ──────────────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
  res.setHeader('Cache-Control', 'no-store');
}

// ── SERVEUR HTTP ──────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.url === '/api/data' && req.method === 'GET') {
    try {
      const data = await getAllData();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (e) {
      log('ERROR', 'Data collection crashed', { error: e.message });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Erreur collecte' }));
    }
    return;
  }

  if (req.url === '/api/action' && req.method === 'POST') {
    const token = req.headers['x-sentinel-token'];
    if (!token || token !== API_TOKEN) {
      log('WARN', 'Action non autorisee — token invalide', { ip: req.socket.remoteAddress });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, msg: 'Token invalide' }));
      return;
    }
    if (isRateLimited()) {
      log('WARN', 'Rate limit depasse');
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, msg: 'Trop de requetes — reessayez dans 1 minute' }));
      return;
    }

    let body = '';
    let tooLarge = false;
    req.on('data', chunk => {
      body += chunk;
      if (body.length > config.maxBodySize) { tooLarge = true; req.destroy(); }
    });
    req.on('end', async () => {
      if (tooLarge) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, msg: 'Requete trop volumineuse' }));
        return;
      }
      try {
        const parsed = JSON.parse(body);
        const result = await handleAction(parsed);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, msg: 'Requete invalide' }));
      }
    });
    return;
  }

  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getHtml());
    return;
  }

  res.writeHead(404); res.end('Not found');
});

// ── GRACEFUL SHUTDOWN ─────────────────────────────────────────────
function shutdown(sig) {
  log('INFO', 'Shutdown: ' + sig);
  server.close(() => { log('INFO', 'Server closed'); process.exit(0); });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── START ─────────────────────────────────────────────────────────
server.listen(config.port, config.host, () => {
  log('INFO', 'SENTINEL v2.0 started', { port: config.port });
  console.log('\n  SENTINEL v2.0 demarre sur http://' + config.host + ':' + config.port + '\n');
  execFile('cmd.exe', ['/c', 'start', 'http://localhost:' + config.port]);
});
