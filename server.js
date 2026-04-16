const http = require('http');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const PORT = 8888;

function ps(cmd, timeout=12000) {
  return new Promise(resolve => {
    exec(`powershell -NoProfile -Command "${cmd.replace(/"/g,'\\"')}"`,
      { timeout }, (err, stdout) => resolve(stdout ? stdout.trim() : ''));
  });
}

function portRisk(port, addr) {
  const local = addr==='127.0.0.1'||addr==='::1';
  const crit = [445,139,135,3389,23,21,25].includes(port);
  const high = [80,8080,8443,22].includes(port);
  if(crit && !local) return 'CRITIQUE';
  if(crit) return 'MOYEN';
  if(high && !local) return 'MOYEN';
  if(!local) return 'FAIBLE';
  return 'OK';
}

async function getDefender() {
  return new Promise(resolve => {
    exec(`powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion | ConvertTo-Json -Compress"`,
      {timeout:10000},(err,stdout)=>{
        try{resolve(JSON.parse(stdout||'{}'));}catch{resolve({});}
      });
  });
}

async function getFirewall() {
  return new Promise(resolve=>{
    exec(`powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress"`,
      {timeout:10000},(err,stdout)=>{
        try{let d=JSON.parse(stdout||'[]');resolve(Array.isArray(d)?d:[d]);}catch{resolve([]);}
      });
  });
}

async function getPorts() {
  return new Promise(resolve=>{
    const cmd=[
      `$r=foreach($c in (Get-NetTCPConnection -State Listen|Sort-Object LocalPort)){`,
      `$p=Get-Process -Id $c.OwningProcess -EA SilentlyContinue;`,
      `[PSCustomObject]@{Port=$c.LocalPort;Addr=$c.LocalAddress;Pid=$c.OwningProcess;`,
      `Name=if($p){$p.ProcessName}else{'INCONNU'};Path=if($p){$p.Path}else{'?'}}};`,
      `$r|ConvertTo-Json -Compress`
    ].join('');
    exec(`powershell -NoProfile -Command "${cmd.replace(/"/g,'\\"')}"`,
      {timeout:15000},(err,stdout)=>{
        try{
          let d=JSON.parse(stdout||'[]');
          if(!Array.isArray(d))d=[d];
          d=d.map(p=>({...p,Risk:portRisk(p.Port,p.Addr)}));
          resolve(d);
        }catch{resolve([]);}
      });
  });
}

async function getConnections() {
  return new Promise(resolve=>{
    const cmd=[
      `$r=Get-NetTCPConnection -State Established|`,
      `Where-Object{$_.RemoteAddress -notmatch '^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|::1)'}|`,
      `Select-Object -First 40;`,
      `$out=foreach($c in $r){$p=Get-Process -Id $c.OwningProcess -EA SilentlyContinue;`,
      `[PSCustomObject]@{Remote=$c.RemoteAddress;RemotePort=$c.RemotePort;LocalPort=$c.LocalPort;`,
      `Pid=$c.OwningProcess;Name=if($p){$p.ProcessName}else{'INCONNU'}}};`,
      `$out|ConvertTo-Json -Compress`
    ].join('');
    exec(`powershell -NoProfile -Command "${cmd.replace(/"/g,'\\"')}"`,
      {timeout:15000},(err,stdout)=>{
        try{let d=JSON.parse(stdout||'[]');resolve(Array.isArray(d)?d:[d]);}catch{resolve([]);}
      });
  });
}

async function getStartup() {
  return new Promise(resolve=>{
    const cmd=[
      `$items=@();`,
      `@('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',`,
      `'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')|ForEach-Object{`,
      `$key=$_;$props=Get-ItemProperty -Path $key -EA SilentlyContinue;`,
      `if($props){$props.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}|ForEach-Object{`,
      `$items+=[PSCustomObject]@{Name=$_.Name;Path=$_.Value;Key=$key}}}};`,
      `$items|ConvertTo-Json -Compress`
    ].join('');
    exec(`powershell -NoProfile -Command "${cmd.replace(/"/g,'\\"')}"`,
      {timeout:10000},(err,stdout)=>{
        try{let d=JSON.parse(stdout||'[]');resolve(Array.isArray(d)?d:[d]);}catch{resolve([]);}
      });
  });
}

async function getEvents() {
  return new Promise(resolve=>{
    const cmd=[
      `$evts=@();`,
      `$sm=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=@(1,3,7,11,12,13)} -MaxEvents 20 -EA SilentlyContinue;`,
      `$sn=@{1='PROCESSUS CREE';3='CONNEXION RESEAU';7='DLL CHARGEE';11='FICHIER CREE';12='REGISTRE';13='REGISTRE MODIFIE'};`,
      `foreach($e in $sm){$m=$e.Message;if($m.Length -gt 200){$m=$m.Substring(0,200)};`,
      `$evts+=[PSCustomObject]@{Source='SYSMON';Time=$e.TimeCreated.ToString('HH:mm:ss');Id=$e.Id;Type=$sn[[int]$e.Id];Msg=$m}};`,
      `$sc=Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4625,4720,4732,4698)} -MaxEvents 10 -EA SilentlyContinue;`,
      `$secn=@{4625='ECHEC LOGIN';4720='COMPTE CREE';4732='GROUPE MODIFIE';4698='TACHE PLANIFIEE'};`,
      `foreach($e in $sc){$m=$e.Message;if($m.Length -gt 200){$m=$m.Substring(0,200)};`,
      `$evts+=[PSCustomObject]@{Source='SECURITE';Time=$e.TimeCreated.ToString('HH:mm:ss');Id=$e.Id;Type=$secn[[int]$e.Id];Msg=$m}};`,
      `$evts|Sort-Object Time -Descending|Select-Object -First 30|ConvertTo-Json -Compress`
    ].join('');
    exec(`powershell -NoProfile -Command "${cmd.replace(/"/g,'\\"')}"`,
      {timeout:15000},(err,stdout)=>{
        try{let d=JSON.parse(stdout||'[]');resolve(Array.isArray(d)?d:[d]);}catch{resolve([]);}
      });
  });
}

async function getAdGuard() {
  return new Promise(resolve=>{
    const cmd=[
      `$r=[PSCustomObject]@{ServiceRunning=$false;DnsPort53Open=$false;SystemDnsIsLocal=$false;SystemDns=@()};`,
      `$svc=Get-Service AdGuardHome -EA SilentlyContinue;if($svc){$r.ServiceRunning=($svc.Status -eq 'Running')};`,
      `$r.DnsPort53Open=($null -ne (Get-NetTCPConnection -State Listen -EA SilentlyContinue|Where-Object{$_.LocalPort -eq 53}));`,
      `$dns=(Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue|Where-Object{$_.ServerAddresses.Count -gt 0}|Select-Object -First 1).ServerAddresses;`,
      `if($dns){$r.SystemDns=$dns;$r.SystemDnsIsLocal=($dns -contains '127.0.0.1')};`,
      `$r|ConvertTo-Json -Compress`
    ].join('');
    exec(`powershell -NoProfile -Command "${cmd.replace(/"/g,'\\"')}"`,
      {timeout:10000},(err,stdout)=>{
        try{resolve(JSON.parse(stdout||'{}'));}
        catch{resolve({ServiceRunning:false,DnsPort53Open:false,SystemDnsIsLocal:false,SystemDns:[]});}
      });
  });
}

async function getSuricata() {
  return new Promise(resolve=>{
    const eveFile='C:\\ProgramData\\Suricata\\log\\eve.json';
    const result={running:false,rulesLoaded:0,packetsToday:0,alertsToday:[],alertCount:0,kernelDrops:0,uptime:0};
    exec(`powershell -NoProfile -Command "$p=Get-Process suricata -EA SilentlyContinue;if($p){'RUNNING'}else{'STOPPED'}"`,
      {timeout:5000},(err,stdout)=>{
        result.running=(stdout||'').trim()==='RUNNING';
        if(!fs.existsSync(eveFile))return resolve(result);
        try{
          const lines=fs.readFileSync(eveFile,'utf8').trim().split('\n').filter(Boolean);
          lines.slice(-1000).forEach(line=>{
            try{
              const e=JSON.parse(line);
              if(e.event_type==='stats'){
                result.packetsToday=e.stats?.decoder?.pkts||result.packetsToday;
                result.kernelDrops=e.stats?.capture?.kernel_drops||0;
                result.uptime=e.stats?.uptime||0;
                result.rulesLoaded=e.stats?.detect?.engines?.[0]?.rules_loaded||result.rulesLoaded;
              }
              if(e.event_type==='alert'){
                result.alertCount++;
                if(result.alertsToday.length<10)result.alertsToday.push({
                  time:e.timestamp.slice(11,19),sig:e.alert?.signature||'Unknown',
                  category:e.alert?.category||'',severity:e.alert?.severity||3,
                  src:e.src_ip||'',dst:e.dest_ip||''
                });
              }
            }catch{}
          });
        }catch{}
        resolve(result);
      });
  });
}

async function getBackup() {
  const f=path.join(__dirname,'backup_status.json');
  if(fs.existsSync(f)){
    try{
      const age=(Date.now()-fs.statSync(f).mtimeMs)/60000;
      if(age<60)return JSON.parse(fs.readFileSync(f,'utf8').replace(/^\uFEFF/,''));
    }catch{}
  }
  return new Promise(resolve=>{
    exec(`powershell -NoProfile -Command "$r=[PSCustomObject]@{vssCount=0;lastBackup=$null;lastBackupAge=$null;vssService=$false};$v=Get-Service VSS -EA SilentlyContinue;$r.vssService=($v-ne$null-and$v.Status-eq'Running');$r|ConvertTo-Json -Compress"`,
      {timeout:6000},(err,stdout)=>{
        try{resolve(JSON.parse(stdout||'{}'));}
        catch{resolve({vssCount:0,lastBackup:null,lastBackupAge:null,vssService:false});}
      });
  });
}

// ── SCORE POSTURE HONNÊTE (100 pts pondérés) ─────────────────────────
function calcPostureScore(d) {
  const def=d.defender||{},fw=Array.isArray(d.firewall)?d.firewall:[];
  const ag=d.adguard||{},sur=d.suricata||{},bkp=d.backup||{};

  // EDR 30pts
  let edr=30;
  if(!def.AntivirusEnabled)edr-=15;
  if(!def.RealTimeProtectionEnabled)edr-=10;
  if(!def.BehaviorMonitorEnabled)edr-=5;
  const raw=def.AntivirusSignatureLastUpdated;
  let ageH=99;
  if(raw){const m=raw.match(/\/Date\((\d+)\)/);const dt=m?new Date(+m[1]):new Date(raw);if(!isNaN(dt))ageH=(Date.now()-dt)/3600000;}
  if(ageH>48)edr-=5;else if(ageH>24)edr-=2;

  // Firewall 20pts
  let firewall=20;
  fw.forEach(f=>{
    if(!f.Enabled)firewall-=7;
    else if(f.DefaultInboundAction!==4&&f.DefaultInboundAction!=='Block')firewall-=4;
  });

  // Backup 20pts
  let backup=20;
  // VSS est un service à démarrage à la demande — vssCount suffit pour valider
  if(!bkp.vssCount||bkp.vssCount===0)backup-=20;
  else if(bkp.lastBackupAge>48)backup-=5;

  // IDS 15pts
  let ids=15;
  if(!sur.running)ids-=15;
  else{
    const dp=sur.packetsToday>0?(sur.kernelDrops/sur.packetsToday)*100:0;
    if(dp>1)ids-=8;else if(dp>0.1)ids-=3;
    if(sur.alertCount>0)ids-=5;
  }

  // Réseau 15pts
  let network=15;
  const critP=(d.ports||[]).filter(p=>p.Risk==='CRITIQUE').length;
  const unknP=(d.ports||[]).filter(p=>p.Name==='INCONNU').length;
  const unknC=(d.connections||[]).filter(c=>c.Name==='INCONNU').length;
  if(!ag.ServiceRunning)network-=5;
  if(!ag.SystemDnsIsLocal)network-=3;
  network-=Math.min(7,critP*2+unknP*3+unknC*2);

  return{
    total:Math.max(0,edr+firewall+backup+ids+network),
    breakdown:{
      edr:{score:Math.max(0,edr),max:30},
      firewall:{score:Math.max(0,firewall),max:20},
      backup:{score:Math.max(0,backup),max:20},
      ids:{score:Math.max(0,ids),max:15},
      network:{score:Math.max(0,network),max:15}
    }
  };
}

// ── GÉNÈRE LES RISQUES ACTIFS ─────────────────────────────────────────
function buildRisks(d) {
  const risks=[];
  const def=d.defender||{},fw=Array.isArray(d.firewall)?d.firewall:[],ag=d.adguard||{};
  const sur=d.suricata||{},bkp=d.backup||{};

  if(!bkp.vssCount||bkp.vssCount===0)
    risks.push({sev:'CRITIQUE',cat:'BACKUP',msg:'Aucun point de restauration VSS — risque ransomware critique',action:'enable-vss',actionLabel:'Activer VSS'});
  if(!def.AntivirusEnabled)
    risks.push({sev:'CRITIQUE',cat:'EDR',msg:'Windows Defender désactivé',action:null});
  if(!def.RealTimeProtectionEnabled)
    risks.push({sev:'CRITIQUE',cat:'EDR',msg:'Protection temps réel désactivée',action:null});
  if(sur.alertCount>0)
    risks.push({sev:'CRITIQUE',cat:'IDS',msg:`Suricata: ${sur.alertCount} alerte(s) IDS détectée(s)`,action:null});

  const critPorts=(d.ports||[]).filter(p=>p.Risk==='CRITIQUE');
  critPorts.forEach(p=>risks.push({sev:'ELEVE',cat:'RÉSEAU',msg:`Port ${p.Port} (${p.Name}) exposé sur ${p.Addr} — protocole sensible`,action:'block-port',actionParams:{port:p.Port},actionLabel:`Bloquer port ${p.Port}`}));

  const unknConn=(d.connections||[]).filter(c=>c.Name==='INCONNU');
  unknConn.forEach(c=>risks.push({sev:'ELEVE',cat:'CONNEXION',msg:`Connexion vers ${c.Remote}:${c.RemotePort} par processus INCONNU (PID ${c.Pid})`,action:'kill-process',actionParams:{pid:c.Pid},actionLabel:`Tuer PID ${c.Pid}`}));

  const raw=def.AntivirusSignatureLastUpdated;
  let ageH=0;
  if(raw){const m=raw.match(/\/Date\((\d+)\)/);const dt=m?new Date(+m[1]):new Date(raw);if(!isNaN(dt))ageH=(Date.now()-dt)/3600000;}
  if(ageH>24)risks.push({sev:'MOYEN',cat:'EDR',msg:`Signatures Defender: ${Math.round(ageH)}h — mise à jour recommandée`,action:null});

  fw.forEach(f=>{if(!f.Enabled)risks.push({sev:'ELEVE',cat:'FIREWALL',msg:`Pare-feu ${f.Name} désactivé`,action:null});});
  if(!ag.ServiceRunning)risks.push({sev:'MOYEN',cat:'DNS',msg:'AdGuard Home arrêté — filtrage DNS inactif',action:null});
  if(!ag.SystemDnsIsLocal)risks.push({sev:'MOYEN',cat:'DNS',msg:`DNS système ne pointe pas vers 127.0.0.1 (AdGuard)`,action:null});

  const dp=sur.packetsToday>0?(sur.kernelDrops/sur.packetsToday)*100:0;
  if(dp>0.1)risks.push({sev:'MOYEN',cat:'IDS',msg:`Suricata: ${dp.toFixed(3)}% paquets perdus (${sur.kernelDrops.toLocaleString()})`,action:null});

  return risks;
}

// ── ACTIONS ────────────────────────────────────────────────────────────
async function handleAction(body) {
  const{action,params}=body;

  if(action==='isolate-host'){
    // KILL SWITCH : bloque tout trafic entrant ET sortant sauf localhost
    return new Promise(resolve=>{
      const cmds=[
        // Bloquer tout trafic entrant
        `New-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-IN' -Direction Inbound -Action Block -Profile Any -Enabled True -EA SilentlyContinue`,
        // Bloquer tout trafic sortant sauf localhost
        `New-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-OUT' -Direction Outbound -Action Block -Profile Any -Enabled True -EA SilentlyContinue`,
        // Autoriser le loopback pour garder le dashboard accessible
        `New-NetFirewallRule -DisplayName 'SENTINEL-ALLOW-LOOPBACK' -Direction Outbound -RemoteAddress 127.0.0.1 -Action Allow -Profile Any -Enabled True -EA SilentlyContinue`,
        `Write-Output 'ISOLATION_OK'`
      ].join(';');
      exec(`powershell -Command "${cmds.replace(/"/g,'\\"')}"`,
        {timeout:15000},(err,stdout,stderr)=>{
          if(stdout&&stdout.includes('ISOLATION_OK'))
            resolve({ok:true,msg:'HÔTE ISOLÉ — Tout trafic réseau bloqué. Dashboard accessible sur localhost seulement.'});
          else resolve({ok:false,msg:stderr||err?.message||'Erreur isolation'});
        });
    });
  }

  if(action==='lift-isolation'){
    // Lever l'isolation
    return new Promise(resolve=>{
      const cmds=[
        `Remove-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-IN' -EA SilentlyContinue`,
        `Remove-NetFirewallRule -DisplayName 'SENTINEL-ISOLATION-OUT' -EA SilentlyContinue`,
        `Remove-NetFirewallRule -DisplayName 'SENTINEL-ALLOW-LOOPBACK' -EA SilentlyContinue`,
        `Write-Output 'LIFT_OK'`
      ].join(';');
      exec(`powershell -Command "${cmds.replace(/"/g,'\\"')}"`,
        {timeout:15000},(err,stdout,stderr)=>{
          if(stdout&&stdout.includes('LIFT_OK'))
            resolve({ok:true,msg:'Isolation levée — Trafic réseau rétabli.'});
          else resolve({ok:false,msg:stderr||err?.message||'Erreur'});
        });
    });
  }

  if(action==='kill-process'){
    const pid=parseInt(params?.pid);
    if(!pid||isNaN(pid)||pid<100)return{ok:false,msg:'PID invalide'};
    return new Promise(resolve=>{
      exec(`powershell -Command "Stop-Process -Id ${pid} -Force -ErrorAction Stop;Write-Output 'OK'"`,
        {timeout:8000},(err,stdout,stderr)=>{
          if(err)resolve({ok:false,msg:stderr||err.message});
          else resolve({ok:true,msg:`Processus PID ${pid} terminé`});
        });
    });
  }

  if(action==='block-port'){
    const port=parseInt(params?.port);
    if(!port||isNaN(port))return{ok:false,msg:'Port invalide'};
    const name=`SENTINEL-Bloc-Port-${port}`;
    return new Promise(resolve=>{
      exec(`powershell -Command "New-NetFirewallRule -DisplayName '${name}' -Direction Inbound -LocalPort ${port} -Protocol TCP -Action Block -Profile Any -EA Stop;Write-Output 'OK'"`,
        {timeout:10000},(err,stdout,stderr)=>{
          if(err)resolve({ok:false,msg:stderr||err.message});
          else resolve({ok:true,msg:`Port ${port}/TCP bloqué par règle firewall`});
        });
    });
  }

  if(action==='disable-startup'){
    const{name,key}=params||{};
    if(!name||!key)return{ok:false,msg:'Paramètres manquants'};
    const sk=key.replace(/'/g,''),sn=name.replace(/'/g,'');
    return new Promise(resolve=>{
      exec(`powershell -Command "Remove-ItemProperty -Path '${sk}' -Name '${sn}' -EA Stop;Write-Output 'OK'"`,
        {timeout:8000},(err,stdout,stderr)=>{
          if(err)resolve({ok:false,msg:stderr||err.message});
          else resolve({ok:true,msg:`Démarrage "${name}" désactivé`});
        });
    });
  }

  if(action==='enable-vss'){
    return new Promise(resolve=>{
      exec(`powershell -Command "Set-Service VSS -StartupType Automatic;Start-Service VSS -EA Stop;Write-Output 'OK'"`,
        {timeout:10000},(err,stdout,stderr)=>{
          if(err)resolve({ok:false,msg:stderr||err.message});
          else resolve({ok:true,msg:'Service VSS activé'});
        });
    });
  }

  return{ok:false,msg:'Action inconnue'};
}

// ── COLLECTE GLOBALE ──────────────────────────────────────────────────
async function getAllData() {
  const[defender,firewall,ports,connections,events,startup,adguard,suricata,backup]=await Promise.all([
    getDefender(),getFirewall(),getPorts(),getConnections(),getEvents(),getStartup(),getAdGuard(),getSuricata(),getBackup()
  ]);
  const d={defender,firewall,ports,connections,events,startup,adguard,suricata,backup};
  const posture=calcPostureScore(d);
  const risks=buildRisks(d);
  const sysmonActive=events.some(e=>e.Source==='SYSMON');
  return{...d,posture,risks,sysmonActive,ts:new Date().toLocaleTimeString('fr-CA')};
}

// ── SERVEUR HTTP ──────────────────────────────────────────────────────
const server=http.createServer(async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if(req.method==='OPTIONS'){res.writeHead(204);res.end();return;}

  if(req.url==='/api/data'&&req.method==='GET'){
    const data=await getAllData();
    res.writeHead(200,{'Content-Type':'application/json'});
    res.end(JSON.stringify(data));return;
  }

  if(req.url==='/api/action'&&req.method==='POST'){
    let body='';
    req.on('data',c=>body+=c);
    req.on('end',async()=>{
      try{
        const parsed=JSON.parse(body);
        const result=await handleAction(parsed);
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify(result));
      }catch(e){
        res.writeHead(400,{'Content-Type':'application/json'});
        res.end(JSON.stringify({ok:false,msg:'Requête invalide'}));
      }
    });return;
  }

  if(req.url==='/'||req.url==='/index.html'){
    const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
    res.end(html);return;
  }

  res.writeHead(404);res.end('Not found');
});

server.listen(PORT,'127.0.0.1',()=>{
  console.log(`\n  SENTINEL démarré sur http://localhost:${PORT}\n`);
  exec(`start http://localhost:${PORT}`);
});
