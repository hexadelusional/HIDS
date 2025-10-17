# =========================== 
# HIDS - Host-based Intrusion Detection System 
# Script PowerShell pour vérifier l'intégrité des fichiers et envoyer des alertes par email 
# =========================== 

param(
    [switch]$InitConfig, # Créer la config par défaut et quitter
    [switch]$Run, # Lancer directement la surveillance
    [switch]$RunAsDaemon # Lancer le script en mode boucle infinie
)

$ScriptDir = Split-Path -Parent $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = Get-Location }
$ConfigPath = Join-Path $ScriptDir 'HIDS.config.json'
$DbPath = Join-Path $ScriptDir 'HIDS.database.json'
$LogPath = Join-Path $ScriptDir 'HIDS.logs.txt'

function Write-Log {
    param($Message, [string]$Level = '-')
    $ts = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss')
    $line = "[$ts] $Level $Message"
    $line | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Host $line
}

function New-DefaultConfig {
    $sample = @{
        HostsToMonitor = @(
            @{ Address = "192.1.1.1"; Ports = @(22,80) }
        )
        PathsToMonitor = @("C:\myfolder\myfile")
        ExcludePatterns = @("*.log","*.tmp")
        Recurse = $true
        SMTP = @{
            Server = "server.smtp.example"
            Port = 587
            From = "default@gmail.com"
            To = @("default@gmail.com")
            UseSsl = $true
            CredFile = "smtp.cred"
        }
    }
    $sample | ConvertTo-Json -Depth 10
}

function Save-SMTPPassword {
    param([string]$PlainPassword, [string]$OutFile = (Join-Path $ScriptDir 'smtp.cred'))
    $secure = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
    $encrypted = $secure | ConvertFrom-SecureString
    [System.IO.File]::WriteAllText($OutFile,$encrypted)
    Write-Host "Password saved to $OutFile (encrypted for current user)."
}

function Load-SMTPPassword {
    param([string]$CredFile)
    if (-not (Test-Path $CredFile)) { return $null }
    $enc = Get-Content $CredFile -Raw
    $enc = $enc -replace '^\uFEFF',''
    $enc = $enc.Trim()
    try { return ConvertTo-SecureString $enc }
    catch { Write-Log "ERROR: failed to convert SMTP password: $($_.Exception.Message)"; return $null }
}

function Load-Config {
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "No config found, creating default."
        New-DefaultConfig | Out-File -FilePath $ConfigPath -Encoding utf8
        exit 0
    }
    $json = Get-Content $ConfigPath -Raw
    return $json | ConvertFrom-Json
}

function Load-DB {
    if (Test-Path $DbPath) {
        $raw = Get-Content $DbPath -Raw
        if ($raw.Trim().Length -eq 0) { return @{} }
        $jsonObj = $raw | ConvertFrom-Json
        $ht=@{}
        foreach($key in $jsonObj.PSObject.Properties.Name){ $ht[$key]=$jsonObj.$key }
        return $ht
    } else { return @{} }
}

function Save-DB($db){ $db | ConvertTo-Json -Depth 10 | Out-File -FilePath $DbPath -Encoding UTF8 }

function Compute-FileHash { param([string]$Path) try { (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null } }

function Send-Alert {
    param($cfg,[string]$subject,[string]$body)
    $smtp = $cfg.SMTP
    $securepwd = Load-SMTPPassword -CredFile (Join-Path $ScriptDir $smtp.CredFile)
    if (-not $securepwd) { Write-Log "ERREUR: mot de passe SMTP manquant..."; return }
    try{
        $cred = New-Object System.Management.Automation.PSCredential($smtp.From,$securepwd)
        Send-MailMessage -SmtpServer $smtp.Server -Port $smtp.Port -UseSsl:$smtp.UseSsl -Credential $cred -From $smtp.From -To ($smtp.To -join ',') -Subject $subject -Body $body -ErrorAction Stop
        Write-Log "Envoi d'email : $subject"
    } catch {
        Write-Log "ERREUR SMTP: $($_.Exception.Message)"
        if ($_.Exception.InnerException){ Write-Log "INNER: $($_.Exception.InnerException.Message)" }
    }
}

function Scan-Hosts {
    param($cfg,[ref]$db)
    $now = Get-Date; $timestamp = $now.ToString('HH:mm:ss')
    $changes=@(); $hasChanges=$false
    foreach($hostConfig in $cfg.HostsToMonitor){
        $address=$hostConfig.Address; $ports=$hostConfig.Ports
        Write-Host "`nSCAN MACHINES :" -ForegroundColor DarkYellow
        $isHostUp = Test-Connection -ComputerName $address -Count 1 -Quiet -ErrorAction SilentlyContinue
        $oldHostStatus = if($db.Value.ContainsKey("HOST_$address")){ $db.Value["HOST_$address"] } else { $null }
        $db.Value["HOST_$address"] = $isHostUp
        if($null -ne $oldHostStatus -and $oldHostStatus -ne $isHostUp){
            $statusTxt = if($isHostUp){ "allumee" } else { "eteinte" }
            $prevTxt = if($oldHostStatus){ "ALLUMEE" } else { "ETEINTE" }
            Write-Host "`n    [$timestamp] Machine $address $statusTxt !" -ForegroundColor Yellow
            $changes += [PSCustomObject]@{ Type='HOST_STATUS_CHANGED'; Address=$address; Port=$null; Status=$statusTxt; PreviousStatus=$prevTxt; Time=$now }
            $hasChanges=$true
        } elseif($null -eq $oldHostStatus) {
            Write-Host "`n    [$timestamp] Découverte de l'hôte $address (statut initial : $($isHostUp))" -ForegroundColor DarkGray
        }

        if($isHostUp){
            foreach($port in $ports){
                $tcpClient = New-Object System.Net.Sockets.TcpClient; $portOpen=$false
                try{ $tcpClient.ReceiveTimeout=2000; $tcpClient.SendTimeout=2000; $tcpClient.Connect($address,$port); $portOpen=$true } catch { $portOpen=$false } finally { $tcpClient.Close() }
                $key="PORT_${address}_$port"
                $oldPortStatus= if($db.Value.ContainsKey($key)){ $db.Value[$key] } else { $null }
                $db.Value[$key]=$portOpen
                if($null -ne $oldPortStatus -and $oldPortStatus -ne $portOpen){
                    $statusTxt = if($portOpen){ "OUVERT" } else { "FERME" }
                    $prevTxt = if($oldPortStatus){ "OUVERT" } else { "FERME" }
                    Write-Host "`n    [$timestamp] Port $port $statusTxt sur $address !" -ForegroundColor Yellow
                    $changes += [PSCustomObject]@{ Type='PORT_STATUS_CHANGED'; Address=$address; Port=$port; Status=$statusTxt; PreviousStatus=$prevTxt; Time=$now }
                    $hasChanges=$true
                } elseif($null -eq $oldPortStatus){
                    Write-Host "    Découverte du port $port sur $address (état initial : $($portOpen))" -ForegroundColor DarkGray
                }
            }
        }
    }
    if(-not $hasChanges){ Write-Host "`n    [$timestamp] - Pas de modification :)" -ForegroundColor Yellow }
    return ,$changes
}

function Scan-Files {
    param($cfg,[ref]$db)
    $now = Get-Date; $timestamp=$now.ToString('HH:mm:ss')
    $changes=New-Object System.Collections.ArrayList; $hasChanges=$false
    foreach($path in $cfg.PathsToMonitor){
        Write-Host "`nSCAN FICHIERS :" -ForegroundColor DarkYellow
        if(-not (Test-Path $path)){ Write-Host "N'EXISTE PAS !" -ForegroundColor Red; continue }
        $items = Get-ChildItem -Path $path -File -Recurse:$cfg.Recurse -ErrorAction SilentlyContinue
        foreach($it in $items){
            $hash = Compute-FileHash -Path $it.FullName
            $oldHash = $db.Value[$it.FullName]
            if(-not $oldHash){
                Write-Host "`n    [$timestamp] Nouveau fichier créé ! ($($it.Name))" -ForegroundColor Yellow
                [void]$changes.Add([PSCustomObject]@{ Type='NOUVEAU'; Path=$it.FullName; Time=$it.LastWriteTime })
                $db.Value[$it.FullName]=$hash; $hasChanges=$true
            } elseif([string]$oldHash -ne [string]$hash -and $hash){
                Write-Host "`n    [$timestamp] - Alerte modification !" -ForegroundColor Yellow
                [void]$changes.Add([PSCustomObject]@{ Type='MODIFIE'; Path=$it.FullName; Time=$it.LastWriteTime })
                $db.Value[$it.FullName]=$hash; $hasChanges=$true
            }
        }
    }
    if(-not $hasChanges){ Write-Host "`n    [$timestamp] - Pas de modification :)" -ForegroundColor Yellow }
    return ,$changes
}

function Format-FileMessage($changes){
    $msg="Une modification a eu lieu dans les fichiers suivants :`n`n"
    foreach($c in $changes){ $msg+="$($c.Type): $($c.Path)`n" }
    return $msg
}

function Format-HostMessage($changes){
    $msg=""
    foreach($c in $changes){
        switch($c.Type){
            'HOST_STATUS_CHANGED' { $msg+="L'etat de la machine $($c.Address) est $($c.PreviousStatus) -> $($c.Status)`n" }
            'PORT_STATUS_CHANGED' { $msg+="Le port $($c.Port) sur la machine $($c.Address) est $($c.Status.ToLower())`n" }
        }
    }
    return $msg
}

function Start-Daemon {
    param([psobject]$cfg)
    $interval=10
    $dbRef=[ref](Load-DB); $stop=$false
    try{
        while(-not $stop){
            $startTime=Get-Date
            Write-Host "`n====================" -ForegroundColor DarkCyan
            Write-Host "Itération daemon : $($startTime.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor Cyan
            try{
                $fileChanges = Scan-Files -cfg $cfg -db $dbRef
                if($fileChanges.Count -gt 0){
                    Save-DB $dbRef.Value
                    $msg = Format-FileMessage $fileChanges
                    Send-Alert -cfg $cfg -subject "Alerte HIDS - Fichiers" -body $msg
                }
                $hostChanges = Scan-Hosts -cfg $cfg -db $dbRef
                if($hostChanges.Count -gt 0){
                    Save-DB $dbRef.Value
                    $msg = Format-HostMessage $hostChanges
                    Send-Alert -cfg $cfg -subject "Alerte HIDS - Machines" -body $msg
                }
                Save-DB $dbRef.Value
            } catch { Write-Log "ERREUR daemon: $($_.Exception.Message)" "ERROR" }
            $elapsed=(Get-Date)-$startTime; $sleepSec=[int]($interval-$elapsed.TotalSeconds)
            if($sleepSec -gt 0){ Start-Sleep -Seconds $sleepSec }
        }
    } finally { Write-Log "Daemon arrêté proprement." }
}

# ===================== POINT D'ENTRÉE =====================
$cfg=Load-Config
if($InitConfig){ New-DefaultConfig | Out-File -FilePath $ConfigPath -Encoding utf8; exit }
if($RunAsDaemon){ Write-Log "Mode daemon active, surveillance continue."; Start-Daemon -cfg $cfg; exit }

$script:daemonActive=$false; $quit=$false
do{
    Write-Host "----------------- Menu HIDS -----------------" -ForegroundColor Blue
    Write-Host "1 - Configurer" -ForegroundColor Cyan
    Write-Host "2 - Info cible" -ForegroundColor Cyan
    Write-Host "3 - Scanner les fichiers" -ForegroundColor Cyan
    Write-Host "4 - Scanner les ports" -ForegroundColor Cyan
    if($script:daemonActive){ Write-Host "5 - Couper scan en arrière plan" -ForegroundColor DarkRed }
    else{ Write-Host "5 - Lancer scan en arrière plan" -ForegroundColor Cyan }
    Write-Host "6 - Credits" -ForegroundColor Cyan
    Write-Host "7 - Exit" -ForegroundColor Cyan
    Write-Host "Option: " -NoNewline -ForegroundColor Blue
    $choice=Read-Host
    switch($choice){
        '1'{
            $configScript = Join-Path $ScriptDir 'HIDS_CONFIG_GUI.ps1'
            if(Test-Path $configScript){ & $configScript; $cfg=Load-Config; Write-Log "Configuration appliquée." }
            else{ Write-Host "ERREUR : Fichier HIDS_CONFIG_GUI.ps1 introuvable." -ForegroundColor Magenta }
        }
        '2'{
            Write-Host "`nCIBLES :" -ForegroundColor DarkYellow
            Write-Host "    Dossiers :" -ForegroundColor Yellow
            foreach($p in $cfg.PathsToMonitor){ Write-Host "        $p" }
            Write-Host "`n    Adresses IP :" -ForegroundColor Yellow
            foreach($h in $cfg.HostsToMonitor){ Write-Host "        $($h.Address) (Ports: $($h.Ports -join ', '))" }
        }
        '3'{
            $dbRef=[ref](Load-DB)
            $changes=Scan-Files -cfg $cfg -db $dbRef
            $changes | Format-Table
            Save-DB $dbRef.Value
            if($changes.Count -gt 0){ Send-Alert -cfg $cfg -subject "Alerte HIDS - Fichiers" -body (Format-FileMessage $changes) }
        }
        '4'{
            $dbRef=[ref](Load-DB)
            $hostChanges=Scan-Hosts -cfg $cfg -db $dbRef
            Save-DB $dbRef.Value
            if($hostChanges.Count -gt 0){
                $hostChanges | Format-Table Type,Address,@{Label="Port";Expression={if($_.Port){$_.Port}else{"-"}}} -AutoSize
                Send-Alert -cfg $cfg -subject "Alerte HIDS - Machines" -body (Format-HostMessage $hostChanges)
            }
        }
        '5'{
            if($script:daemonActive){
                Get-Process powershell | Where-Object { $_.Id -ne $PID -and $_.MainWindowTitle -eq "" } | Stop-Process -Force
                Write-Log "Scan en arrière plan coupé."; $script:daemonActive=$false
            } else{
                Write-Log "Scan en arrière plan, surveillance continue."
                Start-Process powershell -ArgumentList "-WindowStyle Hidden -File `"$PSCommandPath`" -RunAsDaemon" -WindowStyle Hidden
                $script:daemonActive=$true
            }
        }
        '6'{
            Write-Host "*********************************************" -ForegroundColor DarkMagenta
            Write-Host "                   Projet SSE                " -ForegroundColor Magenta
            Write-Host "           Script HIDS par Adele Chamoux     " -ForegroundColor Magenta
            Write-Host "                Promo 2027 - I2 CIL          " -ForegroundColor Magenta
            Write-Host "*********************************************" -ForegroundColor DarkMagenta
        }
        '7'{ Write-Host "-------------------- Bye --------------------" -ForegroundColor Blue; $quit=$true }
        default{ Write-Host "Choix invalide. Veuillez selectionner une option entre 1 et 7." -ForegroundColor Red }
    }
} while(-not $quit)
