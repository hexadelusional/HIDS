Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Fenêtre principale ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Configuration HIDS"
$form.Size = New-Object System.Drawing.Size(520, 820)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::LightGray
$form.FormBorderStyle = 'FixedSingle'

# --- Fonction : créer un label de titre ---
function New-TitleLabel($text, $y) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $text
    $lbl.Location = New-Object System.Drawing.Point(10, $y)
    $lbl.ForeColor = [System.Drawing.Color]::FromArgb(0, 60, 150)
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $lbl.Size = New-Object System.Drawing.Size(480, 25)
    return $lbl
}

# --- SECTION 1 : Dossiers à surveiller ---
$form.Controls.Add((New-TitleLabel "Dossiers/fichiers à surveiller" 15))

$lblPaths = New-Object System.Windows.Forms.Label
$lblPaths.Text = "Saisissez les chemins (séparés par des ';') :"
$lblPaths.ForeColor = [System.Drawing.Color]::FromArgb(0, 60, 150)
$lblPaths.Size = New-Object System.Drawing.Size(480, 20)
$lblPaths.Location = New-Object System.Drawing.Point(10, 45)
$form.Controls.Add($lblPaths)

$txtPaths = New-Object System.Windows.Forms.TextBox
$txtPaths.Location = New-Object System.Drawing.Point(10, 70)
$txtPaths.Size = New-Object System.Drawing.Size(480, 25)
$form.Controls.Add($txtPaths)

# --- SECTION 2 : Hôtes/IPs à surveiller ---
$form.Controls.Add((New-TitleLabel "Adresses IP à surveiller" 115))

$lblIPs = New-Object System.Windows.Forms.Label
$lblIPs.Text = "Saisissez les adresses IP à surveiller (séparés par des ';') :"
$lblIPs.ForeColor = [System.Drawing.Color]::FromArgb(0, 60, 150)
$lblIPs.Size = New-Object System.Drawing.Size(480, 40)
$lblIPs.Location = New-Object System.Drawing.Point(10, 145)
$lblIPs.AutoSize = $false
$lblIPs.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
$form.Controls.Add($lblIPs)

$txtIPs = New-Object System.Windows.Forms.TextBox
$txtIPs.Location = New-Object System.Drawing.Point(10, 190)
$txtIPs.Size = New-Object System.Drawing.Size(480, 25)
$form.Controls.Add($txtIPs)

# --- SECTION 3 : Paramètres SMTP ---
$form.Controls.Add((New-TitleLabel "Paramètres SMTP" 240))

$lblServer = New-Object System.Windows.Forms.Label
$lblServer.Text = "Serveur SMTP :"
$lblServer.ForeColor = [System.Drawing.Color]::FromArgb(0,60,150)
$lblServer.Location = New-Object System.Drawing.Point(10,270)
$form.Controls.Add($lblServer)

$txtServer = New-Object System.Windows.Forms.TextBox
$txtServer.Location = New-Object System.Drawing.Point(10,295)
$txtServer.Size = New-Object System.Drawing.Size(480,25)
$form.Controls.Add($txtServer)

$lblPort = New-Object System.Windows.Forms.Label
$lblPort.Text = "Port :"
$lblPort.ForeColor = [System.Drawing.Color]::FromArgb(0,60,150)
$lblPort.Location = New-Object System.Drawing.Point(10,325)
$form.Controls.Add($lblPort)

$txtPort = New-Object System.Windows.Forms.TextBox
$txtPort.Location = New-Object System.Drawing.Point(10,350)
$txtPort.Size = New-Object System.Drawing.Size(100,25)
$form.Controls.Add($txtPort)

$lblFrom = New-Object System.Windows.Forms.Label
$lblFrom.Text = "Adresse email d'envoi :"
$lblFrom.ForeColor = [System.Drawing.Color]::FromArgb(0,60,150)
$lblFrom.Location = New-Object System.Drawing.Point(10,380)
$lblFrom.Size = New-Object System.Drawing.Size(480,20)
$lblFrom.AutoSize = $false
$form.Controls.Add($lblFrom)

$txtFrom = New-Object System.Windows.Forms.TextBox
$txtFrom.Location = New-Object System.Drawing.Point(10,405)
$txtFrom.Size = New-Object System.Drawing.Size(480,25)
$form.Controls.Add($txtFrom)

$lblTo = New-Object System.Windows.Forms.Label
$lblTo.Text = "Emails destinataire(s) :"
$lblTo.ForeColor = [System.Drawing.Color]::FromArgb(0,60,150)
$lblTo.Location = New-Object System.Drawing.Point(10,435)
$lblTo.Size = New-Object System.Drawing.Size(480,20)
$lblTo.AutoSize = $false
$form.Controls.Add($lblTo)

$txtTo = New-Object System.Windows.Forms.TextBox
$txtTo.Location = New-Object System.Drawing.Point(10,460)
$txtTo.Size = New-Object System.Drawing.Size(480,25)
$form.Controls.Add($txtTo)

$lblPwd = New-Object System.Windows.Forms.Label
$lblPwd.Text = "Mot de passe SMTP :"
$lblPwd.ForeColor = [System.Drawing.Color]::FromArgb(0,60,150)
$lblPwd.Location = New-Object System.Drawing.Point(10,490)
$lblPwd.Size = New-Object System.Drawing.Size(480,20)
$lblPwd.AutoSize = $false
$form.Controls.Add($lblPwd)

$txtPwd = New-Object System.Windows.Forms.MaskedTextBox
$txtPwd.UseSystemPasswordChar = $true
$txtPwd.Location = New-Object System.Drawing.Point(10,515)
$txtPwd.Size = New-Object System.Drawing.Size(480,25)
$form.Controls.Add($txtPwd)

# --- SECTION 4 : Intervalle de scan ---
$form.Controls.Add((New-TitleLabel "Intervalle entre deux scans (en secondes)" 570))

$lblInterval = New-Object System.Windows.Forms.Label
$lblInterval.Text = "Temps entre deux scans :"
$lblInterval.ForeColor = [System.Drawing.Color]::FromArgb(0,60,150)
$lblInterval.Location = New-Object System.Drawing.Point(10,600)
$form.Controls.Add($lblInterval)

$txtInterval = New-Object System.Windows.Forms.TextBox
$txtInterval.Location = New-Object System.Drawing.Point(200,595)
$txtInterval.Size = New-Object System.Drawing.Size(100,25)
$txtInterval.Text = "10"  # valeur par défaut
$form.Controls.Add($txtInterval)


# --- Bouton Enregistrer ---
$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "ENREGISTRER LA CONFIGURATION"
$btnSave.Location = New-Object System.Drawing.Point(10,670)
$btnSave.Size = New-Object System.Drawing.Size(480,50)
$btnSave.BackColor = [System.Drawing.Color]::FromArgb(173, 216, 230)
$btnSave.ForeColor = [System.Drawing.Color]::FromArgb(0, 60, 150)
$btnSave.FlatStyle = 'Flat'
$btnSave.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($btnSave)

# --- Message de statut ---
$lblMsg = New-Object System.Windows.Forms.Label
$lblMsg.ForeColor = 'LightGray'
$lblMsg.Location = New-Object System.Drawing.Point(10,640)
$lblMsg.Size = New-Object System.Drawing.Size(480,80)
$form.Controls.Add($lblMsg)

# --- Action Enregistrer ---
$btnSave.Add_Click({
    $cfg = @{}

    # Charger une config existante si elle existe déjà
    $cfgPath = Join-Path (Split-Path -Parent $PSCommandPath) 'HIDS.config.json'
    if (Test-Path $cfgPath) {
        try { $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json } catch { $cfg = @{} }
    }

    # Met à jour uniquement si champ non vide
    if (-not [string]::IsNullOrWhiteSpace($txtIPs.Text)) {
        $cfg.HostsToMonitor = @(
            $txtIPs.Text.Split(';') | ForEach-Object {
                [PSCustomObject]@{
                    Address = $_.Trim()
                    Ports   = @(22, 80)
                }
            }
        )
    }

    if (-not $cfg.SMTP) { $cfg.SMTP = @{} }

    if (-not [string]::IsNullOrWhiteSpace($txtServer.Text)) { $cfg.SMTP.Server = $txtServer.Text }
    if (-not [string]::IsNullOrWhiteSpace($txtPort.Text))   { $cfg.SMTP.Port = [int]$txtPort.Text }
    if (-not [string]::IsNullOrWhiteSpace($txtFrom.Text))   { $cfg.SMTP.From = $txtFrom.Text }
    if (-not [string]::IsNullOrWhiteSpace($txtTo.Text))     { 
        $cfg.SMTP.To = $txtTo.Text.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } 
    }

    # SSL toujours défini
    $cfg.SMTP.UseSsl = $true

    # Mot de passe : uniquement si saisi
    if (-not [string]::IsNullOrWhiteSpace($txtPwd.Text)) {
        $secure = ConvertTo-SecureString $txtPwd.Text -AsPlainText -Force
        $secure | ConvertFrom-SecureString | Out-File (Join-Path (Split-Path -Parent $PSCommandPath) 'smtp.cred') -Encoding utf8
        $cfg.SMTP.CredFile = "smtp.cred"
    }

    # Intervalle seulement s’il est renseigné et numérique
    if (-not [string]::IsNullOrWhiteSpace($txtInterval.Text) -and $txtInterval.Text -match '^\d+$') {
        $cfg.IntervalSeconds = [int]$txtInterval.Text
    }

    # Sauvegarde
    $cfg | ConvertTo-Json -Depth 10 | Out-File -FilePath $cfgPath -Encoding UTF8

    $lblMsg.Text = "Configuration mise à jour.`nFichier : $cfgPath"
    $lblMsg.ForeColor = 'Green'
})

# Charger la config existante si elle existe
$cfgPath = Join-Path (Split-Path -Parent $PSCommandPath) 'HIDS.config.json'
$cfg = @{}
if (Test-Path $cfgPath) {
    try { $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json } catch { $cfg = @{} }
}

# Pré-remplir les champs si valeurs existantes
if ($cfg.PathsToMonitor) {
    if ($cfg.PathsToMonitor -is [System.Array]) {
        $txtPaths.Text = ($cfg.PathsToMonitor -join ';')
    } else {
        $txtPaths.Text = $cfg.PathsToMonitor
    }
}

if ($cfg.HostsToMonitor) {
    if ($cfg.HostsToMonitor -is [System.Array]) {
        $txtIPs.Text = (($cfg.HostsToMonitor | ForEach-Object { $_.Address }) -join ';')
    } elseif ($cfg.HostsToMonitor.Address) {
        $txtIPs.Text = $cfg.HostsToMonitor.Address
    }
}


if ($cfg.SMTP) {
    if ($cfg.SMTP.Server) { $txtServer.Text = $cfg.SMTP.Server }
    if ($cfg.SMTP.Port)   { $txtPort.Text   = $cfg.SMTP.Port }
    if ($cfg.SMTP.From)   { $txtFrom.Text   = $cfg.SMTP.From }
    if ($cfg.SMTP.To)     { $txtTo.Text     = ($cfg.SMTP.To -join ';') }
}

if ($cfg.IntervalSeconds) { $txtInterval.Text = $cfg.IntervalSeconds }


# --- Afficher ---
[void]$form.ShowDialog()