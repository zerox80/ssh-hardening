<#
.SYNOPSIS
  Richtet den SSH-Zugang von diesem Windows-PC zu einem Linux-Server ein – in einem Rutsch.

.DESCRIPTION
  1. Nutzt einen vorhandenen SSH-Schlüssel oder erzeugt einen neuen (ed25519).
  2. Trägt den öffentlichen Schlüssel auf dem Server ein – nur wenn nötig, dafür EINMAL das Server-Passwort.
  3. Prüft, ob die Anmeldung jetzt ohne Passwort klappt.
  4. Legt in %USERPROFILE%\.ssh\config Kurznamen an: danach genügt "ssh <hostname>".
  5. Auf Wunsch: privaten Schlüssel für Bitwarden in die Zwischenablage (ohne Verlauf), danach geleert.

  Funktioniert mit frischen und mit schon eingerichteten Servern und lässt sich gefahrlos wiederholen.
  https://github.com/zerox80/ssh-hardening

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\ssh-zugang-einrichten.ps1 -Server 192.0.2.10 -User admin
.EXAMPLE
  .\ssh-zugang-einrichten.ps1 -Server server.example.org -User admin -Port 2222 -Alias web1 -Bitwarden
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Server,
    [Parameter(Mandatory)] [string] $User,
    [ValidateRange(1, 65535)] [int] $Port = 22,
    # Zusätzliche Kurznamen; der echte Hostname des Servers und die Adresse kommen automatisch dazu.
    [string[]] $Alias = @(),
    [string] $KeyName = "id_ed25519",
    # Privaten Schlüssel ohne Rückfrage für Bitwarden in die Zwischenablage legen.
    [switch] $Bitwarden,
    # Nicht nach Bitwarden fragen.
    [switch] $NoBitwarden,
    # ~/.ssh/config nicht anfassen.
    [switch] $NoConfig
)

$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 kennt $IsWindows nicht – dort ist es immer Windows.
$OnWindows = ($PSVersionTable.PSEdition -eq "Desktop") -or $IsWindows

function Write-Step([string] $text) { Write-Host ""; Write-Host "==> $text" -ForegroundColor Cyan }
function Stop-WithError([string] $text) { Write-Host ""; Write-Host "ABBRUCH: $text" -ForegroundColor Red; exit 1 }

# Windows-OpenSSH verweigert private Schlüssel und ~/.ssh/config, wenn außer dem Besitzer noch jemand
# Rechte hat – oft vom Profilordner geerbt (z. B. ein Support-Konto): "Bad owner or permissions" bzw.
# "UNPROTECTED PRIVATE KEY FILE". icacls statt Set-Acl: keine Sonderrechte nötig, gibt es auf jedem
# Windows und arbeitet mit SIDs – unabhängig von der Sprache des Systems.
function Set-OwnerOnlyAcl([string] $path) {
    if (-not $OnWindows) {
        # PowerShell 7 unter Linux/macOS: Unix-Rechte genügen
        & chmod 600 $path
        return
    }
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & icacls $path /reset /Q 2>$null | Out-Null
        & icacls $path /inheritance:r /grant:r "*${sid}:F" "*S-1-5-18:F" /Q 2>$null | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        # Besitz übernehmen klappt nicht immer (z. B. als Administrator angelegt) – OpenSSH akzeptiert
        # dann auch die Gruppe Administratoren als Besitzer.
        & icacls $path /setowner "*$sid" /Q 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $previous
    }
    if (-not $ok) {
        Stop-WithError "Rechte für $path ließen sich nicht setzen. Von Hand: icacls `"$path`" /inheritance:r /grant:r `"$($env:USERNAME):F`""
    }
}

# ssh aufrufen und Ausgabe samt Fehlermeldungen einsammeln (nur für Aufrufe ohne Rückfragen).
function Invoke-SshQuiet([string[]] $arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & ssh @arguments 2>&1 | ForEach-Object { "$_" }
        return [pscustomobject]@{ Code = $LASTEXITCODE; Lines = @($lines) }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Test-Interactive {
    return [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
}

# Zwischenablage ohne Verlauf (Win+V) und ohne Cloud-Synchronisierung; Rückfall: normale Zwischenablage.
function Set-SecretClipboard([string] $text) {
    if (-not $OnWindows) {
        Set-Clipboard -Value $text
        return "normal"
    }
    try {
        $null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType = WindowsRuntime]
        $package = New-Object Windows.ApplicationModel.DataTransfer.DataPackage
        $package.SetText($text)
        $options = New-Object Windows.ApplicationModel.DataTransfer.ClipboardContentOptions
        $options.IsAllowedInHistory = $false
        $options.IsRoamable = $false
        $done = [Windows.ApplicationModel.DataTransfer.Clipboard]::SetContentWithOptions($package, $options)
        if ($done -and ((Get-Clipboard -Raw) -eq $text)) { return "ohne Verlauf und ohne Cloud-Synchronisierung" }
    } catch { }
    Set-Clipboard -Value $text
    return "normal – Achtung: bei eingeschaltetem Zwischenablage-Verlauf (Win+V) dort danach den Eintrag löschen"
}
function Clear-SecretClipboard {
    if (-not $OnWindows) { Set-Clipboard -Value " "; return }
    try {
        $null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType = WindowsRuntime]
        [Windows.ApplicationModel.DataTransfer.Clipboard]::Clear()
    } catch {
        Set-Clipboard -Value " "
    }
}

# ---------------------------------------------------------------- OpenSSH vorhanden?
Write-Step "OpenSSH-Client prüfen"
foreach ($tool in "ssh", "ssh-keygen") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Stop-WithError "$tool fehlt. Einstellungen -> System -> Optionale Features -> 'OpenSSH-Client' hinzufügen (oder als Administrator: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0), dann erneut starten."
    }
}
Write-Host "ok"

$profileDir = if ($OnWindows) { $env:USERPROFILE } else { $HOME }
$sshDir = Join-Path $profileDir ".ssh"
$key = Join-Path $sshDir $KeyName
$pub = "$key.pub"
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
$target = "$User@$Server"
# -F none: ~/.ssh/config nicht mitlesen – sonst probiert ssh zusätzlich dort hinterlegte Schlüssel
# und meldet fälschlich "schon eingetragen", obwohl dieser Schlüssel fehlt.
$baseOptions = @("-F", "none", "-p", "$Port", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15")

# ---------------------------------------------------------------- 1. Schlüssel
Write-Step "Schlüssel $key"
if (Test-Path $key) {
    Write-Host "vorhanden – wird verwendet"
    Set-OwnerOnlyAcl $key
    if (-not (Test-Path $pub)) {
        # Öffentlichen Teil aus dem privaten Schlüssel wiederherstellen
        $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        $publicLine = & ssh-keygen -y -f $key
        $ErrorActionPreference = $previous
        if ($LASTEXITCODE -ne 0 -or -not $publicLine) { Stop-WithError "Öffentlicher Schlüssel $pub fehlt und ließ sich nicht erzeugen." }
        [System.IO.File]::WriteAllText($pub, "$publicLine`n", (New-Object System.Text.UTF8Encoding $false))
    }
} else {
    if (Test-Path $pub) { Stop-WithError "$pub ist da, der private Schlüssel $key fehlt. Datei umbenennen oder -KeyName anders wählen." }
    Write-Host "Neuer Schlüssel. Eine Passphrase ist empfohlen (schützt den Schlüssel, falls jemand an den PC kommt)."
    Write-Host "Ohne Passphrase: zweimal Enter drücken."
    & ssh-keygen -t ed25519 -a 64 -f $key -C "$([Environment]::UserName)@$([Environment]::MachineName)"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $pub)) { Stop-WithError "Schlüssel konnte nicht erzeugt werden." }
    Set-OwnerOnlyAcl $key
}
$publicKey = (Get-Content $pub -Raw).Trim()
& ssh-keygen -lf $pub

# ---------------------------------------------------------------- 2. Schon eingerichtet?
Write-Step "Verbindung zu $target prüfen"
$probeCommand = "echo schluessel-ok; hostname -s 2>/dev/null || uname -n"
$keyOptions = @("-i", $key, "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no")
$first = Invoke-SshQuiet ($baseOptions + $keyOptions + @("-o", "BatchMode=yes", $target, $probeCommand))
if (($first.Lines -join "`n") -match "REMOTE HOST IDENTIFICATION HAS CHANGED") {
    Stop-WithError ("Der Server meldet einen anderen Schlüssel als beim letzten Mal (z. B. neu installiert). " +
        "Ist das erklärbar: alten Eintrag mit  ssh-keygen -R $Server  entfernen (bei Port ${Port}: ssh-keygen -R `"[${Server}]:${Port}`") und neu starten. " +
        "Ist es NICHT erklärbar: nicht verbinden und die IT fragen.")
}
if (($first.Lines -join "`n") -match "Could not resolve|Connection refused|timed out|No route to host") {
    Stop-WithError "Server nicht erreichbar: $($first.Lines -join ' ') – Adresse, Port $Port und Firewall prüfen."
}

if ($first.Code -eq 0 -and $first.Lines -contains "schluessel-ok") {
    Write-Host "Der Schlüssel ist auf dem Server schon eingetragen – kein Passwort nötig." -ForegroundColor Green
    $check = $first.Lines
} else {
    # ------------------------------------------------------------ 3. Auf den Server kopieren
    Write-Step "Öffentlichen Schlüssel auf $target eintragen"
    Write-Host "Jetzt das PASSWORT des Server-Benutzers eingeben (nur dieses eine Mal):"
    # Ohne doppelte Anführungszeichen, weil Windows PowerShell 5.1 sie an Programme nicht sauber weiterreicht.
    # Der Schlüssel kommt über die Standardeingabe; Windows-Zeilenenden werden entfernt, doppelte Einträge vermieden.
    $remote = 'umask 077; mkdir -p ~/.ssh; tr -d ''\r'' > ~/.ssh/.ssh-hardening-neu; touch ~/.ssh/authorized_keys; ' +
              'grep -qxFf ~/.ssh/.ssh-hardening-neu ~/.ssh/authorized_keys || cat ~/.ssh/.ssh-hardening-neu >> ~/.ssh/authorized_keys; ' +
              'rm -f ~/.ssh/.ssh-hardening-neu; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; ' +
              'command -v restorecon >/dev/null 2>&1 && restorecon -R ~/.ssh; echo eingetragen'
    $publicKey | & ssh @baseOptions -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password $target $remote
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError ("Eintragen fehlgeschlagen. Häufige Gründe: falsches Passwort oder Benutzer; der Server erlaubt " +
            "keine Passwörter mehr (dann den Schlüssel über einen bestehenden Zugang oder die Konsole eintragen).")
    }

    # ------------------------------------------------------------ 4. Testen
    Write-Step "Anmeldung ohne Passwort testen"
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $check = @(& ssh @baseOptions @keyOptions $target $probeCommand)
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($code -ne 0 -or ($check -notcontains "schluessel-ok")) {
        Stop-WithError "Anmeldung mit Schlüssel klappt noch nicht. Auf dem Server KEINE Härtung ausführen, sonst sperrst du dich aus."
    }
}
Write-Host "Anmeldung mit Schlüssel klappt." -ForegroundColor Green
$remoteHost = $check | Where-Object { $_ -match '^[A-Za-z0-9._-]+$' -and $_ -ne "schluessel-ok" } | Select-Object -Last 1
if ($remoteHost) { $remoteHost = "$remoteHost".Trim() }

# ---------------------------------------------------------------- 5. Kurznamen in ~/.ssh/config
$names = @($Alias + @($remoteHost, $Server)) | Where-Object { $_ -and $_ -match '^[A-Za-z0-9._-]+$' } | Select-Object -Unique
if (-not $NoConfig) {
    Write-Step "Kurznamen in $sshDir\config: $($names -join ', ')"
    $config = Join-Path $sshDir "config"
    $existing = ""
    if (Test-Path $config) { $existing = Get-Content $config -Raw }
    if (-not $existing) { $existing = "" }
    $taken = @($names | Where-Object { $existing -match "(?mi)^\s*Host\s+(.*\s)?$([regex]::Escape($_))(\s|$)" })
    $free = @($names | Where-Object { $taken -notcontains $_ })
    if ($taken.Count -gt 0) { Write-Host "Schon vorhanden und nicht verändert: $($taken -join ', ')" }
    if ($free.Count -gt 0) {
        $block = @(
            "",
            "Host $($free -join ' ')",
            "    HostName $Server",
            "    User $User",
            "    Port $Port",
            "    IdentityFile $key",
            "    IdentitiesOnly yes",
            "    ServerAliveInterval 60",
            ""
        ) -join "`n"
        [System.IO.File]::AppendAllText($config, $block, (New-Object System.Text.UTF8Encoding $false))
        Write-Host "angelegt: $($free -join ', ')"
    }
    Set-OwnerOnlyAcl $config
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & ssh -G $names[0] 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($code -ne 0) { Stop-WithError "ssh kann $config nicht lesen – Inhalt und Rechte der Datei prüfen." }
}

# ---------------------------------------------------------------- 6. Bitwarden (optional)
$wantBitwarden = $Bitwarden
if (-not $Bitwarden -and -not $NoBitwarden -and (Test-Interactive)) {
    Write-Host ""
    $answer = Read-Host "Privaten Schlüssel für Bitwarden in die Zwischenablage legen? (j/N)"
    $wantBitwarden = $answer -match '^(j|ja|y|yes)$'
}
if ($wantBitwarden) {
    Write-Step "Schlüssel für Bitwarden"
    $mode = Set-SecretClipboard ((Get-Content $key -Raw).Trim())
    Write-Host "Der private Schlüssel liegt in der Zwischenablage ($mode)."
    Write-Host "In Bitwarden: Neues Element -> SSH-Schlüssel -> 'Schlüssel aus Zwischenablage importieren' -> Speichern."
    Write-Host "Mit Passphrase fragt Bitwarden beim Import danach."
    if (Test-Interactive) {
        $null = Read-Host "Enter drücken, wenn gespeichert – danach wird die Zwischenablage geleert"
    } else {
        Start-Sleep -Seconds 60
    }
    Clear-SecretClipboard
    Write-Host "Zwischenablage geleert."
}

# ---------------------------------------------------------------- Fertig
Write-Host ""
if ($NoConfig) {
    Write-Host "Fertig. Verbinden mit:  ssh -i $key -p $Port $target" -ForegroundColor Green
} else {
    foreach ($n in $names) { Write-Host "Fertig. Ab jetzt:  ssh $n" -ForegroundColor Green }
}
Write-Host ""
Write-Host "Fingerabdruck des Servers vergleichen (optional): auf dem Server  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
Write-Host "und hier  ssh-keygen -lF $Server"
Write-Host "Server absichern: server/ssh-haerten.sh (https://github.com/zerox80/ssh-hardening)"
