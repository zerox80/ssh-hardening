# Prüft den Import des privaten Schlüssels im Windows-Client.
# Teil 1: die Aufbereitung (ConvertTo-PrivateKeyText) direkt – ohne Zwischenablage.
# Teil 2: in der CI der ganze Ablauf mit -Import gegen einen nicht erreichbaren Server.
$ErrorActionPreference = "Stop"
$client = (Resolve-Path (Join-Path $PSScriptRoot "..\client\ssh-zugang-einrichten.ps1")).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("import-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null

function Assert([bool] $condition, [string] $message) { if (-not $condition) { throw "FEHLER: $message" } }

try {
    # Funktion aus dem Skript laden, ohne das Skript auszuführen
    $null = $tokens = $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($client, [ref]$tokens, [ref]$errors)
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "ConvertTo-PrivateKeyText" }, $true) | Select-Object -First 1
    Assert ($null -ne $fn) "ConvertTo-PrivateKeyText nicht gefunden"
    . ([scriptblock]::Create($fn.Extent.Text))

    $source = Join-Path $work "quelle"
    # Leere Passphrase: Windows PowerShell 5.1 (und 7.0–7.2) verschluckt leere Argumente, dort
    # braucht es '""'. Ab 7.3 käme '""' wörtlich an – dann ein echtes leeres Argument.
    $v = $PSVersionTable.PSVersion
    $emptyArg = if ($v.Major -gt 7 -or ($v.Major -eq 7 -and $v.Minor -ge 3)) { '' } else { '""' }
    & ssh-keygen -q -t ed25519 -N $emptyArg -C test -f $source
    Assert (Test-Path $source) "Testschlüssel ließ sich nicht erzeugen"
    $original = ((Get-Content $source -Raw) -replace "`r", "")
    $expected = ((Get-Content "$source.pub" -Raw).Trim() -split ' ')[0..1] -join ' '

    function Test-Variant([string] $name, [string] $text) {
        $result = ConvertTo-PrivateKeyText $text
        Assert ($null -ne $result) "$name wurde nicht erkannt"
        Assert (-not $result.Contains("`r")) "$name enthält noch CR"
        $file = Join-Path $work ($name -replace '\W', '_')
        [IO.File]::WriteAllText($file, $result, (New-Object System.Text.UTF8Encoding $false))
        & icacls $file /inheritance:r /grant:r "*$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value):F" /Q | Out-Null
        $pub = (& ssh-keygen -y -f $file) -join ''
        Assert ((($pub -split ' ')[0..1] -join ' ') -eq $expected) "$name ergibt einen anderen öffentlichen Schlüssel"
        Write-Host "ok: $name"
    }
    Test-Variant "mehrzeilig mit CRLF" ($original -replace "`n", "`r`n")
    Test-Variant "in einer Zeile" ($original -replace "`n", " ")
    Test-Variant "mit Text drumherum" ("Notiz aus Bitwarden:`n" + $original + "`nEnde")
    Assert ($null -eq (ConvertTo-PrivateKeyText "irgendein Text")) "Text ohne Schlüssel wurde angenommen"
    Assert ($null -eq (ConvertTo-PrivateKeyText "")) "leerer Text wurde angenommen"
    Write-Host "ok: Text ohne Schlüssel abgelehnt"

    # Ganzer Ablauf nur in der CI – lokal bliebe sonst ein Schlüssel in der echten Zwischenablage
    if ($env:CI) {
        $clipboardWorks = $true
        try { Set-Clipboard -Value $original; $clipboardWorks = ((Get-Clipboard -Raw) -replace "`r", "").Trim() -eq $original.Trim() } catch { $clipboardWorks = $false }
        if ($clipboardWorks) {
            $userProfile = Join-Path $work "profil"
            New-Item -ItemType Directory -Path $userProfile | Out-Null
            $previousProfile = $env:USERPROFILE
            $env:USERPROFILE = $userProfile
            try {
                $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $client -Server 127.0.0.1 -Port 1 -User test -Import -NoBitwarden 2>&1 | Out-String
            } finally { $env:USERPROFILE = $previousProfile }
            # Der Client endet absichtlich mit 1 (Server nicht erreichbar) – nicht als Testergebnis werten
            $global:LASTEXITCODE = 0
            $key = Join-Path $userProfile ".ssh\id_ed25519"
            Assert (Test-Path $key) "Import hat keine Datei angelegt:`n$out"
            Assert ($out -match "Zwischenablage geleert") "Zwischenablage nicht geleert:`n$out"
            Assert ($out -match "nicht erreichbar") "Lauf ging nicht bis zur Verbindung:`n$out"
            Write-Host "ok: -Import legt den Schlüssel an und leert die Zwischenablage"
        } else {
            Write-Host "Zwischenablage auf diesem Runner nicht nutzbar – Teil 2 übersprungen"
        }
    }
    Write-Host ""
    Write-Host "==== Windows-Import: alle Prüfungen bestanden"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
exit 0
