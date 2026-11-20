# Prüft unter Windows die Rechte-Korrektur aus dem Client: Eine Datei mit geerbten Rechten für andere
# (wie ein Profilordner mit Support-Konto) muss danach nur noch dem Benutzer und SYSTEM gehören,
# auch beim wiederholten Aufruf und im strengen Fehlermodus des Skripts.
$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "..\client\ssh-zugang-einrichten.ps1"
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptPath), [ref]$null, [ref]$null)
foreach ($name in "Stop-WithError", "Set-OwnerOnlyAcl") {
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
    if (-not $fn) { throw "Funktion $name nicht gefunden" }
    Invoke-Expression $fn.Extent.Text
}
$OnWindows = $true

$dir = Join-Path ([System.IO.Path]::GetTempPath()) ("acl-test-" + [guid]::NewGuid())
New-Item -ItemType Directory $dir | Out-Null
# Ordner vererbt Lesen an "Benutzer" (S-1-5-32-545) – das verweigert OpenSSH
& icacls $dir /grant "*S-1-5-32-545:(OI)(CI)R" | Out-Null
$file = Join-Path $dir "config"
Set-Content -Path $file -Value "Host probe`n    HostName 127.0.0.1"
if (-not ((& icacls $file) -match "S-1-5-32-545|BUILTIN\\Users|VORDEFINIERT\\Benutzer")) { throw "Testaufbau: geerbte Rechte fehlen" }

foreach ($run in 1, 2, 3) {
    Set-OwnerOnlyAcl $file
    $acl = Get-Acl $file
    $sids = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $expected = @($me, "S-1-5-18") | Sort-Object
    if (Compare-Object $sids $expected) { throw "Lauf ${run}: unerwartete Rechte: $($sids -join ', ')" }
    if (-not $acl.AreAccessRulesProtected) { throw "Lauf ${run}: Vererbung noch aktiv" }
    Write-Host "ok: Lauf $run – nur Benutzer und SYSTEM, keine Vererbung"
}

$previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
$out = & ssh -G -F $file probe 2>&1 | Out-String
$ErrorActionPreference = $previous
if ($out -notmatch "(?m)^hostname 127\.0\.0\.1") { throw "ssh liest die Datei nicht: $out" }
Write-Host "ok: ssh akzeptiert die Datei"
Remove-Item -Recurse -Force $dir
