# ssh-hardening

**SSH-Zugang per Schlüssel einrichten und Linux-Server absichern – von jedem PC aus, für frische und
für schon laufende Server.**

| Teil | Wofür | Läuft auf |
|---|---|---|
| [`client/ssh-zugang-einrichten.ps1`](client/ssh-zugang-einrichten.ps1) | Schlüssel anlegen, auf dem Server eintragen, `ssh <hostname>` einrichten | Windows (PowerShell 5.1 und 7), PowerShell 7 unter Linux/macOS |
| [`client/ssh-zugang-einrichten.sh`](client/ssh-zugang-einrichten.sh) | dasselbe | Linux (z. B. Fedora, Ubuntu), macOS |
| [`server/ssh-haerten.sh`](server/ssh-haerten.sh) | Nur noch Schlüssel, kein Root, keine Passwörter, fail2ban – mit Sicherheitsnetz | Ubuntu, Debian, Fedora, RHEL/Rocky/Alma, openSUSE |

## 1. Zugang einrichten (auf deinem PC)

Das Client-Skript

1. nutzt deinen vorhandenen Schlüssel (`~/.ssh/id_ed25519`) oder erzeugt einen neuen,
2. trägt ihn auf dem Server ein – **nur wenn nötig**, dafür fragt es **einmal** nach dem Server-Passwort,
3. prüft, ob die Anmeldung danach ohne Passwort klappt,
4. legt Kurznamen an: Danach genügt **`ssh <hostname>`** (der echte Name des Servers, ohne DNS-Eintrag),
5. legt auf Wunsch den privaten Schlüssel für **Bitwarden** in die Zwischenablage (siehe unten).

Es lässt sich gefahrlos wiederholen: kein doppelter Eintrag, und ist der Schlüssel schon da, wird
nicht nach dem Passwort gefragt.

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/zerox80/ssh-hardening/main/client/ssh-zugang-einrichten.ps1 -OutFile ssh-zugang-einrichten.ps1
powershell -ExecutionPolicy Bypass -File .\ssh-zugang-einrichten.ps1 -Server 192.0.2.10 -User admin
```

**Linux / macOS**:

```bash
curl -fsSLO https://raw.githubusercontent.com/zerox80/ssh-hardening/main/client/ssh-zugang-einrichten.sh
bash ssh-zugang-einrichten.sh -s 192.0.2.10 -u admin
```

| Windows | Linux/macOS | Bedeutung |
|---|---|---|
| `-Server` | `-s` | Adresse oder Name des Servers (Pflicht) |
| `-User` | `-u` | Benutzer auf dem Server (Pflicht) |
| `-Port` | `-p` | SSH-Port, Standard 22 |
| `-Alias` | `-a` | weitere Kurznamen (Hostname und Adresse kommen automatisch dazu) |
| `-KeyName` | `-k` | Name der Schlüsseldatei in `~/.ssh`, Standard `id_ed25519` |
| `-Bitwarden` | `-b` | privaten Schlüssel ohne Rückfrage für Bitwarden in die Zwischenablage |
| `-NoBitwarden` | `-B` | nicht nach Bitwarden fragen |
| `-NoConfig` | `-n` | `~/.ssh/config` nicht anfassen |

Unter Windows setzt das Skript die Dateirechte so, wie OpenSSH es verlangt: Schlüssel und
`~/.ssh/config` gehören nur dir (und SYSTEM). Das verhindert den Fehler *„Bad owner or permissions“*,
der auftritt, wenn der Profilordner Rechte an andere Konten vererbt – etwa an ein Support-Konto.

### Bitwarden

Bitwarden kann SSH-Schlüssel speichern und selbst als SSH-Agent dienen. Das Skript zeigt den privaten
Schlüssel **nicht** im Terminal an (Verlauf, Bildschirmfreigabe), sondern legt ihn auf Wunsch in die
Zwischenablage:

1. Frage „Privaten Schlüssel für Bitwarden in die Zwischenablage legen?“ mit `j` beantworten.
2. In Bitwarden: *Neues Element → SSH-Schlüssel → „Schlüssel aus Zwischenablage importieren“ → Speichern.*
3. Im Skript Enter drücken – die Zwischenablage wird geleert.

Unter Windows landet der Schlüssel dabei nicht im Zwischenablage-Verlauf (Win+V) und wird nicht
synchronisiert. Unter Linux wird `wl-copy` (Wayland, Fedora-Standard), `xclip`/`xsel` oder unter macOS
`pbcopy` verwendet.

## 2. Server absichern

Erst wenn die Anmeldung per Schlüssel klappt (Schritt 1), auf dem Server:

```bash
curl -fsSLO https://raw.githubusercontent.com/zerox80/ssh-hardening/main/server/ssh-haerten.sh
less ssh-haerten.sh                       # ansehen, was ausgeführt wird
sudo bash ssh-haerten.sh --user admin     # admin = dein Benutzer mit sudo-Rechten und SSH-Schlüssel
```

Danach **in einem neuen Fenster** testen (das alte offen lassen) und bestätigen:

```bash
sudo bash ssh-haerten.sh --confirm
```

### Was eingestellt wird

- Anmeldung nur mit Schlüssel: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `AuthenticationMethods publickey`
- Kein Root-Login (`PermitRootLogin no`; mit `--allow-root-key` nur per Schlüssel)
- `MaxAuthTries 3`, `LoginGraceTime 30`, `X11Forwarding no`, Verbindungsabbruch nach 10 Minuten Stille
- fail2ban: 5 Fehlversuche in 10 Minuten sperren die Adresse für eine Stunde
- optional: SSH nur von bestimmten Netzen (`--allow-from`), anderer Port (`--port`), nur ein Benutzer
  und keine Weiterleitungen (`--strict`)

### Sicher auch auf Servern, die schon laufen

- **Prüfungen vor jeder Änderung:** Der Benutzer muss sudo-Rechte und einen Schlüssel haben, die
  vorhandene Konfiguration muss gültig sein – sonst Abbruch, ohne etwas zu ändern.
- **Sicherung** aller SSH-Dateien nach `/var/backups/ssh-hardening/`.
- **Eigene Datei** `/etc/ssh/sshd_config.d/01-ssh-hardening.conf` statt Änderungen quer durch die Konfiguration.
  Widersprechende Einträge (z. B. `PasswordAuthentication yes` in `50-cloud-init.conf`) werden
  auskommentiert; danach prüft das Skript mit `sshd -T`, dass jeder Wert wirklich gilt.
- **Prüfung mit `sshd -t`** – bei Fehlern sofort zurück zum alten Stand.
- **Sicherheitsnetz:** Ohne `--confirm` stellt ein Timer nach 5 Minuten automatisch den alten Stand her.
  Wer sich ausgesperrt hat, wartet einfach.
- **Firewall wird nie zurückgesetzt:** Bei aktiver ufw/firewalld kommen nur Regeln für SSH dazu.
  Eine ausgeschaltete Firewall bleibt aus, außer mit `--firewall`.
- **Neuer Port:** Der alte bleibt bis `--confirm` zusätzlich offen; SELinux wird angepasst.
- **Zwei-Faktor** über `keyboard-interactive` (z. B. Schlüssel + Code) wird erkannt und bleibt erhalten.
- **`--undo`** geht Schritt für Schritt zu früheren Ständen zurück.

### Optionen

| Option | Bedeutung |
|---|---|
| `--user NAME` | Pflicht: Benutzer, der sich danach per Schlüssel anmeldet und sudo nutzen darf |
| `--port N` | SSH auf Port N verlegen (alter Port bleibt bis `--confirm` offen) |
| `--allow-from "A B"` | SSH nur von diesen Adressen/Netzen, z. B. `"192.168.1.0/24 203.0.113.7"` |
| `--firewall` | Firewall einschalten, falls aus (frischer Server) |
| `--open-ports "P …"` | mit `--firewall`: weitere Ports, z. B. `"80/tcp 443/tcp"` |
| `--strict` | nur `--user` darf sich anmelden, keine Weiterleitungen |
| `--allow-root-key` | Root weiter erlaubt, aber nur per Schlüssel |
| `--no-fail2ban` | fail2ban nicht einrichten |
| `--rollback-minutes N` | Sicherheitsnetz in Minuten (Standard 5, 0 = aus) |
| `--dry-run` | nur anzeigen, was geändert würde |
| `--confirm` | Änderung bestätigen: Sicherheitsnetz aus, alten Port und allgemeine SSH-Regeln schließen |
| `--undo` | zum Stand vor dem letzten Lauf zurück (mehrfach möglich) |

**Frischer Server**, Beispiel mit Firewall und Webserver:

```bash
sudo bash ssh-haerten.sh --user admin --firewall --open-ports "80/tcp 443/tcp" --allow-from "192.168.1.0/24"
```

## Häufige Fehler

| Meldung | Lösung |
|---|---|
| `Bad owner or permissions on …/.ssh/config` (Windows) | Client-Skript erneut starten – es setzt die Rechte richtig. |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | Server neu installiert? Dann `ssh-keygen -R <server>`. Sonst nicht verbinden und nachfragen. |
| `Permission denied (publickey)` beim Eintragen | Der Server erlaubt keine Passwörter mehr – Schlüssel über einen bestehenden Zugang oder die Konsole eintragen. |
| `… hat keine vollen sudo-Rechte` | `sudo usermod -aG sudo NAME` (Debian/Ubuntu) bzw. `wheel` (Fedora/RHEL/openSUSE) |
| Ausgesperrt | Bis zu 5 Minuten warten (Sicherheitsnetz) oder über die Konsole `sudo bash ssh-haerten.sh --undo`. |
| Neuer Port nicht erreichbar | Firewall vor dem Server (Router, Cloud) prüfen – die kennt das Skript nicht. |

## Getestet

Jede Änderung läuft durch die [CI](.github/workflows/ci.yml):

- Server-Skript auf Ubuntu 22.04/24.04, Debian 12/13, Fedora, Rocky Linux 9, AlmaLinux 9,
  openSUSE Leap 15.6 und Tumbleweed – inklusive „nicht frischer“ Server mit widersprechender
  Konfiguration, fehlender Include-Zeile, Portwechsel, Zwei-Faktor, Abbrüchen und `--undo`.
- Ende-zu-Ende auf Ubuntu mit systemd: Bash- und PowerShell-Client gegen einen echten sshd, Härtung,
  Sicherheitsnetz (ohne `--confirm` zurück, mit `--confirm` bleibt), fail2ban, `--undo`.
- Windows: PowerShell 5.1 und 7, PSScriptAnalyzer, Dateirechte; macOS mit Bash 3.2.

## Lizenz

[MIT](LICENSE)
