#!/usr/bin/env bash
# =====================================================================
# ssh-haerten.sh – SSH auf einem Linux-Server absichern, frisch installiert oder schon in Betrieb.
# https://github.com/zerox80/ssh-hardening
#
#   sudo bash ssh-haerten.sh --user NAME [Optionen]
#
# Was passiert:
#   * Anmeldung nur noch mit SSH-Schlüssel, kein Root-Login, keine Passwörter.
#   * Eigene Konfiguration in /etc/ssh/sshd_config.d/01-ssh-hardening.conf; widersprechende Einträge
#     anderer Dateien (z. B. 50-cloud-init.conf) werden auskommentiert.
#   * Vorher: Sicherung aller SSH-Dateien, Prüfung mit "sshd -t", Abbruch ohne Änderung bei Fehlern.
#   * Sicherheitsnetz: Ohne "--confirm" stellt ein Timer nach 5 Minuten den alten Stand wieder her.
#   * Firewall (ufw/firewalld) wird nie zurückgesetzt – es kommen nur Regeln für SSH dazu.
#   * fail2ban für SSH.
#
# Unterstützt: Debian, Ubuntu, Fedora, RHEL/Rocky/Alma, openSUSE (OpenSSH ab 8.2, systemd).
# =====================================================================
set -euo pipefail

readonly VERSION="1.0.0"
readonly DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly DROPIN="$DROPIN_DIR/01-ssh-hardening.conf"
readonly MAIN_CONFIG="/etc/ssh/sshd_config"
# openSUSE Tumbleweed/Leap 16: oft nur die Herstellerdatei unter /usr/etc – die wird nie verändert.
VENDOR_CONFIG=""
if [[ ! -f "$MAIN_CONFIG" && -f /usr/etc/ssh/sshd_config ]]; then VENDOR_CONFIG="/usr/etc/ssh/sshd_config"; fi
readonly BACKUP_ROOT="/var/backups/ssh-hardening"
readonly STATE_DIR="/var/lib/ssh-hardening"
readonly STATE="$STATE_DIR/pending"
readonly ROLLBACK_UNIT="ssh-hardening-rollback"
readonly FAIL2BAN_JAIL="/etc/fail2ban/jail.d/ssh-hardening.local"
# Für automatische Tests in Containern ohne systemd: nur Konfiguration schreiben und prüfen.
readonly TEST_MODE="${SSH_HARDENING_TEST:-0}"

admin_user=""
new_port=""
allow_from=""
enable_firewall=0
open_ports=""
strict=0
use_fail2ban=1
rollback_minutes=5
dry_run=0
action="apply"
root_key=0

usage() {
  cat <<'EOF'
Aufruf: sudo bash ssh-haerten.sh --user NAME [Optionen]

Pflicht:
  --user NAME            Benutzer, der sich danach per Schlüssel anmeldet und sudo nutzen darf.
                         Er braucht einen Schlüssel in ~/.ssh/authorized_keys (sonst Abbruch).

Optionen:
  --port N               SSH auf Port N verlegen. Der alte Port bleibt bis "--confirm" zusätzlich offen.
  --allow-from "A B"     SSH nur von diesen Adressen/Netzen (z. B. "192.168.1.0/24 203.0.113.7").
                         Wirkt über die Firewall; allgemeine SSH-Regeln entfernt erst "--confirm".
  --firewall             Firewall einschalten, falls aus (frischer Server). Ohne diese Option wird eine
                         ausgeschaltete Firewall nicht angefasst.
  --open-ports "P …"     Mit --firewall: weitere Ports freigeben, z. B. "80/tcp 443/tcp".
  --strict               Zusätzlich: nur --user darf sich anmelden (AllowUsers), keine Weiterleitungen.
                         Auf Servern mit mehreren SSH-Nutzern vorher abstimmen.
  --allow-root-key       Root darf sich weiter anmelden, aber nur mit Schlüssel (prohibit-password).
  --no-fail2ban          fail2ban nicht einrichten.
  --rollback-minutes N   Sicherheitsnetz in Minuten (Standard 5, 0 = aus).
  --dry-run              Nur anzeigen, was geändert würde.

Danach:
  --confirm              Neue Anmeldung hat geklappt: Sicherheitsnetz beenden, alten Port und
                         allgemeine SSH-Regeln (bei --allow-from) schließen.
  --undo                 Sofort zum Stand vor dem letzten Lauf zurück.
  --version              Version anzeigen.
EOF
}

say()  { printf '\033[36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[33m    Achtung: %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31mABBRUCH: %s\033[0m\n' "$*" >&2; exit 1; }
run()  { if (( dry_run )); then echo "    [dry-run] $*"; else "$@"; fi; }

while (( $# )); do
  case "$1" in
    --user) admin_user="${2:-}"; shift 2 ;;
    --port) new_port="${2:-}"; shift 2 ;;
    --allow-from) allow_from="${2:-}"; shift 2 ;;
    --firewall) enable_firewall=1; shift ;;
    --open-ports) open_ports="${2:-}"; shift 2 ;;
    --strict) strict=1; shift ;;
    --allow-root-key) root_key=1; shift ;;
    --no-fail2ban) use_fail2ban=0; shift ;;
    --rollback-minutes) rollback_minutes="${2:-}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --confirm) action="confirm"; shift ;;
    --undo) action="undo"; shift ;;
    --version) echo "ssh-haerten.sh $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "Unbekannte Option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "Bitte mit sudo bzw. als root ausführen."

# ---------------------------------------------------------------- Umgebung erkennen
SSHD="$(command -v sshd || true)"
[[ -n "$SSHD" ]] || for c in /usr/sbin/sshd /usr/bin/sshd; do [[ -x "$c" ]] && SSHD="$c" && break; done
[[ -n "$SSHD" ]] || fail "sshd nicht gefunden – ist der OpenSSH-Server installiert?"

pkg_install() {
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q "$@" >/dev/null
  elif command -v yum >/dev/null; then yum install -y -q "$@" >/dev/null
  elif command -v zypper >/dev/null; then zypper -q -n install "$@" >/dev/null
  else return 1; fi
}

ssh_service() {
  if systemctl list-unit-files ssh.service >/dev/null 2>&1 && systemctl list-unit-files ssh.service | grep -q '^ssh\.service'; then
    echo ssh
  else
    echo sshd
  fi
}

# Effektive Einstellung laut sshd (berücksichtigt alle Dateien in der richtigen Reihenfolge).
effective() { "$SSHD" -T 2>/dev/null | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print }'; }

reload_ssh() {
  (( TEST_MODE )) && return 0
  local service; service="$(ssh_service)"
  # Ubuntu ab 22.10: Socket-Aktivierung. Ports legt dann ssh.socket fest – nach daemon-reload neu starten.
  if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl daemon-reload
    systemctl restart ssh.socket
  fi
  if systemctl is-active --quiet "$service"; then
    systemctl reload "$service" || systemctl restart "$service"
  fi
}

firewall_kind() {
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then echo ufw-active
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then echo firewalld-active
  elif command -v ufw >/dev/null; then echo ufw-inactive
  elif command -v firewall-cmd >/dev/null; then echo firewalld-inactive
  else echo none; fi
}

# Regeln für einen SSH-Port anlegen (nichts wird gelöscht oder zurückgesetzt).
firewall_allow_ssh() {
  local kind="$1" port="$2" src zone
  case "$kind" in
    ufw*)
      if [[ -n "$allow_from" ]]; then
        for src in $allow_from; do run ufw allow from "$src" to any port "$port" proto tcp comment "ssh-hardening" >/dev/null; done
      else
        run ufw limit "$port/tcp" comment "ssh-hardening" >/dev/null
      fi ;;
    firewalld*)
      zone="$(firewall-cmd --get-default-zone)"
      if [[ -n "$allow_from" ]]; then
        for src in $allow_from; do
          local family=ipv4; [[ "$src" == *:* ]] && family=ipv6
          run firewall-cmd -q --permanent --zone="$zone" --add-rich-rule="rule family=\"$family\" source address=\"$src\" port port=\"$port\" protocol=\"tcp\" accept"
        done
      else
        run firewall-cmd -q --permanent --zone="$zone" --add-port="$port/tcp"
      fi
      run firewall-cmd -q --reload ;;
  esac
}

# ---------------------------------------------------------------- Rückgängig machen
# Sicherungen heißen JJJJMMTT-hhmmss bzw. JJJJMMTT-hhmmss-NN; benutzte bekommen "-rueckgaengig" angehängt.
latest_backup() {
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
    | grep -E '/[0-9]{8}-[0-9]{6}(-[0-9]{2})?$' | sort | tail -n 1 || true
}

if [[ "$action" == "undo" ]]; then
  latest="$(latest_backup)"
  [[ -n "$latest" && -f "$latest/rollback.sh" ]] || fail "Keine (weitere) Sicherung gefunden ($BACKUP_ROOT)."
  say "Stelle den Stand aus $latest wieder her"
  if (( ! TEST_MODE )); then systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true; fi
  SSH_HARDENING_TEST="$TEST_MODE" bash "$latest/rollback.sh"
  # Als benutzt markieren: ein weiteres --undo geht noch einen Schritt zurück.
  mv "$latest" "$latest-rueckgaengig"
  ok "Fertig. SSH läuft wieder mit der vorherigen Konfiguration."
  exit 0
fi

# ---------------------------------------------------------------- Bestätigen
if [[ "$action" == "confirm" ]]; then
  [[ -f "$STATE" ]] || { ok "Nichts offen – keine unbestätigte Änderung."; exit 0; }
  pending_new_port="" pending_old_ports="" pending_all_ports="" pending_allow_from="" pending_firewall="none"
  # shellcheck disable=SC1090
  source "$STATE"
  say "Bestätigung: Sicherheitsnetz beenden"
  if (( ! TEST_MODE )); then
    systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
    systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
  fi
  if [[ -n "${pending_old_ports:-}" ]]; then
    say "Alten Port schließen: $pending_old_ports"
    sed -i "/^Port /d" "$DROPIN"
    sed -i "1a Port ${pending_new_port}" "$DROPIN"
    "$SSHD" -t || fail "sshd -t meldet Fehler – nichts geändert."
    if (( ! TEST_MODE )); then
      for p in $pending_old_ports; do
        case "${pending_firewall:-none}" in
          ufw*) ufw delete limit "$p/tcp" >/dev/null 2>&1 || true; ufw delete allow "$p/tcp" >/dev/null 2>&1 || true ;;
          firewalld*) firewall-cmd -q --permanent --remove-port="$p/tcp" 2>/dev/null || true ;;
        esac
      done
      [[ "${pending_firewall:-}" == firewalld* ]] && firewall-cmd -q --reload
    fi
    reload_ssh
  fi
  if [[ -n "${pending_allow_from:-}" && "${pending_firewall:-none}" != none ]] && (( ! TEST_MODE )); then
    say "Allgemeine SSH-Freigaben entfernen (nur noch: $pending_allow_from)"
    for p in ${pending_all_ports:-22}; do
      case "$pending_firewall" in
        ufw*)
          ufw delete allow OpenSSH >/dev/null 2>&1 || true
          ufw delete allow "$p/tcp" >/dev/null 2>&1 || true
          ufw delete allow "$p" >/dev/null 2>&1 || true
          ufw delete limit "$p/tcp" >/dev/null 2>&1 || true ;;
        firewalld*)
          firewall-cmd -q --permanent --remove-service=ssh 2>/dev/null || true
          firewall-cmd -q --permanent --remove-port="$p/tcp" 2>/dev/null || true ;;
      esac
    done
    [[ "$pending_firewall" == firewalld* ]] && firewall-cmd -q --reload
  fi
  rm -f "$STATE"
  ok "Bestätigt. Die Härtung bleibt dauerhaft aktiv."
  exit 0
fi

# ---------------------------------------------------------------- Prüfungen vor jeder Änderung
say "ssh-haerten.sh $VERSION – Prüfungen"
[[ -f "$STATE" ]] && fail "Eine frühere Änderung ist noch unbestätigt. Erst testen und 'sudo bash $0 --confirm' oder '--undo' ausführen."
[[ -n "$admin_user" ]] || { usage >&2; fail "--user fehlt."; }
getent passwd "$admin_user" >/dev/null || fail "Benutzer '$admin_user' existiert nicht."
[[ -z "$new_port" || ( "$new_port" =~ ^[0-9]+$ && new_port -ge 1 && new_port -le 65535 ) ]] || fail "--port muss eine Zahl zwischen 1 und 65535 sein."
[[ "$rollback_minutes" =~ ^[0-9]+$ ]] || fail "--rollback-minutes muss eine Zahl sein."

ssh_version="$("$SSHD" -V 2>&1 | head -n 1 || true)"
[[ -n "$ssh_version" ]] || ssh_version="$(ssh -V 2>&1 || true)"
if [[ "$ssh_version" =~ OpenSSH_([0-9]+)\.([0-9]+) ]]; then
  (( BASH_REMATCH[1] > 8 || ( BASH_REMATCH[1] == 8 && BASH_REMATCH[2] >= 2 ) )) || fail "OpenSSH ab 8.2 nötig (gefunden: $ssh_version)."
fi
"$SSHD" -t || fail "Die vorhandene SSH-Konfiguration ist schon fehlerhaft (sshd -t). Bitte zuerst beheben."
ok "Konfiguration gültig ($ssh_version)"

if [[ "$admin_user" == root ]]; then
  root_key=1
  warn "--user root: Root bleibt per Schlüssel erreichbar (prohibit-password). Besser ist ein eigener Benutzer mit sudo."
else
  # sudo zeigt je nach Regel "(ALL) ALL", "(ALL : ALL) ALL" (Gruppen sudo/wheel), "(root) NOPASSWD: ALL" …
  if ! sudo -l -U "$admin_user" 2>/dev/null | grep -Eq '\((ALL|root)( *: *ALL)?\) +([A-Z_]+: *)*ALL *$'; then
    fail "'$admin_user' hat keine vollen sudo-Rechte. Ohne Root-Login sperrst du dich sonst aus. Z. B.: usermod -aG sudo $admin_user (Debian/Ubuntu) bzw. usermod -aG wheel $admin_user (Fedora/RHEL/openSUSE)."
  fi
  ok "'$admin_user' hat sudo-Rechte"
fi

# Schlüssel des Benutzers: alle Pfade aus der effektiven Konfiguration für genau diesen Benutzer.
home_dir="$(getent passwd "$admin_user" | cut -d: -f6)"
key_files="$("$SSHD" -T -C "user=$admin_user,host=localhost,addr=127.0.0.1" 2>/dev/null | awk '$1 == "authorizedkeysfile" { $1 = ""; print }')"
[[ -n "$key_files" ]] || key_files=".ssh/authorized_keys"
has_key=0
for f in $key_files; do
  f="${f//%h/$home_dir}"; f="${f//%u/$admin_user}"; f="${f//%%/%}"
  [[ "$f" == /* ]] || f="$home_dir/$f"
  if [[ -s "$f" ]] && grep -Eq '(^|[ ,"])(ssh-(ed25519|rsa|dss)|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+) [A-Za-z0-9+/=]+' "$f"; then
    has_key=1
    # StrictModes: zu offene Rechte würden den Schlüssel stillschweigend ungültig machen.
    if [[ "$f" == "$home_dir/.ssh/"* ]]; then
      run chmod go-w "$home_dir"
      run chmod 700 "$home_dir/.ssh"
      run chmod 600 "$f"
      run chown "$admin_user": "$home_dir/.ssh" "$f"
    fi
  fi
done
(( has_key )) || fail "'$admin_user' hat keinen SSH-Schlüssel in: $key_files. Zuerst einen Schlüssel eintragen (z. B. mit dem Client-Skript), sonst sperrst du dich aus."
ok "'$admin_user' hat einen SSH-Schlüssel"

mapfile -t current_ports < <("$SSHD" -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -un)
(( ${#current_ports[@]} )) || current_ports=(22)
old_ports=""
if [[ -n "$new_port" ]]; then
  for p in "${current_ports[@]}"; do [[ "$p" != "$new_port" ]] && old_ports+="$p "; done
  old_ports="${old_ports% }"
fi
fw="$(firewall_kind)"

# ---------------------------------------------------------------- Neue Konfiguration
current_methods="$(effective authenticationmethods)"
# Auch Dateien prüfen, die sshd gerade (noch) nicht liest – z. B. wenn die Include-Zeile fehlt und
# erst gleich ergänzt wird. Sonst würde eine vorhandene Zwei-Faktor-Regel übersehen.
file_methods=""
for f in "$MAIN_CONFIG" "$VENDOR_CONFIG" "$DROPIN_DIR"/*.conf; do
  [[ -n "$f" && -f "$f" && "$f" != "$DROPIN" ]] || continue
  file_methods+="$(awk 'tolower($1) == "authenticationmethods" { $1 = ""; print }' "$f") "
done
file_methods="${file_methods//[[:space:]]/}"
# Zwei-Faktor über keyboard-interactive (z. B. Schlüssel + Code): diesen Weg nicht abschalten.
mfa=0
[[ "$current_methods $file_methods" == *keyboard-interactive* ]] && mfa=1
{
  echo "# Verwaltet von ssh-hardening $VERSION (https://github.com/zerox80/ssh-hardening) – nicht von Hand ändern."
  if [[ -n "$new_port" ]]; then
    echo "Port $new_port"
    for p in $old_ports; do echo "Port $p"; done
  fi
  if (( root_key )); then echo "PermitRootLogin prohibit-password"; else echo "PermitRootLogin no"; fi
  echo "PasswordAuthentication no"
  if (( ! mfa )); then echo "KbdInteractiveAuthentication no"; fi
  echo "PermitEmptyPasswords no"
  echo "PubkeyAuthentication yes"
  # Vorhandene Mehr-Faktor-Regeln (z. B. "publickey,keyboard-interactive") nicht überschreiben.
  if [[ ( -z "$current_methods" || "$current_methods" == "any" ) && -z "$file_methods" ]]; then echo "AuthenticationMethods publickey"; fi
  echo "MaxAuthTries 3"
  echo "LoginGraceTime 30"
  echo "X11Forwarding no"
  echo "ClientAliveInterval 300"
  echo "ClientAliveCountMax 2"
  if (( strict )); then
    echo "AllowUsers $admin_user"
    echo "AllowTcpForwarding no"
    echo "AllowAgentForwarding no"
    echo "PermitTunnel no"
  fi
} > "/tmp/ssh-hardening.$$"
trap 'rm -f "/tmp/ssh-hardening.$$"' EXIT

say "Geplante SSH-Einstellungen ($DROPIN):"
sed 's/^/      /' "/tmp/ssh-hardening.$$"
if [[ -n "$new_port" ]]; then
  echo "      Port: neu $new_port${old_ports:+, alt ($old_ports) bleibt bis --confirm offen}"
fi
echo "      Firewall: $fw${allow_from:+, SSH nur von: $allow_from}"
if (( dry_run )); then ok "Probelauf – nichts geändert."; exit 0; fi

# ---------------------------------------------------------------- Sicherung
stamp="$(date +%Y%m%d-%H%M%S)"
# Zwei Läufe in derselben Sekunde dürfen sich nicht überschreiben
if [[ -e "$BACKUP_ROOT/$stamp" || -e "$BACKUP_ROOT/$stamp-rueckgaengig" ]]; then
  for n in $(seq -w 2 99); do
    [[ -e "$BACKUP_ROOT/$stamp-$n" || -e "$BACKUP_ROOT/$stamp-$n-rueckgaengig" ]] || { stamp="$stamp-$n"; break; }
  done
fi
backup="$BACKUP_ROOT/$stamp"
say "Sicherung nach $backup"
mkdir -p "$backup/sshd_config.d" "$STATE_DIR"
chmod 700 "$BACKUP_ROOT" "$backup"
[[ -f "$MAIN_CONFIG" ]] && cp -a "$MAIN_CONFIG" "$backup/sshd_config"
if [[ -d "$DROPIN_DIR" ]]; then
  cp -a "$DROPIN_DIR/." "$backup/sshd_config.d/" 2>/dev/null || true
fi
[[ -f "$FAIL2BAN_JAIL" ]] && cp -a "$FAIL2BAN_JAIL" "$backup/fail2ban-jail.local"

cat > "$backup/rollback.sh" <<EOF
#!/usr/bin/env bash
# Stellt die SSH-Konfiguration vom $stamp wieder her und hält SSH erreichbar.
set -u
if [[ -f "$backup/sshd_config" ]]; then cp -a "$backup/sshd_config" "$MAIN_CONFIG"; fi
mkdir -p "$DROPIN_DIR"
find "$DROPIN_DIR" -mindepth 1 -maxdepth 1 -name '*.conf' -delete
cp -a "$backup/sshd_config.d/." "$DROPIN_DIR/" 2>/dev/null || true
if [[ "\${SSH_HARDENING_TEST:-0}" != 1 ]]; then
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    for p in ${current_ports[*]}; do ufw allow "\$p/tcp" >/dev/null 2>&1 || true; done
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    for p in ${current_ports[*]}; do firewall-cmd -q --permanent --add-port="\$p/tcp" || true; done
    firewall-cmd -q --reload || true
  fi
  if [[ -f "$backup/fail2ban-jail.local" ]]; then cp -a "$backup/fail2ban-jail.local" "$FAIL2BAN_JAIL"; else rm -f "$FAIL2BAN_JAIL"; fi
  systemctl reload fail2ban 2>/dev/null || true
  systemctl daemon-reload
  systemctl is-active --quiet ssh.socket && systemctl restart ssh.socket
  for s in ssh sshd; do systemctl is-active --quiet "\$s" && { systemctl reload "\$s" || systemctl restart "\$s"; }; done
fi
rm -f "$STATE"
logger -t ssh-hardening "Sicherung $stamp wiederhergestellt" 2>/dev/null || true
echo "ssh-hardening: Stand vom $stamp wiederhergestellt."
EOF
chmod 700 "$backup/rollback.sh"
ok "gesichert"

restore_and_fail() {
  SSH_HARDENING_TEST=1 bash "$backup/rollback.sh" >/dev/null
  fail "$1 – vorherige Konfiguration wiederhergestellt, nichts geändert."
}

# ---------------------------------------------------------------- Schreiben und prüfen
say "SSH-Konfiguration schreiben"
mkdir -p "$DROPIN_DIR"
if [[ -n "$VENDOR_CONFIG" ]]; then
  grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$VENDOR_CONFIG" \
    || restore_and_fail "$VENDOR_CONFIG bindet $DROPIN_DIR nicht ein"
elif ! grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$MAIN_CONFIG"; then
  # Ältere oder angepasste Konfiguration ohne Include: an den Anfang setzen, damit die Werte gelten.
  sed -i "1i Include $DROPIN_DIR/*.conf" "$MAIN_CONFIG"
  ok "Include-Zeile am Anfang von $MAIN_CONFIG ergänzt"
fi
install -m 600 "/tmp/ssh-hardening.$$" "$DROPIN"
"$SSHD" -t || restore_and_fail "sshd -t meldet Fehler"

# Bei sshd gilt der ERSTE Wert. Steht dieselbe Einstellung vor unserer Datei (z. B. im Kopf von
# sshd_config oder in 00-*.conf), wird sie dort im globalen Teil auskommentiert.
expect() { # Schlüssel Wert
  local value; value="$(effective "$1")"
  [[ "${value,,}" == "${2,,}" ]]
}
fix_conflict() { # Direktive
  local directive="$1" file
  for file in "$MAIN_CONFIG" "$DROPIN_DIR"/*.conf; do
    [[ -f "$file" && "$file" != "$DROPIN" ]] || continue
    # nur bis zum ersten "Match"-Block – dort gelten Einstellungen bedingt
    # Schlüsselwörter sind bei sshd unabhängig von Groß-/Kleinschreibung; awk ohne gawk-Erweiterungen.
    awk -v d="$directive" 'BEGIN { m = 0 }
      { k = tolower($1); sub(/=.*/, "", k) }
      k == "match" { m = 1 }
      { if (!m && k == tolower(d)) print "# ssh-hardening: " $0; else print }' "$file" > "$file.ssh-hardening.tmp"
    if ! cmp -s "$file" "$file.ssh-hardening.tmp"; then
      cat "$file.ssh-hardening.tmp" > "$file"
      ok "Widerspruch auskommentiert: $directive in $file"
    fi
    rm -f "$file.ssh-hardening.tmp"
  done
}
declare -A wanted=(
  [passwordauthentication]="no"
  [pubkeyauthentication]="yes"
  [permitemptypasswords]="no"
  [maxauthtries]="3"
  [x11forwarding]="no"
)
(( mfa )) || wanted[kbdinteractiveauthentication]="no"
if (( root_key )); then wanted[permitrootlogin]="without-password"; else wanted[permitrootlogin]="no"; fi
for key in "${!wanted[@]}"; do
  if ! expect "$key" "${wanted[$key]}"; then
    # "prohibit-password" zeigt sshd -T als "without-password" an
    [[ "$key" == permitrootlogin && "$(effective permitrootlogin)" == "prohibit-password" && "${wanted[$key]}" == "without-password" ]] && continue
    fix_conflict "$key"
  fi
done
"$SSHD" -t || restore_and_fail "sshd -t meldet nach dem Bereinigen Fehler"
for key in "${!wanted[@]}"; do
  v="$(effective "$key")"
  if [[ "${v,,}" != "${wanted[$key],,}" && ! ( "$key" == permitrootlogin && "$v" == "prohibit-password" && "${wanted[$key]}" == "without-password" ) ]]; then
    restore_and_fail "Einstellung $key ist '$v' statt '${wanted[$key]}' (vermutlich in einem Match-Block)"
  fi
done
ok "sshd -t in Ordnung, alle Werte wirksam"

# ---------------------------------------------------------------- SELinux (Fedora/RHEL) bei neuem Port
if [[ -n "$new_port" && "$new_port" != 22 ]] && command -v getenforce >/dev/null && [[ "$(getenforce 2>/dev/null)" != Disabled ]] && (( ! TEST_MODE )); then
  command -v semanage >/dev/null || pkg_install policycoreutils-python-utils || true
  if command -v semanage >/dev/null; then
    semanage port -a -t ssh_port_t -p tcp "$new_port" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$new_port"
    ok "SELinux erlaubt SSH auf Port $new_port"
  else
    restore_and_fail "SELinux aktiv, aber semanage fehlt – Port $new_port lässt sich nicht freigeben"
  fi
fi

# ---------------------------------------------------------------- Zustand für --confirm
cat > "$STATE" <<EOF
pending_backup="$backup"
pending_new_port="$new_port"
pending_old_ports="$old_ports"
pending_all_ports="${current_ports[*]}${new_port:+ $new_port}"
pending_allow_from="$allow_from"
pending_firewall="$fw"
EOF
chmod 600 "$STATE"

# ---------------------------------------------------------------- Sicherheitsnetz vor dem Neuladen
if (( TEST_MODE )); then
  :
elif (( rollback_minutes > 0 )) && command -v systemd-run >/dev/null; then
  systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
  systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
  systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active="${rollback_minutes}m" /bin/bash "$backup/rollback.sh"
  say "Sicherheitsnetz: ohne Bestätigung in $rollback_minutes Minuten automatisch zurück zum alten Stand"
else
  warn "Kein automatisches Zurücksetzen (systemd-run fehlt oder --rollback-minutes 0)."
fi

# ---------------------------------------------------------------- Firewall
if (( ! TEST_MODE )); then
  ports_now="${new_port:-${current_ports[*]}}"
  case "$fw" in
    ufw-active|firewalld-active)
      say "Firewall ($fw): SSH-Regeln ergänzen"
      for p in $ports_now; do firewall_allow_ssh "$fw" "$p"; done
      ok "Regeln ergänzt (nichts gelöscht)" ;;
    *)
      if (( enable_firewall )); then
        say "Firewall einschalten"
        if [[ "$fw" == none ]]; then
          if command -v apt-get >/dev/null; then pkg_install ufw && fw=ufw-inactive
          else pkg_install firewalld && fw=firewalld-inactive; fi
        fi
        case "$fw" in
          ufw-inactive)
            ufw default deny incoming >/dev/null
            ufw default allow outgoing >/dev/null
            for p in $ports_now; do firewall_allow_ssh ufw "$p"; done
            for p in $open_ports; do ufw allow "$p" comment "ssh-hardening --open-ports" >/dev/null; done
            ufw --force enable >/dev/null
            fw=ufw-active ;;
          firewalld-inactive)
            systemctl enable --now firewalld >/dev/null 2>&1
            for p in $ports_now; do firewall_allow_ssh firewalld "$p"; done
            for p in $open_ports; do firewall-cmd -q --permanent --add-port="$p"; done
            firewall-cmd -q --reload
            fw=firewalld-active ;;
        esac
        sed -i "s/^pending_firewall=.*/pending_firewall=\"$fw\"/" "$STATE"
        ok "Firewall aktiv ($fw)"
      elif [[ -n "$allow_from" || -n "$new_port" ]]; then
        warn "Firewall ist aus – --allow-from wirkt erst mit Firewall (--firewall). Gibt es eine Firewall davor (Router, Cloud), dort den Port freigeben."
      else
        echo "    Firewall ist aus und bleibt unverändert (einschalten mit --firewall)."
      fi ;;
  esac
fi

# ---------------------------------------------------------------- fail2ban
if (( use_fail2ban )) && (( ! TEST_MODE )); then
  say "fail2ban für SSH"
  if ! command -v fail2ban-client >/dev/null; then
    if command -v apt-get >/dev/null; then pkg_install fail2ban python3-systemd || true; else pkg_install fail2ban || true; fi
  fi
  if command -v fail2ban-client >/dev/null; then
    f2b_ports="$(echo "${new_port:-} ${current_ports[*]}" | xargs -n1 | sort -un | paste -sd, -)"
    mkdir -p "$(dirname "$FAIL2BAN_JAIL")"
    cat > "$FAIL2BAN_JAIL" <<EOF
# Verwaltet von ssh-hardening – eigene Ausnahmen bitte in einer anderen Datei.
[sshd]
enabled  = true
port     = $f2b_ports
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1 ${allow_from}
EOF
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban || warn "fail2ban ließ sich nicht starten – 'journalctl -u fail2ban' prüfen."
    ok "fail2ban aktiv (5 Fehlversuche in 10 Minuten = 1 Stunde Sperre)"
  else
    warn "fail2ban nicht installierbar (auf RHEL/Rocky/Alma braucht es EPEL: dnf install epel-release)."
  fi
fi

# ---------------------------------------------------------------- SSH neu laden
say "SSH neu laden"
reload_ssh
if (( ! TEST_MODE )) && command -v ss >/dev/null; then
  for p in ${new_port:-${current_ports[*]}}; do
    if ss -tln | grep -Eq "[:.]${p}[[:space:]]"; then
      ok "SSH lauscht auf Port $p"
    else
      warn "Port $p lauscht (noch) nicht – 'ss -tlnp' prüfen (bei Socket-Aktivierung startet sshd erst bei der ersten Verbindung)."
    fi
  done
fi

# ---------------------------------------------------------------- Abschluss
echo ""
printf '\033[32mFertig.\033[0m Jetzt in einem NEUEN Fenster testen (dieses offen lassen):\n'
echo "    ssh ${new_port:+-p $new_port }$admin_user@<server>"
echo ""
echo "Klappt die Anmeldung:   sudo bash $0 --confirm"
if (( rollback_minutes > 0 )) && (( ! TEST_MODE )); then
  echo "Sonst passiert nichts weiter: In $rollback_minutes Minuten gilt automatisch wieder der alte Stand."
fi
echo "Sofort zurück:          sudo bash $0 --undo"
echo "Sicherung:              $backup"
