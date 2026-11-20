#!/usr/bin/env bash
# Ende-zu-Ende auf einer echten Ubuntu-Maschine mit systemd (GitHub-Runner):
#   1. Client (Bash) und Client (PowerShell 7) gegen den lokalen sshd – mit Passwort, wie bei einem frischen Server
#   2. Härtung mit echtem Neuladen von sshd, fail2ban und Sicherheitsnetz
#   3. Ohne --confirm: automatisch zurück · mit --confirm: bleibt · --undo: zurück
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)"
pw='Probe-Passwort-123'
step() { echo; echo "################ $*"; }
fail() { echo "FEHLER: $*"; exit 1; }

step "sshd wie auf einem frischen Server vorbereiten"
sudo apt-get update -qq >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null
id probe >/dev/null 2>&1 || sudo useradd -m -s /bin/bash -G sudo probe
echo "probe:$pw" | sudo chpasswd
# Passwort-Login erlaubt – absichtlich in einer Datei, die VOR der Härtungsdatei gelesen wird
printf 'PasswordAuthentication yes\nKbdInteractiveAuthentication yes\n' | sudo tee /etc/ssh/sshd_config.d/00-test.conf >/dev/null
sudo systemctl daemon-reload
if systemctl list-unit-files ssh.socket 2>/dev/null | grep -q '^ssh.socket'; then sudo systemctl restart ssh.socket; fi
sudo systemctl restart ssh 2>/dev/null || true
sleep 2

askpass="$(mktemp)"
cat > "$askpass" <<EOF
#!/bin/sh
echo '$pw'
EOF
chmod +x "$askpass"
export SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force
mkdir -p ~/.ssh && chmod 700 ~/.ssh

password_login() {
  ssh -o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive \
      -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 probe@127.0.0.1 true </dev/null 2>/dev/null
}
password_login || fail "Passwort-Login vor der Härtung klappt nicht (Testaufbau)"
echo "ok: Passwort-Login vor der Härtung"

step "Client (Bash)"
rm -f ~/.ssh/id_ed25519_probe ~/.ssh/id_ed25519_probe.pub
ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519_probe
bash "$src/client/ssh-zugang-einrichten.sh" -s 127.0.0.1 -u probe -k id_ed25519_probe -a probe-server -B </dev/null
[[ "$(ssh -o BatchMode=yes probe-server whoami)" == probe ]] || fail "ssh probe-server"
echo "ok: ssh probe-server"
host="$(hostname -s 2>/dev/null || uname -n)"
ssh -o BatchMode=yes "$host" true || fail "ssh $host (Hostname als Kurzname)"
echo "ok: ssh $host"
out="$(SSH_ASKPASS=/bin/false bash "$src/client/ssh-zugang-einrichten.sh" -s 127.0.0.1 -u probe -k id_ed25519_probe -B </dev/null)"
grep -q "schon eingetragen" <<<"$out" || fail "zweiter Lauf hätte ohne Passwort durchlaufen müssen"
[[ "$(ssh -o BatchMode=yes probe-server 'grep -c . ~/.ssh/authorized_keys')" == 1 ]] || fail "Schlüssel doppelt eingetragen"
echo "ok: Wiederholung ohne Passwort und ohne doppelten Eintrag"

step "Client (PowerShell 7)"
if command -v pwsh >/dev/null; then
  rm -f ~/.ssh/id_ed25519_pwsh ~/.ssh/id_ed25519_pwsh.pub
  ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519_pwsh
  pwsh -NoProfile -File "$src/client/ssh-zugang-einrichten.ps1" -Server 127.0.0.1 -User probe -KeyName id_ed25519_pwsh -Alias probe-pwsh -NoBitwarden </dev/null
  [[ "$(ssh -o BatchMode=yes probe-pwsh whoami)" == probe ]] || fail "ssh probe-pwsh"
  echo "ok: PowerShell-Client"
else
  echo "pwsh nicht vorhanden – übersprungen"
fi

step "Härten (echtes systemd, Sicherheitsnetz 1 Minute)"
sudo bash "$src/server/ssh-haerten.sh" --user probe --rollback-minutes 1
ssh -o BatchMode=yes probe-server true || fail "Schlüssel-Login nach der Härtung"
echo "ok: Schlüssel-Login nach der Härtung"
if password_login; then fail "Passwort-Login geht nach der Härtung noch"; fi
echo "ok: Passwort-Login gesperrt"
systemctl list-timers --all | grep -q ssh-hardening-rollback || fail "Sicherheitsnetz-Timer fehlt"
echo "ok: Sicherheitsnetz aktiv"

step "Ohne --confirm: automatisch zurück"
sleep 80
password_login || fail "Sicherheitsnetz hat nicht zurückgesetzt"
sudo test ! -f /var/lib/ssh-hardening/pending || fail "offener Zustand nach Zurücksetzen"
echo "ok: nach Ablauf automatisch zurück"

step "Härten und bestätigen"
sudo bash "$src/server/ssh-haerten.sh" --user probe --rollback-minutes 1
sudo bash "$src/server/ssh-haerten.sh" --confirm
sleep 80
if password_login; then fail "bestätigte Härtung wurde zurückgesetzt"; fi
ssh -o BatchMode=yes probe-server true || fail "Schlüssel-Login nach --confirm"
echo "ok: bestätigte Härtung bleibt"
sudo fail2ban-client status sshd >/dev/null || fail "fail2ban-Jail sshd fehlt"
echo "ok: fail2ban schützt sshd"

step "Rückgängig"
sudo bash "$src/server/ssh-haerten.sh" --undo
password_login || fail "--undo hat den alten Stand nicht wiederhergestellt"
echo "ok: --undo"

echo
echo "Alle Ende-zu-Ende-Prüfungen bestanden."
