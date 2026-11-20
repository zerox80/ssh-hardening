#!/usr/bin/env bash
# Prüft server/ssh-haerten.sh in einem Container ohne systemd (SSH_HARDENING_TEST=1):
# Konfiguration, Widersprüche aus anderen Dateien, Portwechsel, Bestätigen, Rückgängig, Abbrüche.
#   docker run --rm -v "$PWD:/src:ro" ubuntu:24.04 bash /src/tests/server-container.sh
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)"
script="$src/server/ssh-haerten.sh"
export SSH_HARDENING_TEST=1

# shellcheck disable=SC1091
. /etc/os-release
echo "################ $PRETTY_NAME"
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*)
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server sudo >/dev/null ;;
  *" fedora "*|*" rhel "*|*" centos "*)
    dnf install -y -q openssh-server sudo shadow-utils diffutils >/dev/null ;;
  *" suse "*|*" opensuse "*)
    zypper -q -n install openssh-server sudo shadow diffutils gawk >/dev/null ;;
  *) echo "Unbekannte Distribution: $ID"; exit 1 ;;
esac
mkdir -p /run/sshd
ssh-keygen -A >/dev/null
SSHD="$(command -v sshd || echo /usr/sbin/sshd)"

# Mehrfachwerte (z. B. Port) sortiert, damit die Reihenfolge in den Dateien keine Rolle spielt
eff() { "$SSHD" -T | awk -v k="$1" 'tolower($1) == k { $1 = ""; sub(/^ /, ""); print }' | sort -n | paste -sd' ' -; }
check() {
  local got; got="$(eff "$1")"
  if [[ "$got" != "$2" ]]; then echo "FEHLER: $1 = '$got', erwartet '$2'"; exit 1; fi
  echo "ok: $1 = $2"
}
fingerprint() { { cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true; } | md5sum; }
expect_fail() { # Beschreibung, Befehl…
  local what="$1"; shift
  local before; before="$(fingerprint)"
  if "$@" >/tmp/out 2>&1; then echo "FEHLER: '$what' hätte abbrechen müssen"; cat /tmp/out; exit 1; fi
  [[ "$(fingerprint)" == "$before" ]] || { echo "FEHLER: '$what' hat trotz Abbruch etwas geändert"; exit 1; }
  echo "ok: Abbruch ohne Änderung – $what"
}

# Benutzer: admin (sudo + Schlüssel), ohnesudo (nur Schlüssel), ohneschluessel (nur sudo)
ssh-keygen -q -t ed25519 -N "" -f /tmp/probe
for u in admin ohnesudo ohneschluessel; do useradd -m "$u"; done
# openSUSE erlaubt standardmäßig jedem sudo mit dem Root-Passwort ("ALL ALL=(ALL) ALL" + targetpw).
# Das zählt zu Recht als sudo-Recht; für den Test "ohne sudo" wird die Regel entfernt.
if [[ ! -f /etc/sudoers && -f /usr/etc/sudoers ]]; then cp /usr/etc/sudoers /etc/sudoers; fi
sed -i -E '/^[[:space:]]*ALL[[:space:]]+ALL[[:space:]]*=/d; /^[[:space:]]*Defaults[[:space:]]+targetpw/d' /etc/sudoers
mkdir -p /etc/sudoers.d
grep -Eq '^[@#]includedir /etc/sudoers.d' /etc/sudoers || echo '@includedir /etc/sudoers.d' >> /etc/sudoers
# admin über eine Gruppe wie bei sudo/wheel: sudo -l zeigt dann "(ALL : ALL) ALL"
groupadd -f admins
usermod -aG admins admin
printf '%%admins ALL=(ALL:ALL) ALL\nohneschluessel ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/probe
chmod 440 /etc/sudoers.d/probe
sudo -l -U admin | grep -q '(ALL : ALL) ALL' && echo "ok: Testfall sudo über Gruppe – (ALL : ALL)"
for u in admin ohnesudo; do
  install -d -m 700 -o "$u" -g "$(id -gn "$u")" "/home/$u/.ssh"
  install -m 644 -o "$u" -g "$(id -gn "$u")" /tmp/probe.pub "/home/$u/.ssh/authorized_keys"
done

# „Nicht frischer“ Server: Passwörter erlaubt, auch in einer Datei, die VOR unserer gelesen wird
mkdir -p /etc/ssh/sshd_config.d
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/00-alt.conf
printf 'PasswordAuthentication yes\nX11Forwarding yes\n' > /etc/ssh/sshd_config.d/50-cloud-init.conf
"$SSHD" -t

echo "---- Abbrüche"
expect_fail "unbekannter Benutzer" bash "$script" --user gibtsnicht
expect_fail "Benutzer ohne sudo" bash "$script" --user ohnesudo
expect_fail "Benutzer ohne Schlüssel" bash "$script" --user ohneschluessel
expect_fail "ungültiger Port" bash "$script" --user admin --port 99999

echo "---- Probelauf"
before="$(fingerprint)"
bash "$script" --user admin --dry-run >/dev/null
[[ "$(fingerprint)" == "$before" ]] || { echo "FEHLER: --dry-run hat etwas geändert"; exit 1; }
echo "ok: --dry-run ändert nichts"

echo "---- Härtung auf nicht frischem Server"
bash "$script" --user admin
check passwordauthentication no
check kbdinteractiveauthentication no
check permitrootlogin no
check pubkeyauthentication yes
check authenticationmethods publickey
check maxauthtries 3
check x11forwarding no
grep -q '^# ssh-hardening: PasswordAuthentication yes' /etc/ssh/sshd_config.d/00-alt.conf
echo "ok: Widerspruch in 00-alt.conf auskommentiert"
expect_fail "zweiter Lauf vor --confirm" bash "$script" --user admin
bash "$script" --confirm >/dev/null
echo "ok: --confirm"

echo "---- Wiederholung (idempotent)"
bash "$script" --user admin >/dev/null && bash "$script" --confirm >/dev/null
check passwordauthentication no
[[ "$(grep -c '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config 2>/dev/null || echo 1)" -le 1 ]] || { echo "FEHLER: Include doppelt"; exit 1; }
echo "ok: zweiter Lauf ohne Doppelungen"

echo "---- Portwechsel"
bash "$script" --user admin --port 2222 >/dev/null
check port "22 2222"
bash "$script" --confirm >/dev/null
check port "2222"

echo "---- Rückgängig"
bash "$script" --undo >/dev/null
check port "22"
bash "$script" --undo >/dev/null   # Stand vor dem zweiten Lauf
bash "$script" --undo >/dev/null   # Stand vor dem ersten Lauf
check passwordauthentication yes
check x11forwarding yes
echo "ok: --undo stellt den ursprünglichen Stand wieder her"

if [[ -f /etc/ssh/sshd_config ]]; then
  echo "---- Konfiguration ohne Include-Zeile"
  sed -i '/^Include \/etc\/ssh\/sshd_config.d\/\*\.conf/d' /etc/ssh/sshd_config
  bash "$script" --user admin >/dev/null && bash "$script" --confirm >/dev/null
  head -n 1 /etc/ssh/sshd_config | grep -q '^Include /etc/ssh/sshd_config.d/\*\.conf' || { echo "FEHLER: Include fehlt"; exit 1; }
  check passwordauthentication no
  bash "$script" --undo >/dev/null
fi

echo "---- Zwei-Faktor bleibt erhalten"
printf 'AuthenticationMethods publickey,keyboard-interactive\nKbdInteractiveAuthentication yes\n' > /etc/ssh/sshd_config.d/00-mfa.conf
bash "$script" --user admin >/dev/null && bash "$script" --confirm >/dev/null
check authenticationmethods "publickey,keyboard-interactive"
check kbdinteractiveauthentication yes
check passwordauthentication no
bash "$script" --undo >/dev/null
rm -f /etc/ssh/sshd_config.d/00-mfa.conf

if command -v script >/dev/null; then
  echo "---- Fragerunde (simuliertes Terminal)"
  # Antworten: Benutzer, Port (Vorschlag), Firewall aus lassen, nicht streng, fail2ban ja, Abbruch
  before="$(fingerprint)"
  printf 'admin\n\nn\nn\nj\nn\n' | script -qec "bash $script" /dev/null > /tmp/fragen 2>&1 || true
  tr -d '\r' </tmp/fragen | grep -q "Abgebrochen – nichts geändert" || { cat /tmp/fragen; echo "FEHLER: kein Abbruch"; exit 1; }
  [[ "$(fingerprint)" == "$before" ]] || { echo "FEHLER: Abbruch hat etwas geändert"; exit 1; }
  echo "ok: Fragen beantwortet, bei 'nein' nichts geändert"
  # Dieselben Antworten, diesmal bestätigen
  printf 'admin\n\nn\nn\nj\nj\n' | script -qec "bash $script" /dev/null > /tmp/fragen 2>&1 || true
  check passwordauthentication no
  bash "$script" --confirm >/dev/null
  echo "ok: mit 'ja' ausgeführt"
  bash "$script" --undo >/dev/null
fi

echo "---- Streng"
bash "$script" --user admin --strict >/dev/null && bash "$script" --confirm >/dev/null
check allowusers admin
check allowtcpforwarding no
"$SSHD" -t
echo "################ alle Prüfungen bestanden: $PRETTY_NAME"
