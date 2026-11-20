#!/usr/bin/env bash
# =====================================================================
# Richtet den SSH-Zugang von diesem Linux- oder macOS-Rechner (z. B. Fedora) zu einem Linux-Server ein.
# Gegenstück zu ssh-zugang-einrichten.ps1 für Windows.  https://github.com/zerox80/ssh-hardening
#
#   1. Nutzt einen vorhandenen SSH-Schlüssel oder erzeugt einen neuen (ed25519).
#   2. Trägt den öffentlichen Schlüssel auf dem Server ein – nur wenn nötig, dafür EINMAL das Passwort.
#   3. Prüft, ob die Anmeldung jetzt ohne Passwort klappt.
#   4. Legt in ~/.ssh/config Kurznamen an: danach genügt "ssh <hostname>".
#   5. Auf Wunsch: privaten Schlüssel für Bitwarden in die Zwischenablage, danach geleert.
#
# Aufruf:
#   bash ssh-zugang-einrichten.sh -s 192.0.2.10 -u admin [-p 22] [-a kurzname] [-k id_ed25519] [-b|-B] [-n]
#     -b  Schlüssel ohne Rückfrage für Bitwarden in die Zwischenablage   -B  nicht nach Bitwarden fragen
#     -n  ~/.ssh/config nicht anfassen
# =====================================================================
# Befehle für den Server werden absichtlich lokal zusammengesetzt und dort ausgeführt.
# shellcheck disable=SC2029
set -euo pipefail

server=""
user_name=""
port=22
aliases=()
key_name="id_ed25519"
bitwarden="ask"
no_config=0

usage() {
  echo "Aufruf: $0 -s <server> -u <benutzer> [-p <port>] [-a <kurzname>]... [-k <schlüsselname>] [-b|-B] [-n]" >&2
  exit 2
}

while getopts "s:u:p:a:k:bBnh" opt; do
  case "$opt" in
    s) server="$OPTARG" ;;
    u) user_name="$OPTARG" ;;
    p) port="$OPTARG" ;;
    a) aliases+=("$OPTARG") ;;
    k) key_name="$OPTARG" ;;
    b) bitwarden="yes" ;;
    B) bitwarden="no" ;;
    n) no_config=1 ;;
    *) usage ;;
  esac
done
[[ -n "$server" && -n "$user_name" ]] || usage
[[ "$port" =~ ^[0-9]+$ ]] || usage

step() { printf '\n\033[36m==> %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31mABBRUCH: %s\033[0m\n' "$1" >&2; exit 1; }
interactive() { [[ -t 0 && -t 1 ]]; }

# ---------------------------------------------------------------- OpenSSH vorhanden?
step "OpenSSH-Client prüfen"
for tool in ssh ssh-keygen; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool fehlt. Fedora: sudo dnf install -y openssh-clients · Debian/Ubuntu: sudo apt install -y openssh-client"
done
echo "ok"

ssh_dir="$HOME/.ssh"
key="$ssh_dir/$key_name"
mkdir -p "$ssh_dir"
chmod 700 "$ssh_dir"
target="$user_name@$server"
# -F none: ~/.ssh/config nicht mitlesen – sonst probiert ssh zusätzlich dort hinterlegte Schlüssel
# und meldet fälschlich "schon eingetragen", obwohl dieser Schlüssel fehlt.
base=(-F none -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
key_opts=(-i "$key" -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no)
# Wird absichtlich erst auf dem Server ausgeführt (SC2029 betrifft das hier nicht).
probe='echo schluessel-ok; hostname -s 2>/dev/null || uname -n'

# ---------------------------------------------------------------- 1. Schlüssel
step "Schlüssel $key"
if [[ -f "$key" ]]; then
  echo "vorhanden – wird verwendet"
  # ssh verweigert private Schlüssel, die andere lesen dürfen ("UNPROTECTED PRIVATE KEY FILE").
  chmod 600 "$key"
  [[ -f "$key.pub" ]] || ssh-keygen -y -f "$key" > "$key.pub" || fail "Öffentlicher Schlüssel fehlt und ließ sich nicht erzeugen."
else
  [[ -f "$key.pub" ]] && fail "$key.pub ist da, der private Schlüssel $key fehlt. Datei umbenennen oder -k anders wählen."
  echo "Neuer Schlüssel. Eine Passphrase ist empfohlen (schützt den Schlüssel, falls jemand an den Rechner kommt)."
  echo "Ohne Passphrase: zweimal Enter drücken."
  ssh-keygen -t ed25519 -a 64 -f "$key" -C "$(id -un)@${HOSTNAME%%.*}"
  [[ -f "$key.pub" ]] || fail "Schlüssel konnte nicht erzeugt werden."
fi
ssh-keygen -lf "$key.pub"

# ---------------------------------------------------------------- 2. Schon eingerichtet?
step "Verbindung zu $target prüfen"
set +e
first=$(ssh "${base[@]}" "${key_opts[@]}" -o BatchMode=yes "$target" "$probe" 2>&1)
first_code=$?
set -e
if grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED" <<<"$first"; then
  if [[ "$port" == 22 ]]; then known="$server"; else known="[$server]:$port"; fi
  fail "Der Server meldet einen anderen Schlüssel als beim letzten Mal (z. B. neu installiert). Ist das erklärbar: ssh-keygen -R '$known' ausführen und neu starten. Ist es NICHT erklärbar: nicht verbinden und die IT fragen."
fi
if grep -Eq "Could not resolve|Connection refused|timed out|No route to host" <<<"$first"; then
  fail "Server nicht erreichbar: $(tr '\n' ' ' <<<"$first")– Adresse, Port $port und Firewall prüfen."
fi

if (( first_code == 0 )) && grep -qx "schluessel-ok" <<<"$first"; then
  printf '\033[32mDer Schlüssel ist auf dem Server schon eingetragen – kein Passwort nötig.\033[0m\n'
  out="$first"
else
  # ------------------------------------------------------------ 3. Auf den Server kopieren
  step "Öffentlichen Schlüssel auf $target eintragen"
  echo "Jetzt das PASSWORT des Server-Benutzers eingeben (nur dieses eine Mal):"
  remote='umask 077; mkdir -p ~/.ssh; tr -d '"'"'\r'"'"' > ~/.ssh/.ssh-hardening-neu; touch ~/.ssh/authorized_keys; '
  remote+='grep -qxFf ~/.ssh/.ssh-hardening-neu ~/.ssh/authorized_keys || cat ~/.ssh/.ssh-hardening-neu >> ~/.ssh/authorized_keys; '
  remote+='rm -f ~/.ssh/.ssh-hardening-neu; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; '
  remote+='command -v restorecon >/dev/null 2>&1 && restorecon -R ~/.ssh; echo eingetragen'
  ssh "${base[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password \
    "$target" "$remote" < "$key.pub" \
    || fail "Eintragen fehlgeschlagen. Häufige Gründe: falsches Passwort oder Benutzer; der Server erlaubt keine Passwörter mehr (dann den Schlüssel über einen bestehenden Zugang oder die Konsole eintragen)."

  # ------------------------------------------------------------ 4. Testen
  step "Anmeldung ohne Passwort testen"
  out=$(ssh "${base[@]}" "${key_opts[@]}" "$target" "$probe") \
    || fail "Anmeldung mit Schlüssel klappt noch nicht. Auf dem Server KEINE Härtung ausführen, sonst sperrst du dich aus."
  grep -qx "schluessel-ok" <<<"$out" || fail "Anmeldung mit Schlüssel klappt noch nicht. Auf dem Server KEINE Härtung ausführen."
fi
printf '\033[32mAnmeldung mit Schlüssel klappt.\033[0m\n'
remote_host=$(grep -E '^[A-Za-z0-9._-]+$' <<<"$out" | grep -vx "schluessel-ok" | tail -n 1 || true)

# ---------------------------------------------------------------- 5. Kurznamen in ~/.ssh/config
names=()
for n in "${aliases[@]+"${aliases[@]}"}" "$remote_host" "$server"; do
  [[ -n "$n" && "$n" =~ ^[A-Za-z0-9._-]+$ ]] || continue
  [[ " ${names[*]-} " == *" $n "* ]] || names+=("$n")
done
if (( ! no_config )); then
  config="$ssh_dir/config"
  step "Kurznamen in $config: ${names[*]}"
  touch "$config"
  chmod 600 "$config"
  free=()
  for n in "${names[@]}"; do
    pattern=$(printf '%s' "$n" | sed 's/[.]/\\./g')
    if grep -Eqi "^[[:space:]]*Host[[:space:]]+(.*[[:space:]])?${pattern}([[:space:]]|$)" "$config"; then
      echo "Schon vorhanden und nicht verändert: $n"
    else
      free+=("$n")
    fi
  done
  if (( ${#free[@]} )); then
    {
      echo ""
      echo "Host ${free[*]}"
      echo "    HostName $server"
      echo "    User $user_name"
      echo "    Port $port"
      echo "    IdentityFile $key"
      echo "    IdentitiesOnly yes"
      echo "    ServerAliveInterval 60"
    } >> "$config"
    echo "angelegt: ${free[*]}"
  fi
  ssh -G "${names[0]}" >/dev/null || fail "ssh kann $config nicht lesen – Inhalt der Datei prüfen."
fi

# ---------------------------------------------------------------- 6. Bitwarden (optional)
copy_secret() {
  if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wl-copy >/dev/null; then
    if wl-copy --help 2>&1 | grep -q -- '--sensitive'; then wl-copy --sensitive < "$1"; else wl-copy < "$1"; fi
    echo "wl-copy"
  elif [[ -n "${DISPLAY:-}" ]] && command -v xclip >/dev/null; then xclip -selection clipboard < "$1"; echo xclip
  elif [[ -n "${DISPLAY:-}" ]] && command -v xsel >/dev/null; then xsel --clipboard --input < "$1"; echo xsel
  elif command -v pbcopy >/dev/null; then pbcopy < "$1"; echo pbcopy
  else echo none; fi
}
clear_secret() {
  case "$1" in
    wl-copy) wl-copy --clear ;;
    xclip) printf '' | xclip -selection clipboard ;;
    xsel) xsel --clipboard --clear ;;
    pbcopy) printf '' | pbcopy ;;
  esac
}
want_bw=0
if [[ "$bitwarden" == yes ]]; then
  want_bw=1
elif [[ "$bitwarden" == ask ]] && interactive; then
  echo ""
  read -r -p "Privaten Schlüssel für Bitwarden in die Zwischenablage legen? (j/N) " answer
  # tr statt ${answer,,}: macOS liefert noch Bash 3.2 mit
  answer=$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')
  [[ "$answer" =~ ^(j|ja|y|yes)$ ]] && want_bw=1
fi
if (( want_bw )); then
  step "Schlüssel für Bitwarden"
  tool=$(copy_secret "$key")
  if [[ "$tool" == none ]]; then
    echo "Kein Programm für die Zwischenablage gefunden (Fedora: sudo dnf install -y wl-clipboard)."
    echo "Den privaten Schlüssel anzeigen birgt Risiken (Verlauf, Bildschirmfreigabe)."
    if interactive; then
      read -r -p "Trotzdem hier anzeigen? Dann 'ANZEIGEN' eingeben: " answer
      if [[ "$answer" == ANZEIGEN ]]; then cat "$key"; read -r -p "Enter drücken und danach den Bildschirm leeren (clear)." _; clear; fi
    fi
  else
    echo "Der private Schlüssel liegt in der Zwischenablage ($tool)."
    echo "In Bitwarden: Neues Element -> SSH-Schlüssel -> 'Schlüssel aus Zwischenablage importieren' -> Speichern."
    echo "Mit Passphrase fragt Bitwarden beim Import danach."
    if interactive; then read -r -p "Enter drücken, wenn gespeichert – danach wird die Zwischenablage geleert. " _; else sleep 60; fi
    clear_secret "$tool"
    echo "Zwischenablage geleert."
  fi
fi

# ---------------------------------------------------------------- Fertig
echo ""
if (( no_config )); then
  printf '\033[32mFertig. Verbinden mit:  ssh -i %s -p %s %s\033[0m\n' "$key" "$port" "$target"
else
  for n in "${names[@]}"; do printf '\033[32mFertig. Ab jetzt:  ssh %s\033[0m\n' "$n"; done
fi
echo ""
echo "Fingerabdruck des Servers vergleichen (optional): auf dem Server  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
echo "und hier  ssh-keygen -lF $server"
echo "Server absichern: server/ssh-haerten.sh (https://github.com/zerox80/ssh-hardening)"
