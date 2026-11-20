#!/usr/bin/env bash
# Prüft den Import des privaten Schlüssels aus der Zwischenablage im Linux/macOS-Client.
# Die Zwischenablage ist eine Attrappe (wl-paste/wl-copy im PATH), der Server absichtlich nicht
# erreichbar: geprüft wird alles bis zur Verbindung. Läuft mit Bash 3.2 (macOS) und neuer.
set -euo pipefail
cd "$(dirname "$0")/.."
client="$PWD/client/ssh-zugang-einrichten.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Attrappe der Zwischenablage: Inhalt aus $work/clip, Leeren wird protokolliert
mkdir -p "$work/bin"
cat >"$work/bin/wl-paste" <<'EOF'
#!/bin/sh
cat "$CLIP_FILE"
EOF
cat >"$work/bin/wl-copy" <<'EOF'
#!/bin/sh
case "$1" in --clear) : >"$CLIP_FILE"; echo geleert >>"$CLIP_LOG" ;; --help) echo "--sensitive" ;; *) cat >"$CLIP_FILE" ;; esac
EOF
chmod +x "$work/bin/wl-paste" "$work/bin/wl-copy"
export PATH="$work/bin:$PATH" WAYLAND_DISPLAY=test CLIP_FILE="$work/clip" CLIP_LOG="$work/clip.log"

ssh-keygen -q -t ed25519 -N "" -C test -f "$work/quelle"
expected_pub=$(cut -d' ' -f1,2 "$work/quelle.pub")

# "$BASH": dieselbe Bash wie der Test – auf macOS mit /bin/bash also Bash 3.2
run() { # neues HOME, Client gegen einen nicht erreichbaren Server
  HOME="$1" "$BASH" "$client" -s 127.0.0.1 -p 1 -u test -B "${@:2}" </dev/null >"$work/out" 2>&1 || true
}
check_key() { # Schlüsseldatei vorhanden, Rechte 600, öffentlicher Teil passt
  local file="$1" mode
  [[ -f "$file" ]] || { cat "$work/out"; echo "FEHLER: $file fehlt"; exit 1; }
  mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
  [[ "$mode" == 600 ]] || { echo "FEHLER: Rechte $mode statt 600"; exit 1; }
  [[ "$(cut -d' ' -f1,2 "$file.pub")" == "$expected_pub" ]] || { echo "FEHLER: öffentlicher Teil passt nicht"; exit 1; }
  ssh-keygen -y -f "$file" >/dev/null || { echo "FEHLER: ssh liest den Schlüssel nicht"; exit 1; }
}

echo "---- Mehrzeilig mit CRLF"
h="$work/h1"; mkdir -p "$h"
awk '{ printf "%s\r\n", $0 }' "$work/quelle" >"$CLIP_FILE"; : >"$CLIP_LOG"   # macOS-sed kennt kein \r
run "$h" -i
check_key "$h/.ssh/id_ed25519"
grep -q geleert "$CLIP_LOG" || { echo "FEHLER: Zwischenablage nicht geleert"; exit 1; }
grep -q "nicht erreichbar" "$work/out" || { cat "$work/out"; echo "FEHLER: Lauf ging nicht bis zur Verbindung"; exit 1; }
echo "ok: übernommen, Rechte 600, Zwischenablage geleert"

echo "---- In einer Zeile (wie aus manchen Passwortmanagern)"
h="$work/h2"; mkdir -p "$h"
tr '\n' ' ' <"$work/quelle" >"$CLIP_FILE"
run "$h" -i
check_key "$h/.ssh/id_ed25519"
echo "ok: neu umbrochen und gültig"

echo "---- Kein Schlüssel in der Zwischenablage"
h="$work/h3"; mkdir -p "$h"
echo "irgendein Text" >"$CLIP_FILE"
run "$h" -i
grep -q "kein privater SSH-Schlüssel" "$work/out" || { cat "$work/out"; echo "FEHLER: keine Meldung"; exit 1; }
[[ ! -e "$h/.ssh/id_ed25519" ]] || { echo "FEHLER: Datei trotzdem angelegt"; exit 1; }
echo "ok: abgelehnt, nichts gespeichert"

echo "---- Anderer Schlüssel unter dem Standardnamen bleibt unangetastet"
h="$work/h4"; mkdir -p "$h/.ssh"
ssh-keygen -q -t ed25519 -N "" -f "$h/.ssh/id_ed25519"
before=$(cat "$h/.ssh/id_ed25519")
cp "$work/quelle" "$CLIP_FILE"
run "$h" -i
[[ "$(cat "$h/.ssh/id_ed25519")" == "$before" ]] || { echo "FEHLER: vorhandener Schlüssel überschrieben"; exit 1; }
check_key "$h/.ssh/id_ed25519_127_0_0_1"
echo "ok: eigener Name id_ed25519_127_0_0_1"

echo "---- Kaputter Schlüssel wird nicht gespeichert"
h="$work/h5"; mkdir -p "$h"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAkaputt\n-----END OPENSSH PRIVATE KEY-----\n' >"$CLIP_FILE"
run "$h" -i
grep -q "kein gültiger privater Schlüssel" "$work/out" || { cat "$work/out"; echo "FEHLER: keine Meldung"; exit 1; }
[[ ! -e "$h/.ssh/id_ed25519" ]] || { echo "FEHLER: kaputte Datei bleibt liegen"; exit 1; }
echo "ok: abgelehnt, nichts liegen geblieben"

if command -v script >/dev/null && script --version 2>/dev/null | grep -q util-linux; then
  echo "---- Ohne -i: im Terminal nachfragen, wenn noch kein Schlüssel da ist"
  h="$work/h6"; mkdir -p "$h"
  cp "$work/quelle" "$CLIP_FILE"
  { sleep 2; printf 'j\n'; sleep 2; } | HOME="$h" script -qec "$BASH $client -s 127.0.0.1 -p 1 -u test -B" /dev/null >"$work/out" 2>&1 || true
  tr -d '\r' <"$work/out" | grep -q "liegt ein privater SSH-Schlüssel" || { cat "$work/out"; echo "FEHLER: keine Rückfrage"; exit 1; }
  check_key "$h/.ssh/id_ed25519"
  echo "ok: Rückfrage und Übernahme"
fi

echo ""
echo "==== Import aus der Zwischenablage: alle Prüfungen bestanden"
