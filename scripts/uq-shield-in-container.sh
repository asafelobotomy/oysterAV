#!/usr/bin/env bash
# CI entry point for uq-shield-live.sh, in an archlinux container given one vkms card (like uQ's
# scripts/smoke-in-container.sh, which this follows). /src is this checkout, /src/uq-src is uQ.
set -eu
card=${SMOKE_CARD:?}
pacman -Syu --noconfirm --needed rust dbus hyprland quickshell qt6-declarative jq ttf-dejavu grim seatd socat gcc pkgconf wayland libxkbcommon libnotify dbus kirigami qqc2-desktop-style >/dev/null
id tester >/dev/null 2>&1 || useradd -m -u "${SMOKE_UID:-1000}" tester
chmod 666 "$card"
SEATD_VTBOUND=0 seatd -u tester -l error &
rc=0
su tester -c "set -e; cd /src/uq-src; cargo build --locked -p uqctl"
# A fake oyst-cli answers with SHIELD_STATE (ok, warning or threat; default warning), and
# oysterAV's icon is installed so the island can show it.
state=${SHIELD_STATE:-warning}
case "$state" in
ok) body='"state":"ok","reasons":[],"scanning":false,"last_scan_at":"2026-11-17T06:00:00","last_scan_age_hours":3,"last_scan_profile":"quick","last_scan_state":"done","open_findings":0,"signature_age_hours":2,"signatures_stale":false,"quarantine_count":0,"checks":[{"id":"firewall","state":"ok","detail":"ufw is on"},{"id":"boot_guard","state":"ok","detail":"boot images match the installed kernels"}]' ;;
threat) body='"state":"threat","reasons":["the last scan found 2 threats"],"scanning":false,"last_scan_at":"2026-11-17T06:00:00","last_scan_age_hours":3,"last_scan_profile":"quick","last_scan_state":"done","open_findings":2,"signature_age_hours":2,"signatures_stale":false,"quarantine_count":1,"checks":[{"id":"firewall","state":"ok","detail":"ufw is on"}]' ;;
*) body='"state":"warning","reasons":["ufw is installed but turned off","virus signatures are 70 hours old"],"scanning":false,"last_scan_at":null,"last_scan_age_hours":null,"open_findings":0,"signature_age_hours":70,"signatures_stale":true,"quarantine_count":0,"checks":[{"id":"firewall","state":"warning","detail":"ufw is installed but turned off"}]' ;;
esac
printf '#!/bin/sh\ncat <<JSON\n{"schema":1,%s}\nJSON\n' "$body" >/usr/bin/oyst-cli
install -Dm644 /src/branding/hicolor/48x48/apps/oysterav.png /usr/share/icons/hicolor/48x48/apps/oysterav.png
chmod +x /usr/bin/oyst-cli
su tester -c "set -e; cd /src
    export XDG_RUNTIME_DIR=\$(mktemp -d) LIBSEAT_BACKEND=seatd UQ_ROOT=/src/uq-src UQCTL=/src/uq-src/target/debug/uqctl UQ_CAPTURE_DIR=/src/captures SHIELD_CLICK='${SHIELD_CLICK:-}'
    timeout 300 scripts/uq-shield-live.sh" || rc=$?
exit "$rc"
