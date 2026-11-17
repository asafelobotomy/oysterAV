#!/usr/bin/env bash
# CI entry point for uq-shield-live.sh, in an archlinux container given one vkms card (like uQ's
# scripts/smoke-in-container.sh, which this follows). /src is this checkout, /src/uq-src is uQ.
set -eu
card=${SMOKE_CARD:?}
pacman -Syu --noconfirm --needed rust dbus hyprland quickshell qt6-declarative jq ttf-dejavu grim seatd socat gcc pkgconf wayland libxkbcommon libnotify dbus kirigami qqc2-desktop-style >/dev/null
id tester >/dev/null 2>&1 || useradd -m -u "${SMOKE_UID:-1000}" tester
chmod 666 "$card"
# The widget directory is under /usr/share: the unprivileged shell only reads it.
install -d -m 755 /usr/share/uq/shell/widgets/oysterav-bar
SEATD_VTBOUND=0 seatd -u tester -l error &
rc=0
su tester -c "set -e; cd /src/uq-src; cargo build --locked -p uqctl"
# A fake oyst-cli answers with a warning; then the rest runs as tester.
printf '#!/bin/sh\ncat <<JSON\n{"schema":1,"state":"warning","reasons":["ufw is installed but turned off","virus signatures are 70 hours old"],"scanning":false,"last_scan_at":null,"last_scan_age_hours":null,"open_findings":0,"signature_age_hours":70,"signatures_stale":true,"quarantine_count":0,"checks":[{"id":"firewall","state":"warning","detail":"ufw is installed but turned off"}]}\nJSON\n' >/usr/bin/oyst-cli
chmod +x /usr/bin/oyst-cli
su tester -c "set -e; cd /src
    export XDG_RUNTIME_DIR=\$(mktemp -d) LIBSEAT_BACKEND=seatd UQ_ROOT=/src/uq-src UQCTL=/src/uq-src/target/debug/uqctl UQ_CAPTURE_DIR=/src/captures SHIELD_CLICK='${SHIELD_CLICK:-}'
    timeout 300 scripts/uq-shield-live.sh" || rc=$?
exit "$rc"
