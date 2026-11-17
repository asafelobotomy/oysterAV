#!/usr/bin/env bash
# The oysterAV bar shield in the real uQ shell on a headless Hyprland (CI: .github/workflows/uq-shield-live.yml).
# Installs uq/widgets/oysterav-bar under /usr/share/uq/shell/widgets/, with a fake `oyst-cli` that
# reports a warning, then captures the bar, the notification uQ shows, and (when SHIELD_CLICK="X Y"
# is set) the popup after a click. Needs UQ_ROOT (a uQ checkout with a built uqctl) and UQCTL.
# Exit 77 when this environment can't run it.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
root=${UQ_ROOT:?UQ_ROOT must name a uQ checkout}
skip() { echo "SKIP: $*"; exit 77; }
for bin in Hyprland hyprctl qs dbus-daemon jq grim socat gcc wayland-scanner notify-send; do
    command -v "$bin" >/dev/null 2>&1 || skip "$bin is not installed"
done
uqctl=${UQCTL:-$root/target/debug/uqctl}
[ -x "$uqctl" ] || skip "no uqctl binary"
cap=${UQ_CAPTURE_DIR:-/tmp/shield-captures}; mkdir -p "$cap"

tmp=$(mktemp -d /tmp/uqsh.XXXXXX); rt="$tmp/rt"; mkdir -m 700 "$rt"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in hypr qs; do [ -f "$tmp/$f.log" ] && { echo "--- $f.log"; tail -n 40 "$tmp/$f.log"; }; done; exit 1; }

# The widget is installed under /usr/share/uq/shell/widgets/ and a fake oyst-cli answers with a warning
# (uq-shield-in-container.sh does both as root).
[ -f /usr/share/uq/shell/widgets/oysterav-bar/widget.toml ] || skip "the widget isn't installed under /usr/share"
[ -x /usr/bin/oyst-cli ] || skip "no (fake) /usr/bin/oyst-cli"

"$root/tests/live/tools/build-uqinput.sh" "$tmp/uqinput" || skip "uqinput didn't build"
dbus-daemon --session --address="unix:path=$tmp/bus" --nofork --nopidfile >"$tmp/dbus.log" 2>&1 &
pids+=($!)
mkdir -p "$tmp/state"
cat >"$tmp/hypr.lua" <<LUA
require([[$root/config/hypr/base.lua]])
hl.monitor({ output = "", mode = "1280x720", position = "auto", scale = 1 })
hl.config({ misc = { disable_hyprland_logo = true, disable_splash_rendering = true } })
LUA
env XDG_RUNTIME_DIR="$rt" LIBGL_ALWAYS_SOFTWARE=1 UQ_DEV_SESSION=1 Hyprland -c "$tmp/hypr.lua" >"$tmp/hypr.log" 2>&1 &
pids+=($!)
sig=""
for _ in $(seq 1 50); do
    sig=$(find "$rt/hypr" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | head -n1)
    [ -n "$sig" ] && [ -S "$rt/hypr/$sig/.socket.sock" ] && break
    sleep 0.2
done
[ -n "$sig" ] || skip "Hyprland never opened its socket"
hc() { env XDG_RUNTIME_DIR="$rt" HYPRLAND_INSTANCE_SIGNATURE="$sig" hyprctl "$@"; }
wl=""
for _ in $(seq 1 25); do
    wl=$(find "$rt" -maxdepth 1 -name 'wayland-*' ! -name '*.lock' -printf '%f\n' | head -n1)
    [ -n "$wl" ] && break; sleep 0.2
done
[ -n "$wl" ] || skip "no Wayland socket"
[ -n "$(hc monitors -j | jq -r '.[0].name // empty')" ] || hc output create headless >/dev/null 2>&1
sleep 0.5

shell_env=(env XDG_RUNTIME_DIR="$rt" WAYLAND_DISPLAY="$wl" HYPRLAND_INSTANCE_SIGNATURE="$sig"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$tmp/bus" PATH="$(dirname "$uqctl"):$PATH"
    XDG_STATE_HOME="$tmp/state" QT_QPA_PLATFORM=wayland LC_ALL=C.UTF-8)
"${shell_env[@]}" qs -p "$root/shell" --no-duplicate >"$tmp/qs.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do hc layers -j | grep -q uq-bar && break; sleep 0.2; done
hc layers -j | grep -q uq-bar || fail "the bar never appeared"
dbus-monitor --address "unix:path=$tmp/bus" "interface='org.freedesktop.Notifications'" >"$tmp/notify.log" 2>&1 &
pids+=($!)
shot() { env XDG_RUNTIME_DIR="$rt" WAYLAND_DISPLAY="$wl" grim "$@" 2>/dev/null; }
hc layers -j | jq -c '.. | objects | select(.namespace? == "uq-bar") | {x,y,w,h}' | head -3 | sed 's/^/bar layer: /'

# The widget loads and runs its summary; the notification should appear within a few seconds.
# One frame every 1.5 s for 15 s: the widget's own notification shows for a few seconds somewhere
# in there (it waits for uQ's notification server to take its name).
for i in $(seq 0 9); do shot "$cap/shield-1-t$(printf %02d $i).png"; sleep 1.5; done
hc dismissnotify >/dev/null 2>&1   # Hyprland's own "started without start-hyprland" banner
grep -iE "notif" "$tmp/qs.log" | head -5
echo "--- notification bus traffic"; grep -E "member=Notify" -A3 "$tmp/notify.log" | grep -E "member=Notify|string \"(Security|ufw)" | head -6; echo "---"
grep -qiE "TypeError|ReferenceError" "$tmp/qs.log" && fail "the widget logged errors"
sleep 8   # let the notification card go before the popup opens under it

if [ -n "${SHIELD_CLICK:-}" ]; then
    mkfifo "$tmp/in"
    env XDG_RUNTIME_DIR="$rt" WAYLAND_DISPLAY="$wl" "$tmp/uqinput" 1280 720 <"$tmp/in" >"$tmp/uqinput.out" 2>&1 &
    pids+=($!); exec 7>"$tmp/in"
    for _ in $(seq 1 50); do grep -q ready "$tmp/uqinput.out" && break; sleep 0.1; done
    read -r cx cy <<<"$SHIELD_CLICK"
    printf '%s\n' "move $cx $cy" "sleep 300" "button 272 down" "sleep 60" "button 272 up" >&7
    sleep 2
    shot "$cap/shield-2-popup.png"
fi
grep -iE "oysterav" "$tmp/qs.log" | head -10
echo "ok: captures in $cap"
