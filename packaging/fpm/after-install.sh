#!/bin/sh
# postinst / after-install for oysterAV native packages
set -e
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload polkit 2>/dev/null || true
fi
exit 0
